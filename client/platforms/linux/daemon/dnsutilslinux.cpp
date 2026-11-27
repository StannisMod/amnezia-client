/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "dnsutilslinux.h"
#include "linuxdnsrecovery.h"

#include <cerrno>
#include <cstring>
#include <net/if.h>

#include <QDBusVariant>
#include <QtDBus/QtDBus>

#include "leakdetector.h"
#include "logger.h"

constexpr const char* DBUS_RESOLVE_SERVICE = "org.freedesktop.resolve1";
constexpr const char* DBUS_RESOLVE_PATH = "/org/freedesktop/resolve1";
constexpr const char* DBUS_RESOLVE_MANAGER = "org.freedesktop.resolve1.Manager";
constexpr const char* DBUS_PROPERTY_INTERFACE =
    "org.freedesktop.DBus.Properties";

namespace {
Logger logger("DnsUtilsLinux");
}

DnsUtilsLinux::DnsUtilsLinux(QObject* parent) : DnsUtils(parent) {
  MZ_COUNT_CTOR(DnsUtilsLinux);
  logger.debug() << "DnsUtilsLinux created.";

  QDBusConnection conn = QDBusConnection::systemBus();
  m_resolver = new QDBusInterface(DBUS_RESOLVE_SERVICE, DBUS_RESOLVE_PATH,
                                  DBUS_RESOLVE_MANAGER, conn, this);
  if (!m_resolver->isValid()) {
    logger.error() << "Unable to initialize systemd-resolved D-Bus interface:"
                   << m_resolver->lastError().name()
                   << m_resolver->lastError().message();
  }
}

DnsUtilsLinux::~DnsUtilsLinux() {
  MZ_COUNT_DTOR(DnsUtilsLinux);

  restoreResolversForCurrentOwner();

  logger.debug() << "DnsUtilsLinux destroyed.";
}

bool DnsUtilsLinux::updateResolversNative(const QString& ifname,
                                    const QList<QHostAddress>& resolvers, bool strict) {
  ++m_domainGeneration;
  const int index = if_nametoindex(qPrintable(ifname));
  if (strict && m_ifindex > 0 && m_ifindex != index) return false;
  m_ifindex = index;
  if (m_ifindex <= 0) {
    logger.error() << "Unable to resolve ifindex for" << ifname
                   << QString::fromLocal8Bit(std::strerror(errno));
    return false;
  }

  if (strict) return updateResolversChecked(resolvers);
  setLinkDNS(m_ifindex, resolvers);
  setLinkDefaultRoute(m_ifindex, true);
  updateLinkDomains();
  return true;
}

bool DnsUtilsLinux::restoreResolversNative(bool strict) {
  ++m_domainGeneration;
  if (strict && !m_dnsRecovery.isEmpty()) {
    if (!LinuxDnsRecovery::restore(m_dnsRecovery, LinuxDnsRecovery::systemBackend())) return false;
    m_dnsRecovery = {};
    m_ifindex = 0;
    m_linkDomains.clear();
    m_strictDomainsSaved = false;
    return true;
  }
  if (strict || m_strictDomainsSaved) return restoreResolversChecked();
  for (auto iterator = m_linkDomains.constBegin();
       iterator != m_linkDomains.constEnd(); ++iterator) {
    setLinkDomains(iterator.key(), iterator.value());
  }
  m_linkDomains.clear();

  /* Revert the VPN interface's DNS configuration */
  if (m_ifindex > 0) {
    QList<QVariant> argumentList = {QVariant::fromValue(m_ifindex)};
    QDBusPendingReply<> reply = m_resolver->asyncCallWithArgumentList(
        QStringLiteral("RevertLink"), argumentList);

    QDBusPendingCallWatcher* watcher = new QDBusPendingCallWatcher(reply, this);
    watcher->setProperty("dnsMethod", QStringLiteral("RevertLink"));
    watcher->setProperty("dnsIfindex", m_ifindex);
    QObject::connect(watcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this,
                     SLOT(dnsCallCompleted(QDBusPendingCallWatcher*)));

    m_ifindex = 0;
  }

  return true;
}

bool DnsUtilsLinux::prepareDnsRecovery(NativeDnsGuard &guard, const QString &ifname,
                                     const QList<QHostAddress> &endpoints) {
  const auto snapshot = LinuxDnsRecovery::capture(ifname, endpoints, m_dnsRecovery, m_linkPolicy);
  if (snapshot.isEmpty() || !guard.storeDnsRecovery(snapshot)) return false;
  m_dnsRecovery = snapshot;
  return true;
}

bool DnsUtilsLinux::setLinkPolicy(const QJsonObject &policy) {
  // Validation is also performed by capture before any OS mutation. Do not
  // accept security or per-server fields that resolved's link API cannot express.
  if (!policy.isEmpty()) {
    if (policy.size() != 2 || !policy["domains"].isArray()
        || !policy["default_route"].isBool()) return false;
    for (const auto &value : policy["domains"].toArray()) {
      if (!value.isObject()) return false;
      const auto domain = value.toObject();
      if (domain.size() != 2 || !domain["name"].isString()
          || domain["name"].toString().isEmpty()
          || domain["name"].toString().contains(QChar(0))
          || !domain["routing_only"].isBool()) return false;
    }
  }
  m_linkPolicy = policy;
  return true;
}

bool DnsUtilsLinux::callChecked(const QString &method, const QList<QVariant> &arguments) {
  QDBusMessage message = QDBusMessage::createMethodCall(
      DBUS_RESOLVE_SERVICE, DBUS_RESOLVE_PATH, DBUS_RESOLVE_MANAGER, method);
  message.setArguments(arguments);
  const auto reply = m_resolver->connection().call(message, QDBus::Block, 4000);
  if (reply.type() != QDBusMessage::ReplyMessage) {
    logger.error() << "Confirmed DNS operation failed:" << method << reply.errorName();
    return false;
  }
  return true;
}

bool DnsUtilsLinux::updateResolversChecked(const QList<QHostAddress> &resolvers) {
  if (!m_dnsRecovery.isEmpty()) {
    // Publish exactly the journaled state, including scoped domains and
    // default-route. This also keeps replacement and crash recovery in sync.
    const auto backend = LinuxDnsRecovery::systemBackend();
    const auto links = m_dnsRecovery["links"].toArray();
    for (const auto &value : links) {
      const auto link = value.toObject();
      const auto current = backend.read(link["index"].toInt());
      if (current["name"] != link["name"] || current["hardware"] != link["hardware"]
          || (link.contains("native_policy") && current["native_policy"] != link["native_policy"]))
        return false;
      const auto after = link["after"].toObject();
      for (auto it = after.begin(); it != after.end(); ++it) {
        if (!backend.write(link["index"].toInt(), it.key(), it.value())) return false;
      }
    }
    for (const auto &value : links) {
      const auto link = value.toObject();
      const auto current = backend.read(link["index"].toInt());
      if (current["name"] != link["name"] || current["hardware"] != link["hardware"])
        return false;
      if (link.contains("native_policy") && current["native_policy"] != link["native_policy"])
        return false;
      const auto after = link["after"].toObject();
      for (auto it = after.begin(); it != after.end(); ++it)
        if (current[it.key()] != it.value()) return false;
    }
    return true;
  }
  if (!m_strictDomainsSaved) {
    QDBusMessage message = QDBusMessage::createMethodCall(
        DBUS_RESOLVE_SERVICE, DBUS_RESOLVE_PATH, DBUS_PROPERTY_INTERFACE, "Get");
    message << QString(DBUS_RESOLVE_MANAGER) << QString("Domains");
    QDBusReply<QDBusVariant> reply =
        m_resolver->connection().call(message, QDBus::Block, 4000);
    if (!reply.isValid()) return false;
    const auto value = reply.value().variant();
    if (!value.canConvert<QDBusArgument>() && !value.canConvert<QList<DnsDomain>>()) return false;
    const auto domains = qdbus_cast<QList<DnsDomain>>(value);
    QMap<int, DnsLinkDomainList> saved;
    for (const auto &domain : domains) {
      if (domain.ifindex != 0)
        saved[domain.ifindex].append(DnsLinkDomain(domain.domain, domain.search));
    }
    m_linkDomains = saved;
    m_strictDomainsSaved = true;
  }
  QList<DnsResolver> servers;
  for (const auto &server : resolvers) servers.append(server);
  if (!callChecked("SetLinkDNS", {m_ifindex, QVariant::fromValue(servers)}) ||
      !callChecked("SetLinkDefaultRoute", {m_ifindex, true})) return false;
  const DnsLinkDomain root(".", true);
  for (auto it = m_linkDomains.constBegin(); it != m_linkDomains.constEnd(); ++it) {
    if (!it.value().contains(root)) continue;
    auto domains = it.value();
    domains.removeAll(root);
    if (!callChecked("SetLinkDomains", {it.key(), QVariant::fromValue(domains)})) return false;
  }
  const DnsLinkDomainList domains = {root};
  return callChecked("SetLinkDomains", {m_ifindex, QVariant::fromValue(domains)});
}

bool DnsUtilsLinux::restoreResolversChecked() {
  for (auto it = m_linkDomains.constBegin(); it != m_linkDomains.constEnd(); ++it) {
    char name[IF_NAMESIZE];
    if (if_indextoname(it.key(), name) == nullptr) continue; // Removed link has no resolver state.
    if (!callChecked("SetLinkDomains", {it.key(), QVariant::fromValue(it.value())})) return false;
  }
  if (m_ifindex > 0) {
    char name[IF_NAMESIZE];
    if (if_indextoname(m_ifindex, name) != nullptr && !callChecked("RevertLink", {m_ifindex}))
      return false;
  }
  m_ifindex = 0;
  m_linkDomains.clear();
  m_strictDomainsSaved = false;
  return true;
}

void DnsUtilsLinux::dnsCallCompleted(QDBusPendingCallWatcher* call) {
  QDBusPendingReply<> reply = *call;
  if (reply.isError()) {
    logger.error() << "DNS D-Bus call failed:"
                   << call->property("dnsMethod").toString()
                   << "ifindex" << call->property("dnsIfindex").toString()
                   << reply.error().name() << reply.error().message();
  }
  delete call;
}

void DnsUtilsLinux::setLinkDNS(int ifindex,
                               const QList<QHostAddress>& resolvers) {
  QList<DnsResolver> resolverList;
  char ifnamebuf[IF_NAMESIZE];
  const char* ifname = if_indextoname(ifindex, ifnamebuf);
  for (const auto& ip : resolvers) {
    resolverList.append(ip);
    if (ifname) {
      logger.debug() << "Adding DNS resolver" << ip.toString() << "via"
                     << ifname;
    }
  }

  QList<QVariant> argumentList;
  argumentList << QVariant::fromValue(ifindex);
  argumentList << QVariant::fromValue(resolverList);
  QDBusPendingReply<> reply = m_resolver->asyncCallWithArgumentList(
      QStringLiteral("SetLinkDNS"), argumentList);

  QDBusPendingCallWatcher* watcher = new QDBusPendingCallWatcher(reply, this);
  watcher->setProperty("dnsMethod", QStringLiteral("SetLinkDNS"));
  watcher->setProperty("dnsIfindex", ifindex);
  QObject::connect(watcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this,
                   SLOT(dnsCallCompleted(QDBusPendingCallWatcher*)));
}

void DnsUtilsLinux::setLinkDomains(int ifindex,
                                   const QList<DnsLinkDomain>& domains) {
  char ifnamebuf[IF_NAMESIZE];
  const char* ifname = if_indextoname(ifindex, ifnamebuf);
  if (ifname) {
    for (const auto& d : domains) {
      // The DNS search domains often winds up revealing user's ISP which
      // can correlate back to their location.
      logger.debug() << "Setting DNS domain:" << logger.sensitive(d.domain)
                     << "via" << ifname << (d.search ? "search" : "");
    }
  }

  QList<QVariant> argumentList;
  argumentList << QVariant::fromValue(ifindex);
  argumentList << QVariant::fromValue(domains);
  QDBusPendingReply<> reply = m_resolver->asyncCallWithArgumentList(
      QStringLiteral("SetLinkDomains"), argumentList);

  QDBusPendingCallWatcher* watcher = new QDBusPendingCallWatcher(reply, this);
  watcher->setProperty("dnsMethod", QStringLiteral("SetLinkDomains"));
  watcher->setProperty("dnsIfindex", ifindex);
  QObject::connect(watcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this,
                   SLOT(dnsCallCompleted(QDBusPendingCallWatcher*)));
}

void DnsUtilsLinux::setLinkDefaultRoute(int ifindex, bool enable) {
  QList<QVariant> argumentList;
  argumentList << QVariant::fromValue(ifindex);
  argumentList << QVariant::fromValue(enable);
  QDBusPendingReply<> reply = m_resolver->asyncCallWithArgumentList(
      QStringLiteral("SetLinkDefaultRoute"), argumentList);

  QDBusPendingCallWatcher* watcher = new QDBusPendingCallWatcher(reply, this);
  watcher->setProperty("dnsMethod", QStringLiteral("SetLinkDefaultRoute"));
  watcher->setProperty("dnsIfindex", ifindex);
  QObject::connect(watcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this,
                   SLOT(dnsCallCompleted(QDBusPendingCallWatcher*)));
}

void DnsUtilsLinux::updateLinkDomains() {
  /* Get the list of search domains, and remove any others that might conspire
   * to satisfy DNS resolution. Unfortunately, this is a pain because Qt doesn't
   * seem to be able to demarshall complex property types.
   */
  QDBusMessage message = QDBusMessage::createMethodCall(
      DBUS_RESOLVE_SERVICE, DBUS_RESOLVE_PATH, DBUS_PROPERTY_INTERFACE, "Get");
  message << QString(DBUS_RESOLVE_MANAGER);
  message << QString("Domains");
  QDBusPendingReply<QVariant> reply =
      m_resolver->connection().asyncCall(message);

  QDBusPendingCallWatcher* watcher = new QDBusPendingCallWatcher(reply, this);
  watcher->setProperty("domainGeneration", QVariant::fromValue(m_domainGeneration));
  QObject::connect(watcher, SIGNAL(finished(QDBusPendingCallWatcher*)), this,
                    SLOT(dnsDomainsReceived(QDBusPendingCallWatcher*)));
}

void DnsUtilsLinux::dnsDomainsReceived(QDBusPendingCallWatcher* call) {
  if (call->property("domainGeneration").toULongLong() != m_domainGeneration) {
    delete call;
    return;
  }
  QDBusPendingReply<QVariant> reply = *call;
  if (reply.isError()) {
    logger.error() << "Error retrieving DNS domains from systemd-resolved:"
                   << reply.error().name() << reply.error().message();
    delete call;
    return;
  }

  /* Update the state of the DNS domains */
  m_linkDomains.clear();
  QDBusArgument args = qvariant_cast<QDBusArgument>(reply.value());
  QList<DnsDomain> list = qdbus_cast<QList<DnsDomain>>(args);
  for (const auto& d : list) {
    if (d.ifindex == 0) {
      continue;
    }
    m_linkDomains[d.ifindex].append(DnsLinkDomain(d.domain, d.search));
  }

  /* Drop any competing root search domains. */
  DnsLinkDomain root = DnsLinkDomain(".", true);
  for (auto iterator = m_linkDomains.constBegin();
       iterator != m_linkDomains.constEnd(); ++iterator) {
    if (!iterator.value().contains(root)) {
      continue;
    }
    QList<DnsLinkDomain> newlist = iterator.value();
    newlist.removeAll(root);
    setLinkDomains(iterator.key(), newlist);
  }

  /* Add a root search domain for the new interface. */
  QList<DnsLinkDomain> newlist = {root};
  setLinkDomains(m_ifindex, newlist);
  delete call;
}

static DnsMetatypeRegistrationProxy s_dnsMetatypeProxy;
