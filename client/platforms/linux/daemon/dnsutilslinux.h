/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef DNSUTILSLINUX_H
#define DNSUTILSLINUX_H

#include <QDBusInterface>
#include <QDBusPendingCallWatcher>

#include "daemon/dnsutils.h"
#include "dbustypeslinux.h"

class DnsUtilsLinux final : public DnsUtils {
  Q_OBJECT
  Q_DISABLE_COPY_MOVE(DnsUtilsLinux)

 public:
  DnsUtilsLinux(QObject* parent);
  ~DnsUtilsLinux();
  bool updateResolversNative(const QString& ifname,
                       const QList<QHostAddress>& resolvers, bool strict) override;
  bool restoreResolversNative(bool strict) override;
  bool prepareDnsRecovery(NativeDnsGuard &guard, const QString &ifname,
                           const QList<QHostAddress> &endpoints) override;
  bool setLinkPolicy(const QJsonObject &policy) override;

 private:
  void setLinkDNS(int ifindex, const QList<QHostAddress>& resolvers);
  void setLinkDomains(int ifindex, const QList<DnsLinkDomain>& domains);
  void setLinkDefaultRoute(int ifindex, bool enable);
  void updateLinkDomains();
  bool callChecked(const QString &method, const QList<QVariant> &arguments);
  bool updateResolversChecked(const QList<QHostAddress> &resolvers);
  bool restoreResolversChecked();

 private slots:
  void dnsCallCompleted(QDBusPendingCallWatcher*);
  void dnsDomainsReceived(QDBusPendingCallWatcher*);

 private:
  int m_ifindex = 0;
  QMap<int, DnsLinkDomainList> m_linkDomains;
  bool m_strictDomainsSaved = false;
  quint64 m_domainGeneration = 0;
  QDBusInterface* m_resolver = nullptr;
  QJsonObject m_dnsRecovery;
  QJsonObject m_linkPolicy;
};

#endif  // DNSUTILSLINUX_H
