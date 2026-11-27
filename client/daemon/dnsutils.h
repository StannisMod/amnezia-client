/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef DNSUTILS_H
#define DNSUTILS_H

#include <QHostAddress>
#include <QString>
#include <QTimer>
#include <functional>
#include <memory>
#include <vector>
#include <utility>

#include "nativeDnsGuard.h"

class DnsUtils : public QObject {
  Q_OBJECT

 public:
   explicit DnsUtils(QObject* parent) : QObject(parent) {
     m_guardWatch.setParent(this);
     m_guardWatch.setInterval(250);
     QObject::connect(&m_guardWatch, &QTimer::timeout, this, [this] {
        if (m_activeGuard && !m_failureReported && !m_activeGuard->healthy()) {
          m_uncertainPublication = true;
          m_activeGuard->quiesce();
         m_failureReported = true;
         emit nativeDnsFailed(m_guardOwner);
       }
     });
   };
  virtual ~DnsUtils() = default;

  using NativeDnsFactory = std::function<std::unique_ptr<NativeDnsGuard>()>;
  static void setNativeDnsFactory(NativeDnsFactory factory) {
    nativeDnsFactory() = std::move(factory);
  }

  // ON remains the original platform path. OFF prepares listeners before
  // publishing their addresses and never publishes an unprepared fallback.
  bool reserveNativeOwner(const QString &owner) {
    if (owner.isEmpty() || !m_guardOwner.isEmpty() || m_activeGuard
            || !m_pendingGuards.empty() || m_publicationAttempted || m_uncertainPublication) return false;
    m_guardOwner = owner;
    return true;
  }
  bool nativeDnsHealthy(const QString &owner) const {
    return owner == m_guardOwner && m_activeGuard && !m_uncertainPublication
        && m_activeGuard->healthy();
  }
  bool updateResolvers(const QString& ifname, const QList<QHostAddress>& resolvers,
                       bool ipv6Enabled = true, const QString &owner = {},
                       const QJsonObject &metadata = {}, const QJsonObject &linkPolicy = {},
                       const QJsonArray &resolverPolicy = {}) {
    if ((!m_guardOwner.isEmpty() || m_activeGuard || !m_pendingGuards.empty() || m_publicationAttempted)
            && owner != m_guardOwner) return false;
    if (m_uncertainPublication || !retirePending()) return false;
    if (ipv6Enabled && !resolverPolicy.isEmpty()) return false;
    if ((!linkPolicy.isEmpty() && ipv6Enabled) || !setLinkPolicy(linkPolicy)) return false;
    if (ipv6Enabled) {
      if (m_activeGuard || !m_pendingGuards.empty()) return false;
      m_guardOwner = owner;
      m_publicationAttempted = true;
      return updateResolversNative(ifname, resolvers, false);
    }
     QJsonArray selectedPolicy;
     if (!selectResolverPolicy(ifname, resolvers, resolverPolicy, selectedPolicy)) {
       // A known failed native-policy read must not leave the preceding
       // generation forwarding against stale security metadata until a timer.
       if (m_activeGuard || !m_pendingGuards.empty()) {
         quiesceResolvers(owner);
         if (!m_failureReported) {
           m_failureReported = true;
           emit nativeDnsFailed(m_guardOwner);
         }
       }
       return false;
     }
     if (m_activeGuard && m_activeGuard->matchesResolverPolicy(selectedPolicy)
            && m_activeGuard->matches(ifname, resolvers)) {
      if (!m_activeGuard->setProtocolMetadata(metadata)) return false;
      if (!prepareDnsRecovery(*m_activeGuard, ifname, m_guardEndpoints)) return false;
      m_publicationAttempted = true;
      if (!updateResolversNative(ifname, m_guardEndpoints, true)) {
        m_activeGuard->quiesce();
        m_uncertainPublication = true;
        return false;
      }
      m_failureReported = false;
      return true;
    }
    const auto &factory = nativeDnsFactory();
    if (!factory) return false;
    auto candidate = factory();
    QList<QHostAddress> endpoints;
     if (!candidate || !candidate->setResolverPolicy(selectedPolicy)) return false;
    if (!candidate->prepare(ifname, resolvers, endpoints)) {
      // Preparation can fail after assigning aliases. Keep failed cleanup
      // owned and retryable rather than losing it with the candidate.
      if (!candidate->retire()) {
        m_guardOwner = owner;
        m_pendingGuards.push_back(std::move(candidate));
      }
      return false;
    }
    m_guardOwner = owner;
    if (endpoints.size() != resolvers.size()) {
      if (!candidate->retire()) m_pendingGuards.push_back(std::move(candidate));
      return false;
    }
    if (!candidate->setProtocolMetadata(metadata) || !prepareDnsRecovery(*candidate, ifname, endpoints)) {
      if (!candidate->retire()) m_pendingGuards.push_back(std::move(candidate));
      return false;
    }
    m_publicationAttempted = true;
    if (!updateResolversNative(ifname, endpoints, true)) {
      // A failed/late OS operation may still have installed these endpoints.
      // Retain them until restoration is confirmed, not an assumed rollback.
      candidate->quiesce();
      m_pendingGuards.push_back(std::move(candidate));
      m_uncertainPublication = true;
      return false;
    }
    if (m_activeGuard) m_pendingGuards.push_back(std::move(m_activeGuard));
    m_activeGuard = std::move(candidate);
    m_guardEndpoints = endpoints;
    m_failureReported = false;
    m_guardWatch.start();
    return retirePending();
  }

  bool quiesceResolvers(const QString &owner = {}) {
    if ((!m_guardOwner.isEmpty() || m_activeGuard || !m_pendingGuards.empty() || m_publicationAttempted)
            && owner != m_guardOwner) return false;
    const bool guarded = m_activeGuard || !m_pendingGuards.empty();
    if (guarded) m_uncertainPublication = true;
    bool complete = true;
    if (m_activeGuard && !m_activeGuard->quiesce()) complete = false;
    for (const auto &guard : m_pendingGuards)
      if (!guard->quiesce()) complete = false;
    return complete;
  }
  bool restoreResolvers(const QString &owner = {}) {
    if (!quiesceResolvers(owner)) return false;
    const bool guarded = m_activeGuard || !m_pendingGuards.empty();
    // Refused policy/failed preparation has not changed OS DNS. In particular,
    // do not run a platform reset against an uninitialized/foreign interface.
    if (m_publicationAttempted && !restoreResolversNative(guarded)) return false;
    m_uncertainPublication = false;
    if (m_activeGuard) m_pendingGuards.push_back(std::move(m_activeGuard));
    m_guardEndpoints.clear();
    m_guardWatch.stop();
    m_failureReported = false;
    const bool restored = retirePending();
    if (restored) {
      m_guardOwner.clear();
      m_publicationAttempted = false;
    }
    return restored;
  }
  bool restoreResolversForCurrentOwner() { return restoreResolvers(m_guardOwner); }

 signals:
  void nativeDnsFailed(const QString &owner);

 protected:
   virtual bool selectResolverPolicy(const QString &, const QList<QHostAddress> &,
                                     const QJsonArray &requested, QJsonArray &selected) {
     selected = requested;
     return true;
   }
   virtual bool setLinkPolicy(const QJsonObject &policy) { return policy.isEmpty(); }
   virtual bool prepareDnsRecovery(NativeDnsGuard &, const QString &,
                                   const QList<QHostAddress> &) { return true; }
  virtual bool updateResolversNative(const QString& ifname,
                                    const QList<QHostAddress>& resolvers, bool strict) {
    Q_UNUSED(ifname); Q_UNUSED(resolvers); Q_UNUSED(strict);
    qFatal("Have you forgotten to implement DnsUtils::updateResolvers?");
    return false;
  };

  virtual bool restoreResolversNative(bool strict) {
    Q_UNUSED(strict);
    qFatal("Have you forgotten to implement DnsUtils::restoreResolvers?");
    return false;
  }

 private:
  static NativeDnsFactory &nativeDnsFactory() {
    static NativeDnsFactory factory;
    return factory;
  }
  bool retirePending() {
    bool complete = true;
    for (auto it = m_pendingGuards.begin(); it != m_pendingGuards.end();) {
      if ((*it)->retire()) it = m_pendingGuards.erase(it);
      else { complete = false; ++it; }
    }
    return complete;
  }
  std::unique_ptr<NativeDnsGuard> m_activeGuard;
  std::vector<std::unique_ptr<NativeDnsGuard>> m_pendingGuards;
  bool m_uncertainPublication = false;
  bool m_publicationAttempted = false;
  QList<QHostAddress> m_guardEndpoints;
  QTimer m_guardWatch;
  bool m_failureReported = false;
  QString m_guardOwner;
};

#endif  // DNSUTILS_H
