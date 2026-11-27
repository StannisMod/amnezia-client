/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef DNSUTILSWINDOWS_H
#define DNSUTILSWINDOWS_H

#include <winsock2.h>
#include <windows.h>

#include <QHostAddress>
#include <QString>

#include "daemon/dnsutils.h"

class DnsUtilsWindows final : public DnsUtils {
  Q_OBJECT
  Q_DISABLE_COPY_MOVE(DnsUtilsWindows)

 public:
  explicit DnsUtilsWindows(QObject* parent);
  virtual ~DnsUtilsWindows();
  bool updateResolversNative(const QString& ifname,
                       const QList<QHostAddress>& resolvers, bool strict) override;
  bool restoreResolversNative(bool strict) override;
  bool prepareDnsRecovery(NativeDnsGuard &guard, const QString &ifname,
                          const QList<QHostAddress> &endpoints) override;
  bool selectResolverPolicy(const QString &ifname, const QList<QHostAddress> &resolvers,
                            const QJsonArray &requested, QJsonArray &selected) override;

 private:
  quint64 m_luid = 0;
  QJsonObject m_dnsRecovery;
  QJsonObject m_selectedPolicyProof;
  DWORD (*m_setInterfaceDnsSettingsProcAddr)(GUID, const void*) = nullptr;

  bool updateResolversWin32(GUID, const QList<QHostAddress>& resolvers);
  bool updateResolversNetsh(int ifindex, const QList<QHostAddress>& resolvers);
};

#endif  // DNSUTILSWINDOWS_H
