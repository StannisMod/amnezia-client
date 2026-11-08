/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef LOCALSOCKETCONTROLLER_H
#define LOCALSOCKETCONTROLLER_H

#include <QHostAddress>
#include <QLocalSocket>
#include <QTimer>
#include <functional>

#include "controllerimpl.h"


class QJsonObject;

class LocalSocketController final : public ControllerImpl {
  Q_DISABLE_COPY_MOVE(LocalSocketController)

 public:
  explicit LocalSocketController(const QString &socketPath = QString());
  ~LocalSocketController();

  void initialize(const Device* device, const Keys* keys) override;

  void activate(const QJsonObject& rawConfig) override;

  void deactivate() override;
  void deactivateWithAck() override;
  void resolveEndpoint(const QString &host, std::function<void(QList<QHostAddress>)> complete) override;
  void cancelEndpointLookup() override;
  QString routingRuntimeId() const override { return m_runtimeId; }
  bool routingRecoverySupported() const override { return m_preserveCapability; }
  void hintRoutingNetwork(const QString &id) override;

  void checkStatus() override;

  void getBackendLogs(std::function<void(const QString&)>&& callback) override;

  void cleanupBackendLogs() override;

  bool multihopSupported() override { return true; }

 private:
  void initializeInternal();
  void disconnectInternal();

  void daemonConnected();
  void errorOccurred(QLocalSocket::LocalSocketError socketError);
  void readData();
  void parseCommand(const QByteArray& command);

  void write(const QJsonObject& json);

 private:
  enum {
    eUnknown,
    eInitializing,
    eReady,
    eDisconnected,
  } m_daemonState = eUnknown;

  QLocalSocket* m_socket = nullptr;
  QString m_socketPath;

  QByteArray m_buffer;

  QString m_deviceIpv4;
  QString m_runtimeId;
  quint64 m_statusId = 0, m_activationStatusFloor = 0;
  bool m_routedActivation = false;
  bool m_ownershipProtocol = false;
  bool m_preserveCapability = false;
  quint64 m_activationId = 0;
  quint64 m_cleanupId = 0, m_waitingCleanupId = 0;
  quint32 m_endpointLookupId = 0;
  quint32 m_endpointResolverAttempt = 0;
  std::function<void(QList<QHostAddress>)> m_endpointCompletion;
  bool m_pendingConfirmedDeactivation = false;
  std::function<void(const QString&)> m_logCallback = nullptr;

  QTimer m_initializingTimer;
  uint32_t m_initializingRetry = 0;
};

#endif  // LOCALSOCKETCONTROLLER_H
