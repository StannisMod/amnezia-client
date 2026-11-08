/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "daemonlocalserverconnection.h"

#include <QJsonDocument>
#include <QJsonArray>
#include <QStringList>
#include "killswitch.h"
#include <QJsonObject>
#include <QJsonValue>
#include <QLocalSocket>

#include "daemon.h"
#include "leakdetector.h"
#include "logger.h"
#if defined(MZ_LINUX) || defined(MZ_WINDOWS)
#include "desktoproutingprocess.h"
#include "killswitch.h"
#endif

namespace {
Logger logger("DaemonLocalServerConnection");
}

DaemonLocalServerConnection::DaemonLocalServerConnection(QObject* parent,
                                                         QLocalSocket* socket)
    : QObject(parent) {
  MZ_COUNT_CTOR(DaemonLocalServerConnection);

  logger.debug() << "Connection created";

  Q_ASSERT(socket);
  m_socket = socket;

  connect(m_socket, &QLocalSocket::readyRead, this,
          &DaemonLocalServerConnection::readData);

  Daemon* daemon = Daemon::instance();
  connect(daemon, &Daemon::connected, this,
          &DaemonLocalServerConnection::connected);
  connect(daemon, &Daemon::disconnected, this,
          &DaemonLocalServerConnection::disconnected);
  connect(daemon, &Daemon::backendFailure, this,
          &DaemonLocalServerConnection::backendFailure);
#if defined(MZ_LINUX) || defined(MZ_WINDOWS)
  auto routing = DesktopRoutingProcess::instance();
  connect(routing, &DesktopRoutingProcess::connected, this, [this,routing](const QString &pubkey) {
    auto row=routing->status();
    row.insert("type","connected");
    row.insert("pubkey",pubkey);
    row.insert("ownership_protocol",1);
    write(row);
  });
  connect(routing, &DesktopRoutingProcess::disconnected, this, &DaemonLocalServerConnection::disconnected);
  connect(routing, &DesktopRoutingProcess::failed, this, [this] { backendFailure(DaemonError::ERROR_FATAL); });
#endif
}

DaemonLocalServerConnection::~DaemonLocalServerConnection() {
  MZ_COUNT_DTOR(DaemonLocalServerConnection);

  logger.debug() << "Connection released";
}

void DaemonLocalServerConnection::readData() {
  logger.debug() << "Read Data";

  Q_ASSERT(m_socket);

  while (true) {
    int pos = m_buffer.indexOf("\n");
    if (pos == -1) {
      QByteArray input = m_socket->readAll();
      if (input.isEmpty()) {
        break;
      }
      m_buffer.append(input);
      continue;
    }

    QByteArray line = m_buffer.left(pos);
    m_buffer.remove(0, pos + 1);

    QByteArray command(line);
    command = command.trimmed();

    if (command.isEmpty()) {
      continue;
    }

    parseCommand(command);
  }
}

void DaemonLocalServerConnection::parseCommand(const QByteArray& data) {
  QJsonDocument json = QJsonDocument::fromJson(data);
  if (!json.isObject()) {
    logger.error() << "Invalid input";
    return;
  }

  QJsonObject obj = json.object();
  QJsonValue typeValue = obj.value("type");
  if (!typeValue.isString()) {
    logger.warning() << "No type command. Ignoring request.";
    return;
  }
  QString type = typeValue.toString();

  logger.debug() << "Command received:" << type;

  // It is expected that sometimes the client will request backend logs
  // before the first authentication. In these cases we just return empty
  // logs.
  if (type == "logs") {
    QJsonObject obj;
    obj.insert("type", "logs");
    obj.insert("logs", "");
    write(obj);
    return;
  }

  if (type == "cancel_endpoint_lookup") { m_endpointDns.cancel(); return; }
  if (type == "resolve_endpoint") {
    const auto id = obj.value("lookup_id");
    // Fixed public bootstrap resolvers: an IPC client cannot turn this into an
    // arbitrary destination/port exception. A new attempt alternates resolvers.
    QHostAddress resolver(obj.value("alternate").toBool() ? "8.8.8.8" : "1.1.1.1");
#ifdef Q_OS_LINUX
    const QStringList resolvers{"1.1.1.1", "2606:4700:4700::1111", "8.8.8.8", "2001:4860:4860::8888"};
    if (obj.contains("resolver_index")) {
      const auto value = obj.value("resolver_index");
      const int index = value.toInt(-1);
      if (!value.isDouble() || index < 0 || index >= resolvers.size() || value.toDouble() != double(index)) {
        write(QJsonObject{{"type", "endpoint_resolved"}, {"lookup_id", id}, {"addresses", QJsonArray{}}});
        return;
      }
      resolver = QHostAddress(resolvers.at(index));
    }
#endif
    m_endpointDns.start(obj.value("host").toString(), resolver,
      [](quint16 port, const QHostAddress &address, bool enabled) {
        return KillSwitch::instance()->endpointDnsAllowed(port, address, enabled);
      }, [this, id](const QList<QHostAddress> &addresses) {
        QJsonArray values;
        for (const auto &address : addresses) values.append(address.toString());
        write(QJsonObject{{"type", "endpoint_resolved"}, {"lookup_id", id}, {"addresses", values}});
      });
    return;
  }

  if (type == "activate") {
    m_endpointDns.cancel();
#if defined(MZ_LINUX) || defined(MZ_WINDOWS)
    if (obj.contains("routing_profile")) {
      Daemon::instance()->deactivate(false);
      if (!DesktopRoutingProcess::instance()->start(obj.value("routing_profile").toObject(), KillSwitch::instance()->isStrictKillSwitchEnabled())) {
        backendFailure(DaemonError::ERROR_FATAL);
        disconnected();
      } else {
        write(QJsonObject{{"type","routing_activated"},{"activation_id",obj.value("activation_id")},
                          {"runtime_id",DesktopRoutingProcess::instance()->status().value("runtime_id")}});
      }
      return;
    }
    DesktopRoutingProcess::instance()->stop(false);
#endif
    InterfaceConfig config;
    if (!Daemon::parseConfig(obj, config)) {
      logger.error() << "Invalid configuration";
      emit disconnected();
      return;
    }

    if (!Daemon::instance()->activate(config)) {
      logger.error() << "Failed to activate the interface";
      emit disconnected();
    }
    return;
  }

#if defined(MZ_LINUX) || defined(MZ_WINDOWS)
  if (type == "routing_network_changed") {
    const auto id = obj.value("runtime_id").toString();
    const bool queued = DesktopRoutingProcess::instance()->networkChanged(id);
    write(QJsonObject{{"type", "routing_network_hint"}, {"runtime_id", id}, {"queued", queued}});
    return;
  }
#endif

  if (type == "deactivate") {
    m_endpointDns.cancel();
#if defined(MZ_LINUX) || defined(MZ_WINDOWS)
    const auto expectedRuntime = obj.value("runtime_id").toString();
    if (!expectedRuntime.isEmpty() && !DesktopRoutingProcess::instance()->matchesRuntime(expectedRuntime)) {
      write(QJsonObject{{"type", "runtime_changed"}, {"runtime_id", expectedRuntime}});
      return; // A stale GUI must not stop a replacement owner or legacy tunnel.
    }
    if (DesktopRoutingProcess::instance()->isActive()) {
      DesktopRoutingProcess::instance()->stop();
      if (obj.value("request_ack").toBool() && !DesktopRoutingProcess::instance()->isActive())
        write(QJsonObject{{"type", "deactivated"}, {"runtime_id", expectedRuntime}, {"cleanup_id", obj.value("cleanup_id")}});
      return;
    }
#endif
    const bool cleaned = Daemon::instance()->deactivate(true);
    if (obj.value("request_ack").toBool() && cleaned) write(QJsonObject{{"type", "deactivated"}, {"cleanup_id", obj.value("cleanup_id")}});
    return;
  }

  if (type == "status") {
    const auto statusId = obj.value("status_id");
    QJsonObject obj = Daemon::instance()->getStatus();
#if defined(MZ_LINUX) || defined(MZ_WINDOWS)
    if (DesktopRoutingProcess::instance()->isActive()) obj = DesktopRoutingProcess::instance()->status();
#endif
    obj.insert("type", "status");
    obj.insert("ownership_protocol", 1);
    if (!statusId.isUndefined()) obj.insert("status_id", statusId);
    write(obj);
    return;
  }

  if (type == "logs") {
    QJsonObject obj;
    obj.insert("type", "logs");
    obj.insert("logs", Daemon::instance()->logs().replace("\n", "|"));
    write(obj);
    return;
  }

  if (type == "cleanlogs") {
    Daemon::instance()->cleanLogs();
    return;
  }

  logger.warning() << "Invalid command:" << type;
}

void DaemonLocalServerConnection::connected(const QString& pubkey) {
  write(QJsonObject{{"type","connected"},{"pubkey",pubkey}});
}

void DaemonLocalServerConnection::disconnected() {
  QJsonObject obj;
  obj.insert("type", "disconnected");
  write(obj);
}

void DaemonLocalServerConnection::backendFailure(DaemonError err) {
  QJsonObject obj;
  obj.insert("type", "backendFailure");
  obj.insert("errorCode", static_cast<int>(err));
#if defined(MZ_LINUX) || defined(MZ_WINDOWS)
  auto routing = DesktopRoutingProcess::instance();
  if (routing->isActive() && routing->status().contains("routingError"))
    obj.insert("routingError", routing->status().value("routingError"));
#endif
  write(obj);
}

void DaemonLocalServerConnection::write(const QJsonObject& obj) {
  m_socket->write(QJsonDocument(obj).toJson(QJsonDocument::Compact));
  m_socket->write("\n");
}
