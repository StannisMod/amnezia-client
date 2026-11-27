#include "openvpndnssession.h"
#include <QRegularExpression>
#include <QUuid>
#include <QScopedValueRollback>
#include <QTcpSocket>
#include <QDebug>

OpenVpnDnsSession::OpenVpnDnsSession(Operations operations, QObject *parent)
    : QObject(parent), m_operations(std::move(operations)), m_management(this),
      m_owner(QUuid::createUuid().toString(QUuid::WithoutBraces))
{
    m_retry.setInterval(250);
    connect(&m_retry, &QTimer::timeout, this, &OpenVpnDnsSession::retry);
    connect(&m_management, &ManagementServer::readyRead, this, &OpenVpnDnsSession::read);
    connect(&m_management, &ManagementServer::disconnected, this, [this] {
        m_disconnected = true;
        if (m_nativeFinished) return;
        m_stopping = true;
        m_retry.start();
        retry();
    });
}

bool OpenVpnDnsSession::start()
{
    if (m_port || !m_operations.publish || !m_operations.restore
        || !m_management.start("127.0.0.1", 0)) return false;
    m_port = m_management.port();
    return m_port != 0;
}

void OpenVpnDnsSession::fail()
{
    if (!m_failed) {
        m_failed = true;
        m_stopping = true;
        m_retry.start();
        emit failed();
    }
}

QJsonObject OpenVpnDnsSession::selectedMetadata() const
{
    QJsonObject metadata;
    for (const auto &[name, value] : m_environment.values()) {
        const auto key = QString::fromStdString(name);
        if (key == "dev" || key.startsWith("dns_server_") || key.startsWith("dns_search_domain_")
            || key.startsWith("foreign_option_") || key.startsWith("amnezia_"))
            metadata.insert(key, QString::fromStdString(value));
    }
    return metadata;
}

void OpenVpnDnsSession::read()
{
    if (m_nativeFinished) return;
    for (;;) {
        auto line = m_management.readLine();
        if (line.isEmpty()) return;
        while (line.endsWith('\r') || line.endsWith('\n')) line.chop(1);
        const auto result = m_environment.consume(line.toStdString());
        if (result != OpenVpnManagementEnvironment::Result::Ignored) {
            if (result == OpenVpnManagementEnvironment::Result::Invalid) {
                qWarning("OpenVPN DNS management environment framing rejected");
                m_frame = {};
                fail();
            } else if (result == OpenVpnManagementEnvironment::Result::Complete) {
                m_frame = m_environment.isUp() ? selectedMetadata() : QJsonObject{};
                ++m_frameSerial;
            }
            continue; // Never forward a native environment (possibly sensitive) to GUI logs.
        }
        if (line.startsWith(">NEED-OK:Need 'AMNEZIA-DNS-")) {
            static const QRegularExpression request(
                "^>NEED-OK:Need '(AMNEZIA-DNS-(PUBLISH|RESTORE):([1-9][0-9]{0,19}))' confirmation(?: MSG:.*)?$");
            const auto match = request.match(line);
            bool valid = false;
            const auto serial = match.hasMatch() ? match.captured(3).toULongLong(&valid) : 0;
            if (!valid || serial == 0) { fail(); continue; }
            if (serial <= m_lastRequest) {
                if (match.captured(1) == m_request) retry(); // Never republish on a replay.
                continue;
            }
            if (!m_request.isEmpty()) { fail(); continue; }
            m_lastRequest = serial;
            m_request = match.captured(1);
            m_action = match.captured(2) == "RESTORE" ? Action::Restore : Action::Publish;
            m_reply.clear();
            m_retry.start();
            retry();
            continue;
        }
        if (line.startsWith(">INFO:OpenVPN Management Interface")) {
            // The backend continues to operate with no GUI connected.
            m_management.writeCommand("state on");
            m_management.writeCommand("log on");
            m_management.writeCommand("bytecount 1");
        }
        emit managementLine(line);
    }
}

bool OpenVpnDnsSession::restore()
{
    if (!m_touched) return true;
    if (!m_operations.restore(m_owner)) return false;
    m_touched = m_active = false;
    m_interface.clear();
    m_metadata = {};
    return true;
}

void OpenVpnDnsSession::retry()
{
    if (m_retrying) return;
    QScopedValueRollback<bool> busy(m_retrying, true);
    if (m_nativeFinished) {
        m_request.clear();
        m_reply.clear();
        m_action = Action::Restore;
    }
    if (m_action == Action::Publish) {
        const auto nativeInterface = m_frame.value("dev").toString();
        const auto routes = m_frame.value("amnezia_native_routes").toString();
        const bool authorized = !m_stopping && !m_failed
            && m_frameSerial > m_consumedFrame
            && m_frame.value("amnezia_native_dns") == QJsonValue("external")
            && !nativeInterface.isEmpty()
            && (routes == "success" || (routes == "preserved" && m_active && nativeInterface == m_interface));
        m_consumedFrame = m_frameSerial;
        if (authorized) {
            // A failed OS publication can have mutated DNS. Mark ownership
            // BEFORE invoking it, and retain its metadata until confirmed restore.
            m_touched = true;
            m_metadata = m_frame;
            if (m_operations.publish(m_owner, m_frame)) {
                m_active = true;
                m_interface = nativeInterface;
                if (!m_stopping && !m_failed && !m_nativeFinished && !m_disconnected) {
                    m_reply = "ok";
                    m_action = Action::None;
                } else m_action = Action::Cancel; // Stop can re-enter a platform publisher.
            } else {
                m_action = Action::Cancel;
                fail();
            }
        } else {
            qWarning() << "OpenVPN DNS publication evidence rejected"
                       << "external" << (m_frame.value("amnezia_native_dns") == QJsonValue("external"))
                       << "interfacePresent" << !nativeInterface.isEmpty()
                       << "routesSuccess" << (routes == "success")
                       << "routesPreserved" << (routes == "preserved");
            m_action = Action::Cancel;
            fail();
        }
    }
    if (m_action == Action::Restore || m_action == Action::Cancel) {
        if (!restore()) return; // No ACK and no process/interface teardown.
        m_reply = m_action == Action::Restore ? "ok" : "cancel";
        m_action = Action::None;
    }
    if (!m_request.isEmpty() && !m_reply.isEmpty() && !m_disconnected && !m_nativeFinished) {
        const auto command = "needok '" + m_request + "' " + m_reply;
        if (m_management.writeCommand(command) != command.toUtf8().size() + 1) return;
        m_request.clear();
        m_reply.clear();
    }
    if (m_stopping || m_nativeFinished || m_disconnected) {
        if (!restore()) return;
        if (m_disconnected && !m_nativeFinished) {
            m_retry.stop();
            if (!m_disconnectEmitted) {
                m_disconnectEmitted = true;
                emit disconnectedAfterRestore();
            }
            return;
        }
        if (m_stopping && !m_nativeFinished && !m_stopSent)
            m_stopSent = m_management.writeCommand("signal SIGTERM") == 15;
        if (m_stopping && !m_nativeFinished && !m_stopNotified) {
            m_stopNotified = true;
            emit stopRestored();
        }
        if (m_nativeFinished) {
            m_retry.stop();
            m_management.stop();
            if (const auto peer = m_management.socket()) peer->abort();
            if (!m_cleanupEmitted) {
                m_cleanupEmitted = true;
                emit cleanupFinished();
            }
            return;
        }
    }
    if (m_request.isEmpty() && !m_stopping && !m_nativeFinished) m_retry.stop();
}

bool OpenVpnDnsSession::requestStop()
{
    m_stopping = true;
    m_retry.start();
    retry();
    return cleanupConfirmed();
}

bool OpenVpnDnsSession::nativeFinished()
{
    m_nativeFinished = true;
    m_stopping = true;
    m_retry.start();
    retry();
    return cleanupConfirmed();
}

bool OpenVpnDnsSession::command(const QString &command)
{
    // GUI cannot fabricate NEED-OK, terminate native initialization before
    // rollback, or issue management "signal"/"kill" behind the DNS owner.
    if (command == "signal SIGTERM") return requestStop();
    if (command != "state on" && command != "log on" && command != "bytecount 1") return false;
    return m_management.writeCommand(command) == command.toUtf8().size() + 1;
}

void OpenVpnDnsSession::guardFailed()
{
    fail();
    requestStop();
}
