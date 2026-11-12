#ifndef CONNECTIONUPDATES_H
#define CONNECTIONUPDATES_H

#include <QJsonObject>
#include <QByteArray>
#include <QString>
#include <QStringList>

namespace amnezia::connectionUpdates {
inline constexpr char metadataKey[] = "connectionUpdates";
// All outputs are assigned only after full authentication and validation.
bool parsePathProbeAddress(const QString &output, const QString &interfaceName, QString &address);
bool parsePeerList(const QString &output, QStringList &peers);
// Accept only unambiguous individual IPv6 /128 assignments from live WG/AWG output.
bool parsePeerIPv6Assignments(const QString &output, QJsonObject &assignments);
bool validateProfile(const QJsonObject &profile);
QJsonObject invitationMetadata(const QJsonObject &administratorMetadata);
QJsonObject publicSettings(const QJsonObject &client, bool awg);
bool mergeServerSettings(const QJsonObject &profile, const QString &container,
                         const QJsonObject &settings, bool preserveManagementHost,
                         QJsonObject &updated);
bool mergePathProbe(const QJsonObject &profile, const QString &container, const QJsonValue &target, QJsonObject &updated);
QByteArray readinessProof(const QJsonObject &profile, const QByteArray &envelope, qint64 now);
bool attachInvitation(const QJsonObject &profile, const QJsonObject &invitation, QJsonObject &updated);
bool clientIdentityMatches(const QJsonObject &client);
bool apply(const QJsonObject &profile, const QByteArray &envelope, qint64 now,
           QJsonObject &updated);
QString updateNativeConfig(const QString &native, const QJsonObject &settings, bool awg);
}
#endif
