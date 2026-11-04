#ifndef CONNECTIONUPDATES_H
#define CONNECTIONUPDATES_H

#include <QJsonObject>
#include <QString>

namespace amnezia::connectionUpdates {
inline constexpr char metadataKey[] = "connectionUpdates";
// All outputs are assigned only after full authentication and validation.
bool validateProfile(const QJsonObject &profile);
QJsonObject invitationMetadata(const QJsonObject &administratorMetadata);
QJsonObject publicSettings(const QJsonObject &client, bool awg);
bool apply(const QJsonObject &profile, const QByteArray &envelope, qint64 now,
           QJsonObject &updated);
QString updateNativeConfig(const QString &native, const QJsonObject &settings, bool awg);
}
#endif
