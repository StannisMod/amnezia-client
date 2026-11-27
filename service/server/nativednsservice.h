#ifndef NATIVEDNSSERVICE_H
#define NATIVEDNSSERVICE_H

#include <memory>
#include <QString>
#include <QJsonObject>
#include <functional>
#include "daemon/nativeDnsGuard.h"

// Uses the already-linked amnezia-xray-bindings runtime. A nonempty directory is
// for explicitly owned local fixtures; production uses the service's profile.
std::unique_ptr<NativeDnsGuard> createNativeDnsServiceGuard(const QString &directory = {});
// Shared checked owner-only storage for service-native DNS lifecycle records.
bool prepareNativeDnsPrivateDirectory(const QString &directory);

// For service startup, before admitting new DNS generations. The callback must
// compare the current OS DNS with its durable snapshot and confirm restoration;
// false preserves the journal and every alias. Never pass an unconditional
// success callback in production.
bool recoverNativeDnsServiceGuards(
    const QString &directory,
    const std::function<bool(const QJsonObject &)> &restoreDns);
#if !defined(Q_OS_ANDROID)
bool recoverNativeDnsServiceOnStartup(const QString &directory);
#endif

#endif
