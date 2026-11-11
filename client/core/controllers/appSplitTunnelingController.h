#ifndef APPSPLITTUNNELINGCONTROLLER_H
#define APPSPLITTUNNELINGCONTROLLER_H

#include <QVector>

#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/repositories/secureAppSettingsRepository.h"

class AppSplitTunnelingController
{
public:
    explicit AppSplitTunnelingController(SecureAppSettingsRepository* appSettingsRepository);

    bool addApp(const amnezia::InstalledAppInfo &appInfo);
    void removeApp(int index);
    void clearAppsList();
    void setRouteMode(AppsRouteMode routeMode);
    void toggleSplitTunneling(bool enabled);

    AppsRouteMode getRouteMode() const;
    bool isSplitTunnelingEnabled() const;
    QVector<amnezia::InstalledAppInfo> getApps() const;
    bool appliesSiteRules(int index) const;
    bool setAppliesSiteRules(int index, bool enabled);
    QJsonObject siteRulesPolicy(int index, bool enabled) const;
    bool commitSiteRulesPolicy(const QJsonObject &policy);

private:
    SecureAppSettingsRepository* m_appSettingsRepository;
    AppsRouteMode m_currentRouteMode;
    QVector<amnezia::InstalledAppInfo> m_apps;
};

#endif // APPSPLITTUNNELINGCONTROLLER_H

