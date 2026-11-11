#include "appSplitTunnelingController.h"
#include <QJsonArray>

AppSplitTunnelingController::AppSplitTunnelingController(SecureAppSettingsRepository* appSettingsRepository)
    : m_appSettingsRepository(appSettingsRepository)
{
    m_currentRouteMode = m_appSettingsRepository->appsRouteMode();
    if (m_currentRouteMode == AppsRouteMode::VpnAllApps) { // for old split tunneling configs
        m_currentRouteMode = AppsRouteMode::VpnAllExceptApps;
        m_apps = m_appSettingsRepository->vpnApps(m_currentRouteMode);
        m_appSettingsRepository->setAppsRouteMode(AppsRouteMode::VpnAllExceptApps);
    } else {
        m_apps = m_appSettingsRepository->vpnApps(m_currentRouteMode);
    }
}

bool AppSplitTunnelingController::addApp(const amnezia::InstalledAppInfo &appInfo)
{
    if (m_apps.contains(appInfo)) {
        return false;
    }

    m_apps.append(appInfo);
    m_appSettingsRepository->setVpnApps(m_currentRouteMode, m_apps);

    return true;
}

void AppSplitTunnelingController::removeApp(int index)
{
    if (index < 0 || index >= m_apps.size()) {
        return;
    }

    const auto removedPackage = m_apps.at(index).packageName;
    m_apps.removeAt(index);
    auto policy = m_appSettingsRepository->androidAppRoutingPolicy();
    if (!policy.isEmpty() && m_currentRouteMode == AppsRouteMode::VpnOnlyForwardApps) {
        QJsonArray retained;
        for (const auto &name : policy.value("site_rule_packages").toArray())
            if (name.toString() != removedPackage) retained.append(name);
        policy.insert("site_rule_packages", retained);
        m_appSettingsRepository->setAndroidAppRoutingPolicy(policy);
    }
    m_appSettingsRepository->setVpnApps(m_currentRouteMode, m_apps);
}

void AppSplitTunnelingController::clearAppsList()
{
    if (m_currentRouteMode == AppsRouteMode::VpnOnlyForwardApps) {
        auto policy = m_appSettingsRepository->androidAppRoutingPolicy();
        if (!policy.isEmpty()) {
            policy.insert("site_rule_packages", QJsonArray());
            m_appSettingsRepository->setAndroidAppRoutingPolicy(policy);
        }
    }
    m_apps.clear();
    m_appSettingsRepository->setVpnApps(m_currentRouteMode, m_apps);
}

void AppSplitTunnelingController::setRouteMode(AppsRouteMode routeMode)
{
    m_currentRouteMode = routeMode;
    m_apps = m_appSettingsRepository->vpnApps(m_currentRouteMode);
    m_appSettingsRepository->setAppsRouteMode(routeMode);
}

void AppSplitTunnelingController::toggleSplitTunneling(bool enabled)
{
    m_appSettingsRepository->setAppsSplitTunnelingEnabled(enabled);
}

AppsRouteMode AppSplitTunnelingController::getRouteMode() const
{
    return m_currentRouteMode;
}

bool AppSplitTunnelingController::isSplitTunnelingEnabled() const
{
    return m_appSettingsRepository->isAppsSplitTunnelingEnabled();
}

QVector<amnezia::InstalledAppInfo> AppSplitTunnelingController::getApps() const
{
    return m_apps;
}

bool AppSplitTunnelingController::appliesSiteRules(int index) const
{
    if (index < 0 || index >= m_apps.size()) return false;
    const auto policy = m_appSettingsRepository->androidAppRoutingPolicy();
    if (policy.isEmpty()) return true; // Preserve existing intersection until an explicit choice.
    return policy.value("site_rule_packages").toArray().contains(m_apps.at(index).packageName);
}

bool AppSplitTunnelingController::setAppliesSiteRules(int index, bool enabled)
{
    if (m_currentRouteMode != AppsRouteMode::VpnOnlyForwardApps || index < 0 || index >= m_apps.size()
        || m_apps.at(index).packageName.isEmpty()) return false;
    auto policy = m_appSettingsRepository->androidAppRoutingPolicy();
    QJsonArray packages;
    for (int i = 0; i < m_apps.size(); ++i) {
        if ((i == index ? enabled : appliesSiteRules(i)) && !m_apps.at(i).packageName.isEmpty())
            packages.append(m_apps.at(i).packageName);
    }
    policy.insert("version", 1);
    policy.insert("site_rule_packages", packages);
    m_appSettingsRepository->setAndroidAppRoutingPolicy(policy);
    return true;
}

