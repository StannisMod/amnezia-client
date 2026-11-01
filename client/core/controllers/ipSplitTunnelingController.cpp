#include "ipSplitTunnelingController.h"
#include "core/utils/networkUtilities.h"
#include "core/utils/domainRoutingConfig.h"
#include <QJsonObject>
#include <QDebug>

IpSplitTunnelingController::IpSplitTunnelingController(SecureAppSettingsRepository* appSettingsRepository, QObject* parent)
    : QObject(parent),
      m_appSettingsRepository(appSettingsRepository)
{
    m_currentRouteMode = m_appSettingsRepository->routeMode();
    if (m_currentRouteMode == RouteMode::VpnAllSites) { // for old split tunneling configs
        m_appSettingsRepository->setRouteMode(RouteMode::VpnOnlyForwardSites);
        m_currentRouteMode = RouteMode::VpnOnlyForwardSites;
    }
    fillSites();
}

bool IpSplitTunnelingController::addSiteInternal(const QString &hostname, const QStringList &ips)
{
    QVariantMap existing = m_appSettingsRepository->vpnSites(m_currentRouteMode);
    if (existing.contains(hostname) && ips.isEmpty()) {
        return false;
    }

    for (int i = 0; i < m_sites.size(); i++) {
        if (m_sites[i].first == hostname) {
            bool changed = false;
            for (const QString &ip : ips) {
                if (!ip.isEmpty() && !m_sites[i].second.contains(ip)) {
                    m_sites[i].second.append(ip);
                    changed = true;
                }
            }
            if (!changed) {
                return false;
            }
            m_appSettingsRepository->addVpnSite(m_currentRouteMode, hostname, ips);
            return true;
        }
    }
    m_sites.append(qMakePair(hostname, ips));
    m_appSettingsRepository->addVpnSite(m_currentRouteMode, hostname, ips);
    return true;
}

void IpSplitTunnelingController::addSites(const QMap<QString, QStringList> &sites, bool replaceExisting)
{
    if (replaceExisting) {
        m_sites.clear();
    }
    for (auto it = sites.constBegin(); it != sites.constEnd(); ++it) {
        const QString &hostname = it.key();
        const QStringList &ips = it.value();
        bool found = false;
        for (int i = 0; i < m_sites.size(); i++) {
            if (m_sites[i].first == hostname) {
                for (const QString &ip : ips) {
                    if (!ip.isEmpty() && !m_sites[i].second.contains(ip)) {
                        m_sites[i].second.append(ip);
                    }
                }
                found = true;
                break;
            }
        }
        if (!found) {
            m_sites.append(qMakePair(hostname, ips));
        }
    }
    if (replaceExisting) {
        m_appSettingsRepository->removeAllVpnSites(m_currentRouteMode);
    }
    m_appSettingsRepository->addVpnSites(m_currentRouteMode, sites);
}

bool IpSplitTunnelingController::addSite(const QString &hostname)
{
    QString normalizedHostname = normalizeHostname(hostname);
    
    if (!validateHostname(normalizedHostname)) {
        return false;
    }

    if (isSingBoxRoutingEnabled()) {
        // Domain rules reach managed DNS as names, not startup DNS snapshots.
        return addSiteInternal(normalizedHostname, {});
    }
    
    if (NetworkUtilities::ipAddressWithSubnetRegExp().exactMatch(normalizedHostname)) {
        processSite(normalizedHostname, {});
        return true;
    }
    
    if (addSiteInternal(normalizedHostname, {})) {
        QHostInfo::lookupHost(normalizedHostname, this, SLOT(onHostResolved(QHostInfo)));
        return true;
    }
    
    return false;
}

bool IpSplitTunnelingController::removeSite(const QString &hostname)
{
    for (int i = 0; i < m_sites.size(); i++) {
        if (m_sites[i].first == hostname) {
            m_sites.removeAt(i);
            m_appSettingsRepository->removeVpnSite(m_currentRouteMode, hostname);
            return true;
        }
    }
    return false;
}

void IpSplitTunnelingController::removeSites()
{
    m_sites.clear();
    m_appSettingsRepository->removeAllVpnSites(m_currentRouteMode);
}

void IpSplitTunnelingController::setRouteMode(RouteMode routeMode)
{
    m_currentRouteMode = routeMode;
    fillSites();
    m_appSettingsRepository->setRouteMode(routeMode);
}

void IpSplitTunnelingController::toggleSplitTunneling(bool enabled)
{
    m_appSettingsRepository->setSitesSplitTunnelingEnabled(enabled);
}

RouteMode IpSplitTunnelingController::getRouteMode() const
{
    return m_currentRouteMode;
}

bool IpSplitTunnelingController::isSplitTunnelingEnabled() const
{
    return m_appSettingsRepository->isSitesSplitTunnelingEnabled();
}

QVector<QPair<QString, QStringList>> IpSplitTunnelingController::getCurrentSites() const
{
    return m_sites;
}

void IpSplitTunnelingController::fillSites()
{
    QVariantMap sitesMap = m_appSettingsRepository->vpnSites(m_currentRouteMode);
    m_sites.clear();
    for (auto it = sitesMap.begin(); it != sitesMap.end(); ++it) {
        m_sites.append(qMakePair(it.key(), SecureAppSettingsRepository::siteIpList(it.value())));
    }
}

QString IpSplitTunnelingController::normalizeHostname(const QString &hostname) const
{
    QString normalized = hostname;
    normalized.replace("https://", "");
    normalized.replace("http://", "");
    normalized.replace("ftp://", "");

    if (NetworkUtilities::ipAddressWithSubnetRegExp().exactMatch(normalized)) {
        return normalized;
    }

    const QStringList parts = normalized.split("/", Qt::SkipEmptyParts);
    return parts.isEmpty() ? QString() : parts.first();
}

bool IpSplitTunnelingController::validateHostname(const QString &hostname) const
{
    if (hostname.isEmpty()) {
        return false;
    }
    if (hostname.contains('*') && (!isSingBoxRoutingEnabled() || !hostname.startsWith("*.")
            || hostname.mid(2).contains('*') || hostname.size() <= 2)) {
        return false;
    }
    if (!hostname.contains(".") && !NetworkUtilities::ipAddressWithSubnetRegExp().exactMatch(hostname)) {
        return false;
    }
    return true;
}

bool IpSplitTunnelingController::isSingBoxRoutingEnabled() const
{
#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS) || defined(Q_OS_LINUX) || defined(Q_OS_WIN)
    return m_appSettingsRepository->isSingBoxRoutingEnabled();
#else
    return false;
#endif
}

bool IpSplitTunnelingController::setSingBoxRoutingEnabled(bool enabled)
{
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(Q_OS_LINUX) && !defined(Q_OS_WIN)
    if (enabled) return false;
#endif
    if (!enabled) {
        for (auto mode : {RouteMode::VpnOnlyForwardSites, RouteMode::VpnAllExceptSites}) {
            const auto sites = m_appSettingsRepository->vpnSites(mode);
            for (auto it = sites.cbegin(); it != sites.cend(); ++it) {
                if (it.key().contains('*')) return false;
            }
        }
    }
    m_appSettingsRepository->setSingBoxRoutingEnabled(enabled);
    if (enabled) m_appSettingsRepository->setDomainRoutingConfig(m_appSettingsRepository->domainRoutingConfig());
    return true;
}

QJsonObject IpSplitTunnelingController::domainRoutingConfig() const
{
    return m_appSettingsRepository->domainRoutingConfig();
}

bool IpSplitTunnelingController::saveDomainRule(int index, const QString &destination, const QString &action, bool enabled,
                                              const QString &ports, const QString &network)
{
    auto config = domainRoutingConfig();
    auto rules = config.value("rules").toArray();
    if (index < -1 || index >= rules.size()) return false;
    const auto rule = amnezia::routing::destinationRule(destination, action, enabled, ports, network);
    if (rule.isEmpty()) return false;
    if (index == -1) rules.append(rule); else rules[index] = rule;
    config.insert("rules", rules);
    config.insert("version", 2);
    QJsonObject normalized;
    QString error;
    if (!amnezia::routing::normalizeConfig(config, normalized, error)) return false;
    m_appSettingsRepository->setDomainRoutingConfig(normalized);
    return true;
}

void IpSplitTunnelingController::removeDomainRule(int index)
{
    auto config = domainRoutingConfig();
    auto rules = config.value("rules").toArray();
    if (index < 0 || index >= rules.size()) return;
    rules.removeAt(index);
    config.insert("rules", rules);
    m_appSettingsRepository->setDomainRoutingConfig(config);
}

void IpSplitTunnelingController::setDomainDefault(const QString &action)
{
    if (!amnezia::routing::validAction(action)) return;
    auto config = domainRoutingConfig();
    config.insert("default", action);
    config.insert("version", 2);
    QJsonObject normalized;
    QString error;
    if (amnezia::routing::normalizeConfig(config, normalized, error)) m_appSettingsRepository->setDomainRoutingConfig(normalized);
}

bool IpSplitTunnelingController::importDomainRouting(const QByteArray &data, QString &error)
{
    if (data.size() > 1024 * 1024) { error = tr("Routing file exceeds 1 MiB"); return false; }
    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(data, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        error = tr("Expected a routing JSON object: %1").arg(parseError.errorString());
        return false;
    }
    QJsonObject normalized;
    if (!amnezia::routing::normalizeConfig(document.object(), normalized, error)) return false;
    m_appSettingsRepository->setDomainRoutingConfig(normalized);
    return true;
}

QByteArray IpSplitTunnelingController::exportDomainRouting(QString &error) const
{
    QJsonObject normalized;
    if (!amnezia::routing::normalizeConfig(domainRoutingConfig(), normalized, error)) return {};
    const auto data = QJsonDocument(normalized).toJson(QJsonDocument::Indented);
    if (data.size() > 1024 * 1024) { error = tr("Routing file exceeds 1 MiB"); return {}; }
    return data;
}

QVariantMap IpSplitTunnelingController::inspectDomainRule(const QString &destination, const QString &ip,
                                                        const QString &port, const QString &network) const
{
    return amnezia::routing::inspectRule(domainRoutingConfig(), destination, ip, port, network);
}


void IpSplitTunnelingController::onHostResolved(const QHostInfo &hostInfo)
{
    const QList<QHostAddress> &addresses = hostInfo.addresses();
    QString hostname = hostInfo.hostName();

    QStringList allIpv4;
    for (const QHostAddress &addr : addresses) {
        if (addr.protocol() == QAbstractSocket::NetworkLayerProtocol::IPv4Protocol) {
            allIpv4.append(addr.toString());
        }
    }
    allIpv4.removeDuplicates();
    qDebug() << "[SplitTunneling] Host resolved:" << hostname
             << "-> adding all IPv4 addresses to list:" << allIpv4;

    if (!allIpv4.isEmpty()) {
        processSiteAfterResolve(hostname, allIpv4);
    }
}

void IpSplitTunnelingController::processSiteAfterResolve(const QString &hostname, const QStringList &ips)
{
    for (int i = 0; i < m_sites.size(); i++) {
        if (m_sites[i].first == hostname) {
            for (const QString &ip : ips) {
                if (!ip.isEmpty() && !m_sites[i].second.contains(ip)) {
                    m_sites[i].second.append(ip);
                }
            }
            break;
        }
    }
    m_appSettingsRepository->addVpnSite(m_currentRouteMode, hostname, ips);
}

void IpSplitTunnelingController::processSite(const QString &hostname, const QStringList &ips)
{
    addSiteInternal(hostname, ips);
}

bool IpSplitTunnelingController::importSitesFromJson(const QByteArray& jsonData, bool replaceExisting, QString &errorMessage)
{
    QJsonParseError parseError;
    QJsonDocument jsonDocument = QJsonDocument::fromJson(jsonData, &parseError);
    
    if (parseError.error != QJsonParseError::NoError) {
        errorMessage = tr("Failed to parse JSON data: %1").arg(parseError.errorString());
        return false;
    }
    
    if (!jsonDocument.isArray()) {
        errorMessage = tr("The JSON data is not an array");
        return false;
    }
    
    QJsonArray jsonArray = jsonDocument.array();
    QMap<QString, QStringList> sites;
    
    for (auto jsonValue : jsonArray) {
        QJsonObject jsonObject = jsonValue.toObject();
        QString hostname = jsonObject.value("hostname").toString("");

        QStringList ips;
        if (jsonObject.value("ips").isArray()) {
            const QJsonArray ipsArray = jsonObject.value("ips").toArray();
            for (const auto &ipValue : ipsArray) {
                ips.append(ipValue.toString());
            }
        }
        const QString singleIp = jsonObject.value("ip").toString("");
        if (!singleIp.isEmpty()) {
            ips.append(singleIp);
        }
        ips.removeAll(QString());
        ips.removeDuplicates();
        
        QString normalizedHostname = normalizeHostname(hostname);
        
        if (!validateHostname(normalizedHostname)) {
            qDebug() << normalizedHostname << " not look like ip adress or domain name";
            continue;
        }
        
        sites.insert(normalizedHostname, ips);
    }
    
    addSites(sites, replaceExisting);
    
    return true;
}

QByteArray IpSplitTunnelingController::exportSitesToJson() const
{
    QVector<QPair<QString, QStringList>> sites = getCurrentSites();
    QJsonArray jsonArray;
    
    for (const auto &site : sites) {
        QJsonObject jsonObject;
        jsonObject["hostname"] = site.first;

        QJsonArray ipsArray;
        for (const QString &ip : site.second) {
            ipsArray.append(ip);
        }
        jsonObject["ips"] = ipsArray;
        // Keep the legacy "ip" field (first address) for backward compatibility.
        jsonObject["ip"] = site.second.isEmpty() ? QString() : site.second.first();

        jsonArray.append(jsonObject);
    }
    
    QJsonDocument jsonDocument(jsonArray);
    return jsonDocument.toJson();
}

