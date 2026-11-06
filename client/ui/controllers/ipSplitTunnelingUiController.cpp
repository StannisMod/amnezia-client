#include "ipSplitTunnelingUiController.h"

#include <QDebug>

#include "systemController.h"
#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"

IpSplitTunnelingUiController::IpSplitTunnelingUiController(IpSplitTunnelingController* ipSplitTunnelingController,
                                                          IpSplitTunnelingModel* ipSplitTunnelingModel, QObject *parent)
    : QObject(parent),
      m_ipSplitTunnelingController(ipSplitTunnelingController),
      m_ipSplitTunnelingModel(ipSplitTunnelingModel)
{
    m_ipSplitTunnelingModel->updateModel(m_ipSplitTunnelingController->getCurrentSites());
}

void IpSplitTunnelingUiController::addSite(QString hostname)
{
    if (m_ipSplitTunnelingController->addSite(hostname)) {
        emit finished(tr("New site added: %1").arg(hostname));
    } else {
        emit errorOccurred(tr("Invalid or duplicate destination. Wildcards require experimental AWG domain routing."));
    }
}

bool IpSplitTunnelingUiController::isSingBoxRoutingAvailable() const
{
#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS) || defined(Q_OS_LINUX) || defined(Q_OS_WIN)
    return true;
#else
    return false;
#endif
}

bool IpSplitTunnelingUiController::isSingBoxRoutingEnabled() const
{
    return m_ipSplitTunnelingController->isSingBoxRoutingEnabled();
}

void IpSplitTunnelingUiController::setSingBoxRoutingEnabled(bool enabled)
{
    if (!m_ipSplitTunnelingController->setSingBoxRoutingEnabled(enabled)) {
        emit errorOccurred(enabled
            ? tr("AWG domain routing is unavailable on this platform.")
            : tr("Remove wildcard destinations before disabling domain routing."));
    }
    emit singBoxRoutingEnabledChanged();
    emit domainRoutingChanged();
}

QVariantList IpSplitTunnelingUiController::domainRules() const
{
    return m_ipSplitTunnelingController->domainRoutingConfig().value("rules").toArray().toVariantList();
}

QString IpSplitTunnelingUiController::domainDefault() const
{
    return m_ipSplitTunnelingController->domainRoutingConfig().value("default").toString();
}

bool IpSplitTunnelingUiController::saveDomainRule(int index, const QString &destination, const QString &action, bool enabled,
                                                const QString &ports, const QString &network)
{
    if (!m_ipSplitTunnelingController->saveDomainRule(index, destination, action, enabled, ports, network)) {
        emit errorOccurred(tr("Invalid or duplicate rule. Use a domain, *.suffix, IP or CIDR; ports must be 1–65535 or ranges such as 8000-8100."));
        return false;
    }
    emit domainRoutingChanged();
    return true;
}

void IpSplitTunnelingUiController::importDomainRouting(const QString &fileName)
{
    QByteArray data;
    if (!SystemController::readFile(fileName, data)) { emit errorOccurred(tr("Can't open file: %1").arg(fileName)); return; }
    QString error;
    if (!m_ipSplitTunnelingController->importDomainRouting(data, error)) { emit errorOccurred(error); return; }
    emit domainRoutingChanged();
    emit finished(tr("Routing configuration imported. Reconnect to apply."));
}

void IpSplitTunnelingUiController::exportDomainRouting(const QString &fileName)
{
    QString error;
    const auto data = m_ipSplitTunnelingController->exportDomainRouting(error);
    if (data.isEmpty()) { emit errorOccurred(error); return; }
    bool cancelled = false;
    if (!SystemController::saveFile(fileName, data, QStringLiteral("application/json"), &cancelled)) {
        if (!cancelled) emit errorOccurred(tr("Routing export failed"));
        return;
    }
    emit finished(tr("Routing configuration exported"));
}

QVariantMap IpSplitTunnelingUiController::inspectDomainRule(const QString &destination, const QString &ip,
                                                          const QString &port, const QString &network) const
{
    return m_ipSplitTunnelingController->inspectDomainRule(destination, ip, port, network);
}

void IpSplitTunnelingUiController::removeDomainRule(int index)
{
    m_ipSplitTunnelingController->removeDomainRule(index);
    emit domainRoutingChanged();
}

void IpSplitTunnelingUiController::setDomainDefault(const QString &action)
{
    m_ipSplitTunnelingController->setDomainDefault(action);
    emit domainRoutingChanged();
}

void IpSplitTunnelingUiController::removeSite(int index)
{
    auto modelIndex = m_ipSplitTunnelingModel->index(index);
    auto hostname = m_ipSplitTunnelingModel->data(modelIndex, IpSplitTunnelingModel::Roles::UrlRole).toString();
    if (m_ipSplitTunnelingController->removeSite(hostname)) {
        emit finished(tr("Site removed: %1").arg(hostname));
    }
}

void IpSplitTunnelingUiController::removeSites()
{
    m_ipSplitTunnelingController->removeSites();
    emit finished(tr("Site list cleared!"));
}

void IpSplitTunnelingUiController::importSites(const QString &fileName, bool replaceExisting)
{
    QByteArray jsonData;
    if (!SystemController::readFile(fileName, jsonData)) {
        emit errorOccurred(tr("Can't open file: %1").arg(fileName));
        return;
    }

    QString errorMessage;
    if (m_ipSplitTunnelingController->importSitesFromJson(jsonData, replaceExisting, errorMessage)) {
        emit finished(tr("Import completed"));
    } else {
        emit errorOccurred(errorMessage);
    }
}

void IpSplitTunnelingUiController::exportSites(const QString &fileName)
{
    QByteArray jsonData = m_ipSplitTunnelingController->exportSitesToJson();
    if (!SystemController::saveFile(fileName, jsonData)) {
        qInfo() << "IpSplitTunnelingUiController::exportSites: save or share was cancelled or failed";
        return;
    }
    emit finished(tr("Export completed"));
}

void IpSplitTunnelingUiController::toggleSplitTunneling(bool enabled)
{
    m_ipSplitTunnelingController->toggleSplitTunneling(enabled);
}

void IpSplitTunnelingUiController::setRouteMode(int routeMode)
{
    m_ipSplitTunnelingController->setRouteMode(static_cast<amnezia::RouteMode>(routeMode));
}

int IpSplitTunnelingUiController::getRouteMode() const
{
    return static_cast<int>(m_ipSplitTunnelingController->getRouteMode());
}

bool IpSplitTunnelingUiController::isSplitTunnelingEnabled() const
{
    return m_ipSplitTunnelingController->isSplitTunnelingEnabled();
}

void IpSplitTunnelingUiController::updateModel()
{
    m_ipSplitTunnelingModel->updateModel(m_ipSplitTunnelingController->getCurrentSites());
    emit routeModeChanged();
    emit isSplitTunnelingEnabledChanged();
    emit singBoxRoutingEnabledChanged();
    emit domainRoutingChanged();
}
