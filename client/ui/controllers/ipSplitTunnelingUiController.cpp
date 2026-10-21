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
            : tr("Remove wildcard destinations before disabling AWG domain routing."));
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

bool IpSplitTunnelingUiController::saveDomainRule(int index, const QString &destination, const QString &action, bool enabled)
{
    if (!m_ipSplitTunnelingController->saveDomainRule(index, destination, action, enabled)) {
        emit errorOccurred(tr("Invalid or duplicate rule. Use a domain, *.suffix, IP address or CIDR."));
        return false;
    }
    emit domainRoutingChanged();
    return true;
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
    emit isSplitTunnelingEnabledChanged();
}

void IpSplitTunnelingUiController::setRouteMode(int routeMode)
{
    m_ipSplitTunnelingController->setRouteMode(static_cast<amnezia::RouteMode>(routeMode));
    emit routeModeChanged();
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
    emit domainRoutingChanged();
}
