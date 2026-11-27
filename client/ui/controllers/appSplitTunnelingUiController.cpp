#include "appSplitTunnelingUiController.h"

#include <QFileInfo>
#include <QTimer>
#ifdef Q_OS_ANDROID
#include <QJniObject>
#endif

#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"

AppSplitTunnelingUiController::AppSplitTunnelingUiController(AppSplitTunnelingController* appSplitTunnelingController,
                                                              AppSplitTunnelingModel* appSplitTunnelingModel,
                                                              QObject *parent)
    : QObject(parent),
      m_appSplitTunnelingController(appSplitTunnelingController),
      m_appSplitTunnelingModel(appSplitTunnelingModel)
{
    m_appSplitTunnelingModel->updateModel(m_appSplitTunnelingController->getApps());
}

void AppSplitTunnelingUiController::addApp(const QString &appPath)
{
    amnezia::InstalledAppInfo appInfo { "", "", appPath };
    if (!appPath.isEmpty()) {
        QFileInfo fileInfo(appPath);
        appInfo.appName = fileInfo.fileName();
    }

    if (m_appSplitTunnelingController->addApp(appInfo)) {
        emit finished(tr("Application added: %1").arg(appInfo.appName));
    } else {
        emit errorOccurred(tr("The application has already been added"));
    }
}

void AppSplitTunnelingUiController::addApps(QVector<QPair<QString, QString>> apps)
{
    for (const auto &app : apps) {
        amnezia::InstalledAppInfo appInfo { app.first, app.second, "" };
        m_appSplitTunnelingController->addApp(appInfo);
    }
    emit finished(tr("The selected applications have been added"));
}

void AppSplitTunnelingUiController::removeApp(const int index)
{
    auto modelIndex = m_appSplitTunnelingModel->index(index);
    auto appPath = m_appSplitTunnelingModel->data(modelIndex, AppSplitTunnelingModel::Roles::AppPathRole).toString();
    m_appSplitTunnelingController->removeApp(index);

    QFileInfo fileInfo(appPath);
    emit finished(tr("Application removed: %1").arg(fileInfo.fileName()));
}

void AppSplitTunnelingUiController::toggleSplitTunneling(bool enabled)
{
    m_appSplitTunnelingController->toggleSplitTunneling(enabled);
}

void AppSplitTunnelingUiController::setRouteMode(int routeMode)
{
    m_appSplitTunnelingController->setRouteMode(static_cast<amnezia::AppsRouteMode>(routeMode));
}

int AppSplitTunnelingUiController::getRouteMode() const
{
    return static_cast<int>(m_appSplitTunnelingController->getRouteMode());
}

bool AppSplitTunnelingUiController::isSplitTunnelingEnabled() const
{
    return m_appSplitTunnelingController->isSplitTunnelingEnabled();
}

void AppSplitTunnelingUiController::updateModel()
{
    m_appSplitTunnelingModel->updateModel(m_appSplitTunnelingController->getApps());
    emit routeModeChanged();
    emit isSplitTunnelingEnabledChanged();
    ++m_applicationPolicyRevision;
    emit applicationPolicyChanged();
}

bool AppSplitTunnelingUiController::perAppSiteRulesSupported() const
{
#ifdef Q_OS_ANDROID
    return QJniObject::getStaticField<jint>("android/os/Build$VERSION", "SDK_INT") >= 29;
#else
    return false;
#endif
}

bool AppSplitTunnelingUiController::appliesSiteRules(int index) const
{
    return m_appSplitTunnelingController->appliesSiteRules(index);
}

void AppSplitTunnelingUiController::configureLivePolicy(std::function<bool()> connected, std::function<void(qint64, const QJsonObject &)> dispatch)
{
    m_connected = std::move(connected);
    m_dispatchPolicy = std::move(dispatch);
}

void AppSplitTunnelingUiController::setAppliesSiteRules(int index, bool enabled)
{
    if (!perAppSiteRulesSupported() || m_policyPending || m_policyUnconfirmed) return;
    const auto policy = m_appSplitTunnelingController->siteRulesPolicy(index, enabled);
    if (policy.isEmpty()) return;
    if (m_connected && m_connected()) {
        if (!m_dispatchPolicy) { emit errorOccurred(tr("Live application routing is unavailable")); return; }
        const qint64 request = ++m_nextPolicyRequest;
        m_policyRequest = request;
        m_pendingPolicy = policy;
        m_policyPending = true;
        ++m_applicationPolicyRevision;
        emit applicationPolicyChanged();
        m_dispatchPolicy(request, policy);
        QTimer::singleShot(15000, this, [this, request] {
            if (m_policyRequest != request || !m_policyPending) return;
            m_policyPending = false;
            m_policyUnconfirmed = true;
            ++m_applicationPolicyRevision;
            emit applicationPolicyChanged();
            emit errorOccurred(tr("Could not confirm the active application rules. Reconnect before changing them again."));
        });
        return;
    }
    if (m_appSplitTunnelingController->commitSiteRulesPolicy(policy)) {
        ++m_applicationPolicyRevision;
        emit applicationPolicyChanged();
    }
}

void AppSplitTunnelingUiController::completeApplicationPolicy(qint64 requestId, bool success, const QString &reason)
{
    if (requestId != m_policyRequest || m_pendingPolicy.isEmpty()) return;
    if (success) success = m_appSplitTunnelingController->commitSiteRulesPolicy(m_pendingPolicy);
    m_policyRequest = 0;
    m_pendingPolicy = {};
    m_policyPending = m_policyUnconfirmed = false;
    ++m_applicationPolicyRevision;
    emit applicationPolicyChanged();
    if (!success) emit errorOccurred(reason.isEmpty() ? tr("Application routing update failed") : reason);
}

void AppSplitTunnelingUiController::connectionClosed()
{
    m_policyRequest = 0;
    m_pendingPolicy = {};
    m_policyPending = m_policyUnconfirmed = false;
    ++m_applicationPolicyRevision;
    emit applicationPolicyChanged();
}
