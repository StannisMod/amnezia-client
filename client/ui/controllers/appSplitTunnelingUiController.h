#ifndef APPSPLITTUNNELINGUICONTROLLER_H
#define APPSPLITTUNNELINGUICONTROLLER_H

#include <QObject>
#include <QVector>
#include <functional>

#include "core/controllers/appSplitTunnelingController.h"
#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "ui/models/appSplitTunnelingModel.h"

class AppSplitTunnelingUiController : public QObject
{
    Q_OBJECT

    Q_PROPERTY(int routeMode READ getRouteMode WRITE setRouteMode NOTIFY routeModeChanged)
    Q_PROPERTY(bool isSplitTunnelingEnabled READ isSplitTunnelingEnabled NOTIFY isSplitTunnelingEnabledChanged)
    Q_PROPERTY(bool perAppSiteRulesSupported READ perAppSiteRulesSupported CONSTANT)
    Q_PROPERTY(bool applicationPolicyPending READ applicationPolicyPending NOTIFY applicationPolicyChanged)
    Q_PROPERTY(bool applicationPolicyUnconfirmed READ applicationPolicyUnconfirmed NOTIFY applicationPolicyChanged)
    Q_PROPERTY(int applicationPolicyRevision READ applicationPolicyRevision NOTIFY applicationPolicyChanged)

public:
    explicit AppSplitTunnelingUiController(AppSplitTunnelingController* appSplitTunnelingController,
                                          AppSplitTunnelingModel* appSplitTunnelingModel,
                                          QObject *parent = nullptr);

public slots:
    void addApp(const QString &appPath);
    void addApps(QVector<QPair<QString, QString>> apps);
    void removeApp(const int index);
    void toggleSplitTunneling(bool enabled);
    void setRouteMode(int routeMode);

    int getRouteMode() const;
    bool isSplitTunnelingEnabled() const;
    virtual bool perAppSiteRulesSupported() const;
public:
    void configureLivePolicy(std::function<bool()> connected, std::function<void(qint64, const QJsonObject &)> dispatch);
    bool applicationPolicyPending() const { return m_policyPending; }
    bool applicationPolicyUnconfirmed() const { return m_policyUnconfirmed; }
    void completeApplicationPolicy(qint64 requestId, bool success, const QString &reason);
    void connectionClosed();
    int applicationPolicyRevision() const { return m_applicationPolicyRevision; }
public slots:
    bool appliesSiteRules(int index) const;
    void setAppliesSiteRules(int index, bool enabled);

    void updateModel();

signals:
    void routeModeChanged();
    void isSplitTunnelingEnabledChanged();
    void errorOccurred(const QString &errorMessage);
    void finished(const QString &message);
    void applicationPolicyChanged();

private:
    AppSplitTunnelingController* m_appSplitTunnelingController;
    AppSplitTunnelingModel* m_appSplitTunnelingModel;
    int m_applicationPolicyRevision = 0;
    std::function<bool()> m_connected;
    std::function<void(qint64, const QJsonObject &)> m_dispatchPolicy;
    qint64 m_nextPolicyRequest = 0;
    qint64 m_policyRequest = 0;
    QJsonObject m_pendingPolicy;
    bool m_policyPending = false;
    bool m_policyUnconfirmed = false;
};

#endif // APPSPLITTUNNELINGUICONTROLLER_H
