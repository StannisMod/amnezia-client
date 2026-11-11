#ifndef APPSPLITTUNNELINGUICONTROLLER_H
#define APPSPLITTUNNELINGUICONTROLLER_H

#include <QObject>
#include <QVector>

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
    bool perAppSiteRulesSupported() const;
    int applicationPolicyRevision() const { return m_applicationPolicyRevision; }
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
};

#endif // APPSPLITTUNNELINGUICONTROLLER_H
