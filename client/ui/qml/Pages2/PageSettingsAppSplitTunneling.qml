import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

import QtCore

import SortFilterProxyModel 0.2

import PageEnum 1.0
import ContainerProps 1.0
import Style 1.0

import "./"
import "../Controls2"
import "../Controls2/TextTypes"
import "../Config"
import "../Components"

PageType {
    id: root

    property bool pageEnabled: !ConnectionController.isConnected && !ConnectionController.isConnectionInProgress

    Component.onCompleted: {
        if (ConnectionController.isConnected) {
            PageController.showNotificationMessage(qsTr("Application selection cannot be changed during an active connection"))
        }
    }

    QtObject {
        id: routeMode
        property int allApps: 0
        property int onlyForwardApps: 1
        property int allExceptApps: 2
    }

    property list<QtObject> routeModesModel: [
        onlyForwardApps,
        allExceptApps
    ]

    QtObject {
        id: onlyForwardApps

        readonly property string segmentName: qsTr("Via VPN")
        readonly property string name: qsTr("Only the apps from the list should have access via VPN")
        readonly property int type: routeMode.onlyForwardApps
    }

    QtObject {
        id: allExceptApps

        readonly property string segmentName: qsTr("Directly")
        readonly property string name: qsTr("Apps from the list should not have access via VPN")
        readonly property int type: routeMode.allExceptApps
    }

    function getRouteModesModelIndex() {
        return AppSplitTunnelingController.routeMode === routeMode.allExceptApps ? 1 : 0
    }

    ListViewType {
        id: listView

        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: addAppPanel.top

        model: SortFilterProxyModel {
            id: proxyAppSplitTunnelingModel
            sourceModel: AppSplitTunnelingModel
            filters: RegExpFilter {
                roleName: "appPath"
                pattern: ".*" + searchField.textField.text + ".*"
                caseSensitivity: Qt.CaseInsensitive
            }
            sorters: [
                RoleSorter { roleName: "appPath"; sortOrder: Qt.AscendingOrder }
            ]
        }

        header: ColumnLayout {
            width: listView.width

            spacing: 0

            onHeightChanged: {
                if (!listView.moving) {
                    Qt.callLater(listView.positionViewAtBeginning)
                }
            }

            NavigationBarType {
                id: navigationBar

                Layout.fillWidth: true

                title: qsTr("App split tunneling")

                header.showSwitcher: true
                header.switcher.checked: AppSplitTunnelingController.isSplitTunnelingEnabled
                header.switcher.enabled: root.pageEnabled

                Connections {
                    target: navigationBar.header

                    function onSwitcherToggled(checked) {
                        AppSplitTunnelingController.toggleSplitTunneling(checked)
                    }
                }
            }

            SegmentedControlType {
                id: modeSelector

                Layout.fillWidth: true
                Layout.topMargin: 16
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                enabled: root.pageEnabled && (Qt.platform.os === "android"
                    || ((Qt.platform.os === "windows" || Qt.platform.os === "linux")
                        && IpSplitTunnelingController.singBoxRoutingEnabled))

                model: [onlyForwardApps.segmentName, allExceptApps.segmentName]
                currentIndex: root.getRouteModesModelIndex()

                onActivated: function(index) {
                    if (AppSplitTunnelingController.routeMode !== root.routeModesModel[index].type) {
                        AppSplitTunnelingController.routeMode = root.routeModesModel[index].type
                    }
                }

                Connections {
                    target: AppSplitTunnelingController

                    function onRouteModeChanged() {
                        modeSelector.currentIndex = root.getRouteModesModelIndex()
                    }
                }
            }

            BodyTextType {
                Layout.fillWidth: true
                Layout.topMargin: 8
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 24

                text: root.routeModesModel[modeSelector.currentIndex].name
                color: AmneziaStyle.color.textSecondary
            }

            NotificationType {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 24

                text: qsTr("Only \"Apps from the list should not have access via VPN\" mode is available on Windows")

                visible: Qt.platform.os === "windows" && root.pageEnabled
                    && !IpSplitTunnelingController.singBoxRoutingEnabled
            }
        }

        delegate: Item {
            width: listView.width
            implicitHeight: appItem.implicitHeight + (siteRulesSwitch.visible ? siteRulesSwitch.implicitHeight + 24 : 0)

            ListItemType {
                id: appItem
                enabled: root.pageEnabled

                anchors.top: parent.top
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.leftMargin: 16
                anchors.rightMargin: 16

                text: appPath
                trailingIconSource: "qrc:/images/controls/trash.svg"

                onClicked: {
                    var headerText = qsTr("Remove ") + appPath + "?"
                    var yesButtonText = qsTr("Continue")
                    var noButtonText = qsTr("Cancel")

                    var yesButtonFunction = function() {
                        AppSplitTunnelingController.removeApp(proxyAppSplitTunnelingModel.mapToSource(index))
                    }
                    var noButtonFunction = function() {
                    }

                    showQuestionDrawer(headerText, "", yesButtonText, noButtonText, yesButtonFunction, noButtonFunction)
                }
            }

            SwitchType {
                id: siteRulesSwitch
                anchors.top: appItem.bottom
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.leftMargin: 32
                anchors.rightMargin: 32
                visible: AppSplitTunnelingController.perAppSiteRulesSupported
                         && ServersUiController.defaultServerSupportsPerAppSiteRules
                         && AppSplitTunnelingController.routeMode === routeMode.onlyForwardApps
                enabled: !ConnectionController.isConnectionInProgress
                         && !AppSplitTunnelingController.applicationPolicyPending
                         && !AppSplitTunnelingController.applicationPolicyUnconfirmed
                text: qsTr("Apply site rules")
                descriptionText: AppSplitTunnelingController.applicationPolicyPending
                                 ? qsTr("Updating application rules…")
                                 : AppSplitTunnelingController.applicationPolicyUnconfirmed
                                   ? qsTr("The active rules could not be confirmed. Reconnect before changing them again.")
                                   : qsTr("Off: all traffic and DNS from this app use VPN. On: site routing and DNS rules apply. Changes affect new connections; existing connections keep their current route.")
                checked: {
                    var revision = AppSplitTunnelingController.applicationPolicyRevision
                    return AppSplitTunnelingController.appliesSiteRules(proxyAppSplitTunnelingModel.mapToSource(index))
                }
                onToggled: AppSplitTunnelingController.setAppliesSiteRules(proxyAppSplitTunnelingModel.mapToSource(index), checked)
            }
        }
    }

    Rectangle {
        id: addAppPanel

        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.bottomMargin: searchField.textField.activeFocus ? 0 : PageController.imeHeight

        implicitHeight: searchField.implicitHeight + 24 + PageController.safeAreaBottomMargin

        color: AmneziaStyle.color.bgBase

        TextFieldType {
            id: searchField

            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.topMargin: 16
            anchors.leftMargin: 16
            anchors.rightMargin: 16

            enabled: root.pageEnabled

            textField.placeholderText: qsTr("application name")
            buttonImageSource: "qrc:/images/controls/plus.svg"
            buttonJoined: true

            rightButtonClickedOnEnter: true

            clickedFunc: function() {
                searchField.focus = false
                PageController.showBusyIndicator(true)

                if (Qt.platform.os === "windows" || Qt.platform.os === "linux") {
                    var fileName = SystemController.getFileName(qsTr("Open executable file"),
                                                                qsTr("Executable files (*.*)"))
                    if (fileName !== "") {
                        AppSplitTunnelingController.addApp(fileName)
                    }
                } else if (Qt.platform.os === "android"){
                    installedAppDrawer.open()
                }

                PageController.showBusyIndicator(false)
            }
        }
    }

    InstalledAppsDrawer {
        id: installedAppDrawer
    }
}
