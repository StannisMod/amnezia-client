import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import PageEnum 1.0
import Style 1.0

import "./"
import "../Controls2"
import "../Config"

PageType {
    id: root

    property bool isAppSplitTinnelingEnabled: Qt.platform.os === "windows" || Qt.platform.os === "android"
        || (Qt.platform.os === "linux" && IpSplitTunnelingController.singBoxRoutingEnabled)

    FlickableType {
        id: flickable

        anchors.top: parent.top

        contentHeight: content.implicitHeight

        ColumnLayout {
            id: content

            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right

            spacing: 0

            NavigationBarType {
                Layout.fillWidth: true

                title: qsTr("Connection")
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.topMargin: 16
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 16 + PageController.safeAreaBottomMargin

                spacing: 0

                ListItemType {
                    Layout.fillWidth: true
                    text: qsTr("Tunnel IPv6")
                    subtitle: qsTr("Enabled by default. Changes apply on the next connection. When disabled, IPv6 is blocked instead of bypassing the VPN.")
                    onClicked: {
                        ipv6Switch.toggle()
                        ipv6Switch.toggled()
                    }
                    SwitchType {
                        id: ipv6Switch
                        focusPolicy: Qt.NoFocus
                        checked: SettingsController.ipv6Enabled
                        onToggled: SettingsController.ipv6Enabled = checked
                    }
                }

                ListItemType {
                    id: amneziaDnsRow

                    Layout.fillWidth: true

                    text: qsTr("Use AmneziaDNS")
                    subtitle: qsTr("If AmneziaDNS is installed on the server")

                    onClicked: {
                        amneziaDnsSwitch.toggle()
                        amneziaDnsSwitch.toggled()
                    }

                    SwitchType {
                        id: amneziaDnsSwitch

                        focusPolicy: Qt.NoFocus

                        checked: SettingsController.isAmneziaDnsEnabled()
                        onToggled: function() {
                            if (checked !== SettingsController.isAmneziaDnsEnabled()) {
                                SettingsController.toggleAmneziaDns(checked)
                            }
                        }
                    }
                }

                ListItemType {
                    id: dnsServersButton

                    Layout.fillWidth: true

                    text: qsTr("DNS servers")
                    subtitle: qsTr("When AmneziaDNS is not used or installed")
                    trailingIconSource: "qrc:/images/controls/chevron-right.svg"

                    onClicked: {
                        PageController.goToPage(PageEnum.PageSettingsDns)
                    }
                }

                ListItemType {
                    id: splitTunnelingButton

                    Layout.fillWidth: true

                    text: qsTr("Site-based split tunneling")
                    subtitle: qsTr("Allows you to select which sites you want to access through the VPN")
                    trailingIconSource: "qrc:/images/controls/chevron-right.svg"

                    onClicked: {
                        PageController.goToPage(PageEnum.PageSettingsSplitTunneling)
                    }
                }

                ListItemType {
                    id: splitTunnelingButton2

                    Layout.fillWidth: true

                    visible: root.isAppSplitTinnelingEnabled

                    text: qsTr("App-based split tunneling")
                    subtitle: qsTr("Allows you to use the VPN only for certain Apps")
                    trailingIconSource: "qrc:/images/controls/chevron-right.svg"

                    onClicked: {
                        PageController.goToPage(PageEnum.PageSettingsAppSplitTunneling)
                    }
                }

                ListItemType {
                    id: killSwitchButton

                    Layout.fillWidth: true

                    visible: !GC.isMobile()

                    text: qsTr("KillSwitch")
                    subtitle: qsTr("Blocks network connections without VPN")
                    trailingIconSource: "qrc:/images/controls/chevron-right.svg"

                    onClicked: {
                        PageController.goToPage(PageEnum.PageSettingsKillSwitch)
                    }
                }
            }
        }
    }
}
