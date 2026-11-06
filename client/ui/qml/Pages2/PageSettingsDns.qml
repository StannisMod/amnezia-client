import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import PageEnum 1.0
import Style 1.0

import "./"
import "../Controls2"
import "../Controls2/TextTypes"
import "../Config"
import "../Components"

PageType {
    id: root

    property bool isServerFromApi: ServersUiController.isDefaultServerFromApi
    Component.onCompleted: {
        if (root.isServerFromApi) {
            PageController.showNotificationMessage(qsTr("Default server does not support custom DNS"))
        }
    }

    FlickableType {
        id: flickable

        anchors.top: parent.top
        anchors.bottom: buttons.top

        contentHeight: content.implicitHeight

        ColumnLayout {
            id: content

            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right

            spacing: 0

            NavigationBarType {
                Layout.fillWidth: true

                title: qsTr("DNS servers")
                description: qsTr("Reconnect to apply DNS changes.")
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.topMargin: 16
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 16

                spacing: 12

                enabled: !ConnectionController.isConnected

                BodyTextType {
                    Layout.fillWidth: true
                    visible: !root.isServerFromApi && IpSplitTunnelingController.singBoxRoutingEnabled
                    text: qsTr("DNS follows site routing automatically. Direct sites use your network DNS; VPN sites use the DNS selected by Amnezia settings.")
                    wrapMode: Text.WordWrap
                }
                TextFieldType {
                    id: primaryDns
                    enabled: !root.isServerFromApi

                    Layout.fillWidth: true

                    headerText: qsTr("Primary DNS")

                    textField.text: SettingsController.primaryDns
                    textField.validator: RegularExpressionValidator {
                        regularExpression: InstallController.ipAddressRegExp()
                    }
                }

                TextFieldType {
                    id: secondaryDns
                    enabled: !root.isServerFromApi

                    Layout.fillWidth: true

                    headerText: qsTr("Secondary DNS")

                    textField.text: SettingsController.secondaryDns
                    textField.validator: RegularExpressionValidator {
                        regularExpression: InstallController.ipAddressRegExp()
                    }
                }
            }
        }
    }

    ColumnLayout {
        id: buttons

        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.leftMargin: 16
        anchors.rightMargin: 16
        anchors.bottomMargin: 8 + PageController.safeAreaBottomMargin

        spacing: 12

        enabled: !ConnectionController.isConnected

        ButtonType {
            id: restoreDefaultButton
            enabled: !root.isServerFromApi

            Layout.fillWidth: true

            variant: ButtonType.Secondary
            text: qsTr("Restore default")

            onClicked: {
                var headerText = qsTr("Restore default DNS settings?")
                var yesButtonText = qsTr("Continue")
                var noButtonText = qsTr("Cancel")

                var yesButtonFunction = function() {
                    if (!root.isServerFromApi) {
                        SettingsController.primaryDns = "1.1.1.1"
                        primaryDns.textField.text = SettingsController.primaryDns
                        SettingsController.secondaryDns = "1.0.0.1"
                        secondaryDns.textField.text = SettingsController.secondaryDns
                    }
                    PageController.showNotificationMessage(qsTr("Settings have been reset"))
                }
                var noButtonFunction = function() {
                }

                showQuestionDrawer(headerText, "", yesButtonText, noButtonText, yesButtonFunction, noButtonFunction)
            }
        }

        ButtonType {
            id: saveButton
            enabled: !root.isServerFromApi

            Layout.fillWidth: true

            text: qsTr("Save")

            onClicked: {
                if (ConnectionController.isConnected) {
                    PageController.showNotificationMessage(qsTr("Disconnect before changing DNS settings"))
                    return
                }
                if (!root.isServerFromApi && primaryDns.textField.text === "") {
                    primaryDns.errorText = qsTr("Primary DNS cannot be empty")
                    return
                }
                primaryDns.errorText = ""
                secondaryDns.errorText = ""

                if (!root.isServerFromApi && primaryDns.textField.text !== SettingsController.primaryDns) {
                    SettingsController.primaryDns = primaryDns.textField.text
                }
                if (!root.isServerFromApi && secondaryDns.textField.text !== SettingsController.secondaryDns) {
                    SettingsController.secondaryDns = secondaryDns.textField.text
                }
                PageController.showNotificationMessage(qsTr("Settings saved"))
            }
        }
    }
}
