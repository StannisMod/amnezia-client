import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import Style 1.0

import "../Controls2"
import "../Controls2/TextTypes"

import "../Config"

SheetType {
    property string serverNameText

    id: root
    objectName: "serverNameEditDrawer"

    Connections {
        target: root
        function onAboutToShow() {
            vpnHost.textField.text = ServersUiController.vpnHostName(ServersUiController.processedServerId)
        }
    }

    expandedHeight: content.implicitHeight + 16 + 8 + PageController.safeAreaBottomMargin + PageController.imeHeight

    ColumnLayout {
        id: content

        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.topMargin: 16
        anchors.leftMargin: 16
        anchors.rightMargin: 16

        spacing: 26

        TextFieldType {
            id: serverName

            Layout.fillWidth: true
            headerText: qsTr("Server name")
            textField.text: root.serverNameText
            textField.maximumLength: 30
            checkEmptyText: true
        }

        TextFieldType {
            id: vpnHost
            Layout.fillWidth: true
            visible: ServersUiController.isProcessedServerHasWriteAccess()
            headerText: qsTr("VPN address (AWG / WireGuard)")
            textField.maximumLength: 253
            textField.placeholderText: "vpn.example.org"
            helperText: qsTr("Leave empty to use the server address. SSH access is unchanged.")
        }

        ButtonType {
            id: saveButton

            Layout.fillWidth: true

            text: qsTr("Save")

            onClicked: {
                if (serverName.textField.text === "") {
                    return
                }

                if (vpnHost.visible && vpnHost.textField.text !== ServersUiController.vpnHostName(ServersUiController.processedServerId)) {
                    if (ServersUiController.isDefaultServerCurrentlyProcessed() && ConnectionController.isConnected) {
                        PageController.showNotificationMessage(qsTr("Disconnect before changing the VPN address"))
                        return
                    }
                    if (!ServersUiController.setVpnHostName(ServersUiController.processedServerId, vpnHost.textField.text)) {
                        return
                    }
                }
                if (serverName.textField.text !== root.serverNameText) {
                    ServersUiController.editServerName(ServersUiController.processedServerId, serverName.textField.text);
                }
                root.close()
            }
        }
    }
}
