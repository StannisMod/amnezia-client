import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Dialog {
    id: root
    property string selectedServerId: ""
    readonly property var migration: ServerMigrationController
    title: qsTr("Move server")
    modal: true
    closePolicy: Popup.NoAutoClose
    width: Math.min(parent.width - 24, 560)
    height: Math.min(parent.height - 24, 720)
    anchors.centerIn: parent

    contentItem: ScrollView {
        clip: true
        ColumnLayout {
            width: root.availableWidth
            spacing: 12
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: qsTr("Move standard WireGuard/AWG, DNS and signed subscriptions to another Linux server with Docker and Python 3.9+. The VPN and subscription DNS names stay the same. Keep both servers until all clients reconnect. A brief interruption is possible during switching.")
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                visible: migration.phase === "" || migration.phase === "fingerprints"
                text: qsTr("The target must be empty, use the same CPU architecture and allow passwordless sudo. Open its VPN UDP ports and subscription TCP port 8443. Do not edit users or server settings during migration.")
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.WrapAnywhere
                visible: migration.domain !== ""
                text: qsTr("Domain: %1\nTarget: %2").arg(migration.domain).arg(migration.targetAddress)
                textFormat: Text.PlainText
            }
            ColumnLayout {
                Layout.fillWidth: true
                visible: migration.phase === ""
                TextField { id: host; Layout.fillWidth: true; placeholderText: qsTr("Target SSH IP address") }
                TextField { id: port; Layout.fillWidth: true; placeholderText: qsTr("SSH port"); text: "22"; inputMethodHints: Qt.ImhDigitsOnly }
                TextField { id: user; Layout.fillWidth: true; placeholderText: qsTr("SSH login"); text: "root" }
                TextField { id: secret; Layout.fillWidth: true; placeholderText: qsTr("SSH password or unencrypted private key"); echoMode: TextInput.Password }
                Button {
                    text: qsTr("Check SSH identities")
                    enabled: !migration.busy
                    onClicked: {
                        migration.discover(root.selectedServerId, host.text, parseInt(port.text), user.text, secret.text)
                        secret.clear()
                    }
                }
            }
            Label {
                visible: migration.serverId !== "" && migration.serverId !== root.selectedServerId
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: qsTr("This saved operation belongs to another server. Its domain and target are shown above.")
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.WrapAnywhere
                text: migration.details
                textFormat: Text.PlainText
            }
            Label {
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                visible: migration.phase === "fingerprints"
                text: qsTr("Compare both SSH fingerprints with your server console. Credentials are sent only after you approve these identities.")
            }
            Button {
                visible: migration.phase === "fingerprints"
                enabled: !migration.busy
                text: qsTr("Trust these identities and copy")
                onClicked: migration.stage()
            }
            Label {
                visible: migration.phase === "staged" || migration.phase === "switching"
                Layout.fillWidth: true
                wrapMode: Text.Wrap
                text: qsTr("Update every VPN and subscription A/AAAA record to the target address. Remove stale AAAA records if the target has no IPv6. Switching checks DNS again, verifies unchanged source state and stops the old containers. DNS caches on other devices may need time to expire.")
            }
            Button {
                visible: migration.phase === "staged" || migration.phase === "switching"
                enabled: !migration.busy
                text: qsTr("DNS updated — switch servers")
                onClicked: migration.cutover()
            }
            Button {
                visible: migration.phase !== "" && migration.phase !== "fingerprints" && migration.phase !== "discovering"
                enabled: !migration.busy
                text: qsTr("Check saved operation")
                onClicked: migration.recover()
            }
            Button {
                visible: ["copying", "staged", "switching", "active", "rolling-back"].indexOf(migration.phase) >= 0
                enabled: !migration.busy
                text: qsTr("Restore source server")
                onClicked: migration.rollback()
            }
            BusyIndicator { running: migration.busy; visible: running; Layout.alignment: Qt.AlignHCenter }
            Button {
                visible: ["discovering", "fingerprints", "rolled-back", "active", "aborted", "finalizing"].indexOf(migration.phase) >= 0
                enabled: !migration.busy
                text: (migration.phase === "active" || migration.phase === "finalizing") ? qsTr("Finish and forget rollback credentials") : qsTr("Clear saved operation")
                onClicked: migration.dismiss()
            }
            Button {
                enabled: !migration.busy
                text: qsTr("Close")
                onClicked: root.close()
            }
        }
    }
}
