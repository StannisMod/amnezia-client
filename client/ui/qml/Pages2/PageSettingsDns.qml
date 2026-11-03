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
    property var dnsDraft: ({})
    readonly property var policyIds: Object.keys(dnsDraft.policies || {})
    readonly property var policyChoices: policyIds.map(function(id) { return {id: id, label: root.dnsDraft.policies[id].name || id} })

    function loadDnsDraft() {
        const saved = JSON.parse(JSON.stringify(SettingsController.splitDnsConfig))
        splitDnsEnabled.checked = SettingsController.splitDnsEnabled
        dnsDraft = saved.version !== undefined ? saved : {
            version: 1, default: "vpn", follow_routing: false, direct: "direct", vpn: "vpn",
            policies: {
                direct: {name: qsTr("Direct DNS"), transport: "udp", server: "1.1.1.1", path: "direct"},
                vpn: {name: qsTr("VPN DNS"), transport: "udp", server: SettingsController.primaryDns, path: "vpn"}
            }, rules: []
        }
        followRouting.checked = dnsDraft.follow_routing
        preserveNetworkDomains.checked = !!dnsDraft.preserve_network_domains
    }

    function collectDnsDraft() {
        const config = {version: 1, default: defaultPolicy.currentValue || "",
            follow_routing: followRouting.checked, direct: directPolicy.currentValue || "", vpn: vpnPolicy.currentValue || "",
            policies: {}, rules: []}
        if (preserveNetworkDomains.checked) config.preserve_network_domains = true
        for (let i = 0; i < policies.count; ++i) {
            const row = policies.itemAt(i)
            config.policies[row.policyId] = row.policy()
        }
        for (let i = 0; i < dnsRules.count; ++i) config.rules.push(dnsRules.itemAt(i).rule())
        return config
    }

    Component.onCompleted: {
        loadDnsDraft()
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
                description: qsTr("Reconnect to apply DNS changes. Split DNS requires AWG / WireGuard domain routing.")
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.topMargin: 16
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 16

                spacing: 12

                enabled: !root.isServerFromApi && !ConnectionController.isConnected


                CheckBox {
                    id: splitDnsEnabled
                    Layout.fillWidth: true
                    text: qsTr("Different DNS for domains")
                    enabled: IpSplitTunnelingController.singBoxRoutingEnabled && !ConnectionController.isConnected
                }
                BodyTextType {
                    Layout.fillWidth: true
                    visible: !IpSplitTunnelingController.singBoxRoutingEnabled
                    text: qsTr("Enable experimental domain routing in Split tunneling to use split DNS.")
                    wrapMode: Text.WordWrap
                }
                TextFieldType {
                    id: primaryDns

                    Layout.fillWidth: true

                    headerText: qsTr("Primary DNS")
                    visible: !splitDnsEnabled.checked

                    textField.text: SettingsController.primaryDns
                    textField.validator: RegularExpressionValidator {
                        regularExpression: InstallController.ipAddressRegExp()
                    }
                }

                TextFieldType {
                    id: secondaryDns

                    Layout.fillWidth: true

                    headerText: qsTr("Secondary DNS")
                    visible: !splitDnsEnabled.checked

                    textField.text: SettingsController.secondaryDns
                    textField.validator: RegularExpressionValidator {
                        regularExpression: InstallController.ipAddressRegExp()
                    }
                }

                ColumnLayout {
                    visible: splitDnsEnabled.checked
                    enabled: !ConnectionController.isConnected
                    Layout.fillWidth: true
                    spacing: 12
                    CheckBox {
                        id: followRouting
                        Layout.fillWidth: true
                        text: qsTr("DNS by site route")
                    }
                    BodyTextType {
                        Layout.fillWidth: true
                        text: followRouting.checked
                            ? qsTr("Direct site → direct DNS. VPN site → VPN DNS. Explicit DNS exceptions take priority. Application and IP rules do not select DNS.")
                            : qsTr("DNS exceptions take priority over the default DNS policy. Site routes do not change DNS.")
                        wrapMode: Text.WordWrap
                    }
                    Label { text: qsTr("Default DNS policy"); visible: !followRouting.checked }
                    ComboBox {
                        id: defaultPolicy
                        Layout.fillWidth: true
                        visible: !followRouting.checked
                        model: root.policyChoices
                        textRole: "label"
                        valueRole: "id"
                        currentIndex: root.policyIds.indexOf(root.dnsDraft.default)
                        Accessible.name: qsTr("Default DNS policy")
                    }
                    Label { text: qsTr("DNS policy for direct sites"); visible: followRouting.checked }
                    ComboBox {
                        id: directPolicy
                        Layout.fillWidth: true
                        visible: followRouting.checked
                        model: root.policyChoices
                        textRole: "label"
                        valueRole: "id"
                        currentIndex: root.policyIds.indexOf(root.dnsDraft.direct)
                        Accessible.name: qsTr("DNS policy for direct sites")
                    }
                    Label { text: qsTr("DNS policy for VPN sites"); visible: followRouting.checked }
                    ComboBox {
                        id: vpnPolicy
                        Layout.fillWidth: true
                        visible: followRouting.checked
                        model: root.policyChoices
                        textRole: "label"
                        valueRole: "id"
                        currentIndex: root.policyIds.indexOf(root.dnsDraft.vpn)
                        Accessible.name: qsTr("DNS policy for VPN sites")
                    }
                    Label { text: qsTr("DNS policies") }
                    Repeater {
                        id: policies
                        model: root.policyIds
                        delegate: ColumnLayout {
                            id: policyRow
                            required property string modelData
                            readonly property string policyId: modelData
                            readonly property var saved: root.dnsDraft.policies[policyId]
                            Layout.fillWidth: true
                            function policy() {
                                const value = {name: policyName.text, server: policyServer.text.trim(),
                                    transport: policyTransport.currentText, path: policyPath.currentIndex === 0 ? "direct" : "vpn"}
                                if (policyPort.text.trim()) value.port = Number(policyPort.text)
                                if (networkSource.checked) {
                                    value.source = "network"
                                    value.server = ""
                                    if (networkInterface.text.trim()) value.interface = networkInterface.text.trim()
                                    return value
                                }
                                if (bootstrap.text.trim()) value.bootstrap = bootstrap.text.trim()
                                if (policyTransport.currentIndex >= 2 && tlsName.text.trim()) value.server_name = tlsName.text.trim()
                                if (policyTransport.currentIndex === 3 && httpsPath.text.trim()) value.https_path = httpsPath.text.trim()
                                return value
                            }
                            Label { text: policyRow.policyId }
                            CheckBox {
                                id: networkSource
                                visible: IpSplitTunnelingController.singBoxRoutingAvailable || checked
                                enabled: IpSplitTunnelingController.singBoxRoutingAvailable
                                text: qsTr("Use DNS from the current network")
                                checked: policyRow.saved.source === "network"
                                onClicked: { if (checked) { policyPath.currentIndex = 0; policyTransport.currentIndex = 0 } }
                            }
                            TextField {
                                id: policyName
                                Layout.fillWidth: true
                                text: policyRow.saved.name || ""
                                placeholderText: qsTr("Policy name")
                                Accessible.name: qsTr("Policy name")
                            }
                            TextField {
                                id: policyServer
                                Layout.fillWidth: true
                                visible: !networkSource.checked
                                text: policyRow.saved.server
                                placeholderText: qsTr("DNS server IP or hostname")
                                Accessible.name: qsTr("DNS server")
                            }
                            TextField {
                                id: networkInterface
                                Layout.fillWidth: true
                                visible: networkSource.checked
                                text: policyRow.saved.interface || ""
                                placeholderText: qsTr("Network interface (leave empty for automatic selection)")
                                Accessible.name: qsTr("DNS network interface")
                            }
                            RowLayout {
                                ComboBox {
                                    id: policyTransport
                                    model: networkSource.checked ? ["udp", "tcp"] : ["udp", "tcp", "tls", "https"]
                                    currentIndex: Math.max(0, model.indexOf(policyRow.saved.transport))
                                    Accessible.name: qsTr("DNS transport")
                                }
                                TextField {
                                    id: policyPort
                                    Layout.fillWidth: true
                                    text: policyRow.saved.port || ""
                                    placeholderText: qsTr("Default port")
                                    validator: IntValidator { bottom: 1; top: 65535 }
                                    Accessible.name: qsTr("DNS port")
                                }
                                ComboBox {
                                    id: policyPath
                                    enabled: !networkSource.checked
                                    model: [qsTr("Direct"), qsTr("VPN")]
                                    currentIndex: policyRow.saved.path === "direct" ? 0 : 1
                                    Accessible.name: qsTr("DNS route")
                                }
                            }
                            TextField {
                                id: bootstrap
                                Layout.fillWidth: true
                                visible: !networkSource.checked
                                text: policyRow.saved.bootstrap || ""
                                placeholderText: qsTr("Bootstrap for hostname: IP:port or [IPv6]:port")
                                Accessible.name: qsTr("DNS bootstrap server")
                            }
                            TextField {
                                id: tlsName
                                Layout.fillWidth: true
                                visible: policyTransport.currentIndex >= 2
                                text: policyRow.saved.server_name || ""
                                placeholderText: qsTr("TLS hostname (optional for a named server)")
                                Accessible.name: qsTr("DNS TLS hostname")
                            }
                            TextField {
                                id: httpsPath
                                Layout.fillWidth: true
                                visible: policyTransport.currentIndex === 3
                                text: policyRow.saved.https_path || ""
                                placeholderText: "/dns-query"
                                Accessible.name: qsTr("DNS HTTPS path")
                            }
                            Button {
                                text: qsTr("Remove policy")
                                onClicked: {
                                    const config = root.collectDnsDraft()
                                    delete config.policies[policyRow.policyId]
                                    root.dnsDraft = config
                                }
                            }
                        }
                    }
                    Button {
                        text: qsTr("Add DNS policy")
                        onClicked: {
                            const config = root.collectDnsDraft()
                            let i = 1
                            while (config.policies["policy-" + i]) ++i
                            config.policies["policy-" + i] = {transport: "udp", server: "", path: "direct"}
                            root.dnsDraft = config
                        }
                    }
                    Label { text: qsTr("DNS exceptions") }
                    Repeater {
                        id: dnsRules
                        model: root.dnsDraft.rules || []
                        delegate: ColumnLayout {
                            id: dnsRuleRow
                            required property int index
                            required property var modelData
                            Layout.fillWidth: true
                            function rule() {
                                let value = dnsDomain.text.trim()
                                const kind = value.startsWith("*.") ? "suffix" : "domain"
                                if (kind === "suffix") value = value.substring(2)
                                return {kind: kind, value: value, policy: dnsRulePolicy.currentValue || "", disabled: !dnsRuleEnabled.checked}
                            }
                            TextField {
                                id: dnsDomain
                                Layout.fillWidth: true
                                text: (dnsRuleRow.modelData.kind === "suffix" ? "*." : "") + dnsRuleRow.modelData.value
                                placeholderText: qsTr("Domain or *.suffix")
                                Accessible.name: qsTr("DNS exception domain")
                            }
                            RowLayout {
                                CheckBox { id: dnsRuleEnabled; text: qsTr("Enabled"); checked: !dnsRuleRow.modelData.disabled }
                                ComboBox {
                                    id: dnsRulePolicy
                                    Layout.fillWidth: true
                                    model: root.policyChoices
                                    textRole: "label"
                                    valueRole: "id"
                                    currentIndex: root.policyIds.indexOf(dnsRuleRow.modelData.policy)
                                    Accessible.name: qsTr("DNS exception policy")
                                }
                                Button {
                                    text: qsTr("Remove")
                                    onClicked: {
                                        const config = root.collectDnsDraft()
                                        config.rules.splice(dnsRuleRow.index, 1)
                                        root.dnsDraft = config
                                    }
                                }
                            }
                        }
                    }
                    Button {
                        text: qsTr("Add DNS exception")
                        onClicked: {
                            const config = root.collectDnsDraft()
                            config.rules.push({kind: "domain", value: "", policy: root.policyIds[0] || ""})
                            root.dnsDraft = config
                        }
                    }
                    CheckBox {
                        id: preserveNetworkDomains
                        visible: Qt.platform.os === "linux" || Qt.platform.os === "windows" || checked
                        Layout.fillWidth: true
                        text: qsTr("Preserve corporate DNS rules from the network (Linux / Windows)")
                    }
                    BodyTextType {
                        Layout.fillWidth: true
                        text: qsTr("A suffix includes its root domain. Exact names win over suffixes; longer suffixes win. No automatic fallback to another policy. Corporate DNS rules are discovered on Linux and Windows; search suffixes alone do not create DNS rules. Apps using their own DoH/DoT may bypass these rules.")
                        wrapMode: Text.WordWrap
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

        enabled: !root.isServerFromApi && !ConnectionController.isConnected

        ButtonType {
            id: restoreDefaultButton

            Layout.fillWidth: true

            variant: ButtonType.Secondary
            text: qsTr("Restore default")

            onClicked: {
                var headerText = qsTr("Restore default DNS settings?")
                var yesButtonText = qsTr("Continue")
                var noButtonText = qsTr("Cancel")

                var yesButtonFunction = function() {
                    SettingsController.primaryDns = "1.1.1.1"
                    primaryDns.textField.text = SettingsController.primaryDns
                    SettingsController.secondaryDns = "1.0.0.1"
                    secondaryDns.textField.text = SettingsController.secondaryDns
                    SettingsController.saveSplitDnsConfig({})
                    root.loadDnsDraft()
                    PageController.showNotificationMessage(qsTr("Settings have been reset"))
                }
                var noButtonFunction = function() {
                }

                showQuestionDrawer(headerText, "", yesButtonText, noButtonText, yesButtonFunction, noButtonFunction)
            }
        }

        ButtonType {
            id: saveButton

            Layout.fillWidth: true

            text: qsTr("Save")

            onClicked: {
                if (ConnectionController.isConnected) {
                    PageController.showNotificationMessage(qsTr("Disconnect before changing DNS settings"))
                    return
                }
                if (primaryDns.textField.text === "") {
                    primaryDns.errorText = qsTr("Primary DNS cannot be empty")
                    return
                }
                primaryDns.errorText = ""
                secondaryDns.errorText = ""
                const dnsError = SettingsController.saveSplitDnsConfig(splitDnsEnabled.checked ? root.collectDnsDraft() : {})
                if (dnsError) {
                    PageController.showNotificationMessage(dnsError)
                    return
                }

                if (primaryDns.textField.text !== SettingsController.primaryDns) {
                    SettingsController.primaryDns = primaryDns.textField.text
                }
                if (secondaryDns.textField.text !== SettingsController.secondaryDns) {
                    SettingsController.secondaryDns = secondaryDns.textField.text
                }
                root.loadDnsDraft()
                PageController.showNotificationMessage(qsTr("Settings saved"))
            }
        }
    }
}
