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

    property var isServerFromTelegramApi: ServersUiController.isServerFromApi(ServersUiController.defaultServerId)
    
    property var routeActions: ["vpn", "direct", "block"]
    property string inspectionResult: ""
    property bool pageEnabled

    Component.onCompleted: {
        if (ConnectionController.isConnected) {
            PageController.showNotificationMessage(qsTr("Cannot change split tunneling settings during active connection"))
            root.pageEnabled = false
        } else if (ServersUiController.isDefaultServerDefaultContainerHasSplitTunneling) {
            PageController.showNotificationMessage(qsTr("Default server does not support split tunneling function"))
            root.pageEnabled = false
        } else {
            root.pageEnabled = true
        }
    }

    Connections {
        target: IpSplitTunnelingController

        function onDomainRoutingChanged() { root.inspectionResult = "" }

        function onFinished(message) {
            PageController.showNotificationMessage(message)
        }

        function onErrorOccurred(errorMessage) {
            PageController.showErrorMessage(errorMessage)
        }
    }

    QtObject {
        id: routeMode
        property int allSites: 0
        property int onlyForwardSites: 1
        property int allExceptSites: 2
    }

    property list<QtObject> routeModesModel: [
        onlyForwardSites,
        allExceptSites
    ]

    QtObject {
        id: onlyForwardSites
        property string segmentName: qsTr("Via VPN")
        property string name: qsTr("Only the sites listed here will be accessed through the VPN")
        property int type: routeMode.onlyForwardSites
    }
    QtObject {
        id: allExceptSites
        property string segmentName: qsTr("Directly")
        property string name: qsTr("Addresses from the list should not be accessed via VPN")
        property int type: routeMode.allExceptSites
    }

    function getRouteModesModelIndex() {
        return IpSplitTunnelingController.routeMode === routeMode.allExceptSites ? 1 : 0
    }

    ListViewType {
        id: listView

        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: addSitePanel.top

        model: IpSplitTunnelingController.singBoxRoutingEnabled ? null : legacyProxy

        SortFilterProxyModel {
            id: legacyProxy

            sourceModel: IpSplitTunnelingModel
            filters: [
                AnyOf {
                    RegExpFilter {
                        roleName: "url"
                        pattern: ".*" + addSitePanel.textField.text + ".*"
                        caseSensitivity: Qt.CaseInsensitive
                    }
                    RegExpFilter {
                        roleName: "ip"
                        pattern: ".*" + addSitePanel.textField.text + ".*"
                        caseSensitivity: Qt.CaseInsensitive
                    }
                }
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

                title: qsTr("Split tunneling")

                header.showSwitcher: true
                header.switcher.checked: IpSplitTunnelingController.isSplitTunnelingEnabled
                header.switcher.enabled: root.pageEnabled

                Connections {
                    target: navigationBar.header

                    function onSwitcherToggled(checked) {
                        IpSplitTunnelingController.toggleSplitTunneling(checked)
                    }
                }
            }

            CheckBox {
                visible: IpSplitTunnelingController.singBoxRoutingAvailable
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                enabled: root.pageEnabled
                text: qsTr("Experimental domain routing (AWG / WireGuard) (supports *.ru)")
                checked: IpSplitTunnelingController.singBoxRoutingEnabled
                onClicked: {
                    IpSplitTunnelingController.setSingBoxRoutingEnabled(checked)
                    checked = IpSplitTunnelingController.singBoxRoutingEnabled
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.margins: 16
                spacing: 8
                BodyTextType {
                    Layout.fillWidth: true
                    text: qsTr("Portable domain routing configuration (AWG / WireGuard)")
                    wrapMode: Text.WordWrap
                }
                RowLayout {
                    Layout.fillWidth: true
                    Button {
                        text: qsTr("Import configuration")
                        enabled: root.pageEnabled
                        onClicked: root.importRoutingConfiguration()
                    }
                    Button {
                        text: qsTr("Export configuration")
                        onClicked: root.exportRoutingConfiguration()
                    }
                }
            }

            ColumnLayout {
                visible: IpSplitTunnelingController.singBoxRoutingEnabled
                Layout.fillWidth: true
                Layout.margins: 16
                enabled: root.pageEnabled
                spacing: 12

                BodyTextType {
                    Layout.fillWidth: true
                    text: qsTr("Routing rules apply to apps included in the VPN. Exact domain → longest suffix → longest CIDR → default. A suffix includes its root domain. Domains can come from managed DNS or visible HTTP/TLS/QUIC metadata. If no domain is available, IP rules and the default route still apply. ECH may hide the original hostname. Port and TCP/UDP conditions are combined with the destination. Equally specific rules are checked in list order. Reconnect to apply changes.")
                    wrapMode: Text.WordWrap
                    color: AmneziaStyle.color.textSecondary
                }
                RowLayout {
                    Label { text: qsTr("Default route") }
                    ComboBox {
                        model: [qsTr("VPN"), qsTr("Direct"), qsTr("Block")]
                        currentIndex: root.routeActions.indexOf(IpSplitTunnelingController.domainDefault)
                        onActivated: IpSplitTunnelingController.setDomainDefault(root.routeActions[currentIndex])
                    }
                }
                Repeater {
                    model: IpSplitTunnelingController.domainRules
                    delegate: ColumnLayout {
                        id: routingRow
                        required property int index
                        required property var modelData
                        Layout.fillWidth: true
                        TextField {
                            id: ruleDestination
                            Layout.fillWidth: true
                            text: (routingRow.modelData.kind === "suffix" && !routingRow.modelData.value.startsWith("*.") ? "*." : "") + routingRow.modelData.value
                            placeholderText: qsTr("Domain, *.suffix or CIDR")
                            Accessible.name: qsTr("Rule destination")
                        }
                        RowLayout {
                            TextField {
                                id: rulePorts
                                Layout.fillWidth: true
                                text: routingRow.modelData.ports || ""
                                placeholderText: qsTr("All ports, or 80,443,8000-8100")
                                Accessible.name: qsTr("Rule destination ports")
                            }
                            ComboBox {
                                id: ruleNetwork
                                model: [qsTr("TCP + UDP"), qsTr("TCP"), qsTr("UDP")]
                                currentIndex: routingRow.modelData.network === "tcp" ? 1 : routingRow.modelData.network === "udp" ? 2 : 0
                                Accessible.name: qsTr("Rule network")
                            }
                        }
                        RowLayout {
                            CheckBox {
                                id: ruleEnabled
                                text: qsTr("Enabled")
                                checked: !routingRow.modelData.disabled
                            }
                            ComboBox {
                                id: ruleAction
                                Layout.fillWidth: true
                                model: [qsTr("VPN"), qsTr("Direct"), qsTr("Block")]
                                currentIndex: root.routeActions.indexOf(routingRow.modelData.action)
                                Accessible.name: qsTr("Rule route")
                            }
                            Button {
                                text: qsTr("Save")
                                onClicked: IpSplitTunnelingController.saveDomainRule(routingRow.index, ruleDestination.text, root.routeActions[ruleAction.currentIndex], ruleEnabled.checked, rulePorts.text, ruleNetwork.currentIndex === 0 ? "" : ruleNetwork.currentIndex === 1 ? "tcp" : "udp")
                            }
                            Button {
                                text: qsTr("Remove")
                                onClicked: IpSplitTunnelingController.removeDomainRule(routingRow.index)
                            }
                        }
                    }
                }
                TextField {
                    id: newRuleDestination
                    Layout.fillWidth: true
                    placeholderText: qsTr("Domain, *.suffix, IP or CIDR")
                    Accessible.name: qsTr("New rule destination")
                }
                RowLayout {
                    TextField {
                        id: newRulePorts
                        Layout.fillWidth: true
                        placeholderText: qsTr("All ports, or 80,443,8000-8100")
                        Accessible.name: qsTr("New rule destination ports")
                    }
                    ComboBox {
                        id: newRuleNetwork
                        model: [qsTr("TCP + UDP"), qsTr("TCP"), qsTr("UDP")]
                        Accessible.name: qsTr("New rule network")
                    }
                }
                RowLayout {
                    ComboBox {
                        id: newRuleAction
                        Layout.fillWidth: true
                        model: [qsTr("VPN"), qsTr("Direct"), qsTr("Block")]
                        currentIndex: 1
                    }
                    Button {
                        text: qsTr("Add rule")
                        onClicked: {
                            if (IpSplitTunnelingController.saveDomainRule(-1, newRuleDestination.text, root.routeActions[newRuleAction.currentIndex], true,
                                    newRulePorts.text, newRuleNetwork.currentIndex === 0 ? "" : newRuleNetwork.currentIndex === 1 ? "tcp" : "udp")) {
                                newRuleDestination.clear()
                                newRulePorts.clear()
                            }
                        }
                    }
                }
            }

            ColumnLayout {
                visible: IpSplitTunnelingController.singBoxRoutingEnabled
                Layout.fillWidth: true
                Layout.margins: 16
                spacing: 8
                BodyTextType {
                    text: qsTr("Check a routing rule")
                }
                TextField {
                    id: checkDestination
                    Layout.fillWidth: true
                    placeholderText: qsTr("Exact hostname or IP")
                    Accessible.name: qsTr("Destination to check")
                    onTextChanged: root.inspectionResult = ""
                }
                TextField {
                    id: checkIp
                    Layout.fillWidth: true
                    placeholderText: qsTr("Known destination IP (optional with hostname)")
                    Accessible.name: qsTr("Known destination IP")
                    onTextChanged: root.inspectionResult = ""
                }
                RowLayout {
                    TextField {
                        id: checkPort
                        Layout.fillWidth: true
                        text: "443"
                        placeholderText: qsTr("Destination port")
                        Accessible.name: qsTr("Destination port to check")
                        onTextChanged: root.inspectionResult = ""
                    }
                    ComboBox {
                        id: checkNetwork
                        model: [qsTr("TCP"), qsTr("UDP")]
                        Accessible.name: qsTr("Network to check")
                        onCurrentIndexChanged: root.inspectionResult = ""
                    }
                    Button {
                        text: qsTr("Check")
                        onClicked: {
                            var result = IpSplitTunnelingController.inspectDomainRule(checkDestination.text, checkIp.text, checkPort.text,
                                                                                   checkNetwork.currentIndex === 0 ? "tcp" : "udp")
                            var action = result.action === "direct" ? qsTr("Direct") : result.action === "vpn" ? qsTr("VPN") : qsTr("Block")
                            root.inspectionResult = result.error || (result.reason === "managed_dns"
                                ? qsTr("Managed DNS — port 53 is intercepted before destination rules")
                                : result.reason === "rule" ? qsTr("%1 — rule %2").arg(action).arg(result.rule)
                                : qsTr("%1 — default route").arg(action))
                        }
                    }
                }
                BodyTextType {
                    Layout.fillWidth: true
                    text: root.inspectionResult
                    wrapMode: Text.WordWrap
                }
                BodyTextType {
                    Layout.fillWidth: true
                    text: qsTr("Checks the saved policy against the hostname, IP, port and network you enter. No DNS lookup is performed. A live connection can differ if its hostname is hidden, or application rules exclude it from the VPN.")
                    wrapMode: Text.WordWrap
                    color: AmneziaStyle.color.textSecondary
                }
            }

            SegmentedControlType {
                id: modeSelector
                visible: !IpSplitTunnelingController.singBoxRoutingEnabled

                Layout.fillWidth: true
                Layout.topMargin: 16
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                enabled: root.pageEnabled

                model: [onlyForwardSites.segmentName, allExceptSites.segmentName]
                currentIndex: root.getRouteModesModelIndex()

                onActivated: function(index) {
                    if (IpSplitTunnelingController.routeMode !== root.routeModesModel[index].type) {
                        IpSplitTunnelingController.routeMode = root.routeModesModel[index].type
                    }
                }

                Connections {
                    target: IpSplitTunnelingController

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

                visible: !IpSplitTunnelingController.singBoxRoutingEnabled
                text: root.routeModesModel[modeSelector.currentIndex].name
                color: AmneziaStyle.color.textSecondary
            }
        }

        delegate: Item {
            width: listView.width
            implicitHeight: site.implicitHeight

            enabled: root.pageEnabled

            ListItemType {
                id: site

                anchors.fill: parent
                anchors.leftMargin: 16
                anchors.rightMargin: 16

                text: url
                subtitle: ip
                trailingIconSource: "qrc:/images/controls/trash.svg"

                onClicked: {
                    var headerText = qsTr("Remove ") + url + "?"
                    var yesButtonText = qsTr("Continue")
                    var noButtonText = qsTr("Cancel")

                    var yesButtonFunction = function() {
                        IpSplitTunnelingController.removeSite(legacyProxy.mapToSource(index))
                        if (!GC.isMobile()) {
                            site.forceActiveFocus(Qt.TabFocusReason)
                        }
                    }
                    var noButtonFunction = function() {
                        if (!GC.isMobile()) {
                            site.forceActiveFocus(Qt.TabFocusReason)
                        }
                    }

                    showQuestionDrawer(headerText, "", yesButtonText, noButtonText, yesButtonFunction, noButtonFunction)
                }
            }
        }
    }

    AddSitePanel {
        id: addSitePanel
        visible: !IpSplitTunnelingController.singBoxRoutingEnabled
        height: visible ? implicitHeight : 0

        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.bottomMargin: addSitePanel.textField.activeFocus ? 0 : PageController.imeHeight

        enabled: root.pageEnabled
        placeholderText: qsTr("website or IP")
        moreButtonAccessibleName: qsTr("Additional options")

        onAddClicked: function(text) {
            PageController.showBusyIndicator(true)
            IpSplitTunnelingController.addSite(text)
            PageController.showBusyIndicator(false)
        }

        onMoreClicked: {
            moreActionsMenu.openAbove(addSitePanel.moreButton)
        }
    }

    PopupMenuType {
        id: moreActionsMenu

        PopupMenuItemType {
            id: addImportedSitesButton

            text: qsTr("Add imported sites to existing ones")

            onClicked: {
                moreActionsMenu.close()
                root.selectImportFile(false)
            }
        }

        PopupMenuItemType {
            id: replaceSitesButton

            text: qsTr("Replace site list")

            onClicked: {
                moreActionsMenu.close()
                root.selectImportFile(true)
            }
        }

        PopupMenuItemType {
            id: exportSitesButton

            text: qsTr("Save site list")

            onClicked: {
                moreActionsMenu.close()
                var fileName = ""
                if (GC.isMobile()) {
                    fileName = "amnezia_sites.json"
                } else {
                    fileName = SystemController.getFileName(qsTr("Save sites"),
                                                            qsTr("Sites files (*.json)"),
                                                            StandardPaths.standardLocations(StandardPaths.DocumentsLocation) + "/amnezia_sites",
                                                            true,
                                                            ".json")
                }
                if (fileName !== "") {
                    PageController.showBusyIndicator(true)
                    IpSplitTunnelingController.exportSites(fileName)
                    PageController.showBusyIndicator(false)
                }
            }
        }

        PopupMenuSeparatorType {}

        PopupMenuItemType {
            id: clearSitesButton

            text: qsTr("Clear site list")
            destructive: true

            onClicked: {
                moreActionsMenu.close()
                var headerText = qsTr("Clear site list?")
                var descriptionText = qsTr("All sites will be removed from list.")
                var yesButtonText = qsTr("Continue")
                var noButtonText = qsTr("Cancel")

                var yesButtonFunction = function() {
                    PageController.showBusyIndicator(true)
                    IpSplitTunnelingController.removeSites()
                    PageController.showBusyIndicator(false)
                }
                var noButtonFunction = function() {
                }

                showQuestionDrawer(headerText, descriptionText, yesButtonText, noButtonText, yesButtonFunction, noButtonFunction)
            }
        }
    }

    function importRoutingConfiguration() {
        var fileName = SystemController.getFileName(qsTr("Import routing configuration"), qsTr("Routing configuration (*.json)"))
        if (fileName === "") return
        showQuestionDrawer(qsTr("Replace routing configuration?"),
            qsTr("Replaces all domain routing rules and the default route after validation. VPN connections and enable switches are unchanged. Reconnect to apply."),
            qsTr("Import"), qsTr("Cancel"),
            function() { IpSplitTunnelingController.importDomainRouting(fileName) }, function() {})
    }

    function exportRoutingConfiguration() {
        var fileName = GC.isMobile() ? "amnezia_routing.json" : SystemController.getFileName(qsTr("Export routing configuration"),
            qsTr("Routing configuration (*.json)"),
            StandardPaths.standardLocations(StandardPaths.DocumentsLocation) + "/amnezia_routing", true, ".json")
        if (fileName !== "") IpSplitTunnelingController.exportDomainRouting(fileName)
    }

    function selectImportFile(replaceExistingSites) {
        var fileName = SystemController.getFileName(qsTr("Open sites file"),
                                                    qsTr("Sites files (*.json)"))
        if (fileName !== "") {
            root.importSites(fileName, replaceExistingSites)
        }
    }

    function importSites(fileName, replaceExistingSites) {
        PageController.showBusyIndicator(true)
        IpSplitTunnelingController.importSites(fileName, replaceExistingSites)
        PageController.showBusyIndicator(false)
    }
}
