#include "wireguardInstaller.h"
#include "core/configurators/wireguardConfigurator.h"

#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/protocolEnum.h"
#include "core/utils/protocolEnum.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/selfhosted/sshSession.h"

using namespace amnezia;
using namespace ProtocolUtils;

WireguardInstaller::WireguardInstaller(QObject *parent)
    : InstallerBase(parent)
{
}

ErrorCode WireguardInstaller::extractConfigFromContainer(DockerContainer container, const ServerCredentials &credentials,
                                                         SshSession* sshSession, ContainerConfig &config)
{
    ErrorCode errorCode = ErrorCode::NoError;
    
    QString serverConfig = sshSession->getTextFileFromContainer(container, credentials,
                                                                      protocols::wireguard::serverConfigPath, errorCode);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    if (auto* wgConfig = config.getWireGuardProtocolConfig()) {
        const auto prefix = WireguardConfigurator::serverIPv4CidrFromInterfaceConfig(serverConfig);
        wgConfig->serverConfig.subnetAddress = prefix.section('/', 0, 0);
        wgConfig->serverConfig.subnetCidr = prefix.section('/', 1, 1);
    }
    
    return ErrorCode::NoError;
}

