#include "proxyIpv6Upgrade.h"
#include <QFile>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QStringList>
#include "core/utils/containers/containerUtils.h"
#include "core/utils/selfhosted/sshSession.h"

namespace amnezia::proxyIpv6Upgrade {
bool supported(DockerContainer container)
{
    return container == DockerContainer::Xray || container == DockerContainer::SSXray;
}

bool parseProbeResponse(const QString &output, const QString &expectedRemote, QJsonObject &evidence)
{
    evidence = {};
    const QString marker = QStringLiteral("\namnezia_ipv6_probe=");
    const auto position = output.indexOf(marker);
    if (output.toUtf8().size() > 65536 || position <= 0 || position != output.lastIndexOf(marker)) return false;
    QJsonParseError error;
    const auto metadata = QJsonDocument::fromJson(output.mid(position + marker.size()).trimmed().toUtf8(), &error);
    if (error.error != QJsonParseError::NoError || !metadata.isObject()) return false;
    const auto fields = metadata.object();
    if (fields.value("http").toInt(-1) != 200 || fields.value("verify").toInt(-1) != 0) return false;
    const QHostAddress remote(fields.value("remote").toString()), local(fields.value("local").toString());
    bool mapped = false; local.toIPv4Address(&mapped);
    if (remote.protocol() != QAbstractSocket::IPv6Protocol || remote != QHostAddress(expectedRemote)
        || local.protocol() != QAbstractSocket::IPv6Protocol || local.isNull() || local.isLoopback()
        || !local.scopeId().isEmpty() || mapped) return false;
    const auto body = QJsonDocument::fromJson(output.left(position).toUtf8(), &error);
    if (error.error != QJsonParseError::NoError || !body.isObject()) return false;
    const auto answer = body.object();
    const auto questions = answer.value("Question").toArray(), records = answer.value("Answer").toArray();
    if (answer.value("Status").toInt(-1) != 0 || questions.size() != 1 || questions[0].toObject().value("name").toString() != "."
        || questions[0].toObject().value("type").toInt() != 2 || records.isEmpty() || records.size() > 64) return false;
    bool nameserver = false;
    for (const auto &record : records) if (record.toObject().value("type").toInt() == 2 && !record.toObject().value("data").toString().isEmpty()) nameserver = true;
    if (!nameserver) return false;
    evidence = {{"remoteAddress", remote.toString()}, {"localAddress", local.toString()}};
    return true;
}

ErrorCode prepare(const ServerCredentials &credentials, DockerContainer container, QJsonObject &outcome)
{
    outcome = {{"version", 1}, {"result", "unavailable"}};
    if (!credentials.isValid() || !supported(container)) return ErrorCode::InternalError;
    QFile resource(":/server_scripts/prepare_ipv6_network.sh");
    if (!resource.open(QIODevice::ReadOnly)) return ErrorCode::InternalError;
    const auto name = ContainerUtils::containerToString(container);
    const auto networkScript = QString::fromUtf8(resource.readAll()).replace("\r", "")
        + QString("\nif [ -z \"$AMNEZIA_IPV6_NETWORK\" ]; then printf '\\namnezia_proxy_ipv6_target=unavailable\\n'; exit 0; fi\n"
                  "amnezia_attach_ipv6_network '%1' || exit 1\n"
                  "printf '\\namnezia_proxy_ipv6_target=%s\\n' \"$amnezia_v6_container_id\"\n").arg(name);
    SshSession ssh;
    QString output;
    auto collect = [&](const QString &data, libssh::Client &) {
        if (output.toUtf8().size() + data.toUtf8().size() > 65536) return ErrorCode::InternalError;
        output += data;
        return ErrorCode::NoError;
    };
    auto error = ssh.runScript(credentials, SshSession::wholeScriptCommand(networkScript), collect);
    if (error != ErrorCode::NoError) { outcome["reason"] = "network_preparation_failed"; return error; }
    const auto markers = output.split('\n').filter(QRegularExpression("^amnezia_proxy_ipv6_target=(unavailable|[a-f0-9]{64})$"));
    if (markers.size() != 1) return ErrorCode::InternalError;
    const auto target = markers.first().section('=', 1);
    if (target == "unavailable") { outcome["reason"] = "ipv6_network_unavailable"; return ErrorCode::NoError; }
    outcome["containerId"] = target;
    for (const auto &provider : QList<QStringList>{
             {"2606:4700:4700::1111", "cloudflare-dns.com", "/dns-query"},
             {"2001:4860:4860::8888", "dns.google", "/resolve"}}) {
        output.clear();
        // -q must be first: a container's curlrc must not disable certificate
        // checks, add a proxy, or follow a redirect around the measured path.
        const auto probe = QString(
            "sudo docker exec '%1' curl -q --ipv6 --noproxy '*' --proto '=https' --tlsv1.2 "
            "--silent --show-error --connect-timeout 4 --max-time 5 --max-filesize 65536 "
            "--resolve '%2:443:[%3]' -H 'Accept: application/dns-json' "
            "--write-out '\\namnezia_ipv6_probe={\"http\":%{http_code},\"verify\":%{ssl_verify_result},\"remote\":\"%{remote_ip}\",\"local\":\"%{local_ip}\"}\\n' "
            "'https://%2%4?name=.&type=NS'").arg(target, provider[1], provider[0], provider[2]);
        QJsonObject evidence;
        if (ssh.runScript(credentials, probe, collect) != ErrorCode::NoError || !parseProbeResponse(output, provider[0], evidence)) continue;
        output.clear();
        error = ssh.runScript(credentials, QString("sudo docker inspect -f '{{.Id}}' '%1'").arg(name), collect);
        if (error != ErrorCode::NoError || output.trimmed() != target) return ErrorCode::InternalError;
        outcome = evidence;
        outcome["version"] = 1; outcome["result"] = "verified"; outcome["containerId"] = target; outcome["provider"] = provider[1];
        return ErrorCode::NoError;
    }
    outcome["reason"] = "authenticated_ipv6_egress_unavailable";
    return ErrorCode::NoError;
}
}
