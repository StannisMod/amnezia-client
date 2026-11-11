#include "connectionUpdates.h"

#include <QCryptographicHash>
#include <QJsonArray>
#include <QHostAddress>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSslCertificate>
#include <QUrl>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <memory>

#include "constants/configKeys.h"
#include "vpnEndpoint.h"

namespace amnezia::connectionUpdates {
namespace {
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
QByteArray decode(const QJsonValue &v, int size = -1)
{
    if (!v.isString()) return {};
    const auto encoded = v.toString().toLatin1();
    const auto result = QByteArray::fromBase64Encoding(encoded, QByteArray::AbortOnBase64DecodingErrors);
    if (!result || result.decoded.toBase64() != encoded || (size >= 0 && result.decoded.size() != size)) return {};
    return result.decoded;
}
bool supported(const QString &container)
{
    return container == "amnezia-wireguard" || container == "amnezia-awg2";
}
QString protocol(const QString &container) { return container == "amnezia-wireguard" ? "wireguard" : "awg"; }
bool validSettings(const QJsonObject &s, bool awg)
{
    QStringList keys = { "hostName", "port", "server_pub_key" };
    if (awg) keys += configKey::awgProtocolKeys();
    for (auto it = s.begin(); it != s.end(); ++it) {
        if (!keys.contains(it.key())) return false;
        if (it.key() != "port") {
            if (!it->isString() || it->toString().size() > 4096 || it->toString().contains(QRegularExpression("[\\x00\\r\\n]"))) return false;
        }
    }
    const auto host = s.value("hostName").toString();
    return !vpnEndpoint::normalizeHost(host).isEmpty() && host == vpnEndpoint::normalizeHost(host)
        && s.value("port").isDouble() && s.value("port").toInt() >= 1 && s.value("port").toInt() <= 65535
        && s.value("port").toDouble() == s.value("port").toInt() && !decode(s.value("server_pub_key"), 32).isEmpty();
}
bool validPathProbe(const QJsonValue &value)
{
    if (!value.isString() || value.toString().isEmpty() || value.toString().size() > 64) return false;
    const auto text = value.toString(); const QHostAddress address(text);
    bool mapped = false; address.toIPv4Address(&mapped);
    if (address.isNull() || address == QHostAddress::AnyIPv4 || address == QHostAddress::AnyIPv6
        || address == QHostAddress::Broadcast || address.isLoopback() || address.isMulticast()
        || address.isLinkLocal() || !address.scopeId().isEmpty() || address.toString() != text
        || (address.protocol() == QAbstractSocket::IPv6Protocol && mapped)) return false;
    return true;
}
bool usablePathProbe(const QJsonValue &value, const QJsonObject &client)
{
    if (!validPathProbe(value)) return false;
    const QHostAddress address(value.toString());
    bool family = false, allowed = false;
    for (const auto &entry : client.value(configKey::clientIp).toString().split(',')) {
        const QHostAddress local(entry.trimmed().section('/', 0, 0));
        if (!local.isNull() && local.protocol() == address.protocol()) family = true;
    }
    for (const auto &entry : client.value(configKey::allowedIps).toArray()) {
        const auto subnet = QHostAddress::parseSubnet(entry.toString());
        if (subnet.second >= 0 && subnet.first.protocol() == address.protocol() && address.isInSubnet(subnet)) allowed = true;
    }
    return family && allowed;
}
bool identityMatches(const QJsonObject &client)
{
    const auto priv = decode(client.value(configKey::clientPrivKey), 32);
    const auto pub = decode(client.value(configKey::clientPubKey), 32);
    if (priv.isEmpty() || pub.isEmpty()) return false;
    Key key(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
        reinterpret_cast<const unsigned char *>(priv.constData()), priv.size()), EVP_PKEY_free);
    unsigned char derived[32]; size_t size = sizeof(derived);
    return key && EVP_PKEY_get_raw_public_key(key.get(), derived, &size) == 1 && size == 32
        && pub == QByteArray(reinterpret_cast<char *>(derived), 32);
}
}
bool parsePathProbeAddress(const QString &output, const QString &interfaceName, QString &address)
{
    const QString marker = "\namnezia_interface_addresses=ok\n";
    if ((interfaceName != "wg0" && interfaceName != "awg0") || output.size() > 65536 || !output.endsWith(marker)) return false;
    const QRegularExpression linePattern(QStringLiteral("^\\d+:\\s+(\\S+)\\s+(inet6?)\\s+(\\S+)(?:\\s|$)"));
    QString ipv4, ipv6;
    for (const auto &line : output.left(output.size() - marker.size()).split('\n', Qt::SkipEmptyParts)) {
        const auto match = linePattern.match(line.trimmed());
        if (!match.hasMatch() || match.captured(1) != interfaceName) return false;
        const auto cidr = match.captured(3); const auto subnet = QHostAddress::parseSubnet(cidr);
        if (!cidr.contains('/') || subnet.second < 0) return false;
        const QHostAddress candidate(cidr.section('/', 0, 0));
        const bool v4 = match.captured(2) == "inet";
        if (candidate.protocol() != (v4 ? QAbstractSocket::IPv4Protocol : QAbstractSocket::IPv6Protocol)
            || !validPathProbe(candidate.toString())) return false;
        auto &target = v4 ? ipv4 : ipv6;
        if (target.isEmpty()) target = candidate.toString();
    }
    const auto target = ipv4.isEmpty() ? ipv6 : ipv4;
    if (target.isEmpty()) return false;
    address = target; return true;
}
bool parsePeerList(const QString &output, QStringList &peers)
{
    const QString marker = "\namnezia_peers=ok\n";
    if (!output.endsWith(marker)) return false;
    const auto values = output.left(output.size() - marker.size()).split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
    for (const auto &key : values) if (decode(key, 32).isEmpty()) return false;
    peers = values; return true;
}
QJsonObject invitationMetadata(const QJsonObject &administratorMetadata)
{
    QJsonObject result;
    for (const auto *key : { "version", "url", "certificate", "publicKey" }) result[key] = administratorMetadata.value(key);
    return result;
}
QJsonObject publicSettings(const QJsonObject &client, bool awg)
{
    QJsonObject result;
    QStringList keys = { "hostName", "port", "server_pub_key" };
    if (awg) keys += configKey::awgProtocolKeys();
    for (const auto &key : keys) if (client.contains(key)) result[key] = client.value(key);
    return result;
}
bool validateProfile(const QJsonObject &profile)
{
    const auto m = profile.value(metadataKey).toObject();
    if (m.value("version").toDouble(-1) != 1 || !profile.value(configKey::userName).toString().isEmpty()
        || !profile.value(configKey::password).toString().isEmpty() || profile.contains("api_config")) return false;
    static const QRegularExpression id("^[a-f0-9]{32}$"), token("^[A-Za-z0-9_-]{43}$"), revision("^(0|[1-9][0-9]{0,19})$");
    if (!id.match(m.value("id").toString()).hasMatch() || !token.match(m.value("token").toString()).hasMatch()
        || decode(m.value("publicKey"), 32).isEmpty() || !revision.match(m.value("revision").toString()).hasMatch()) return false;
    bool ok; m.value("revision").toString().toULongLong(&ok); if (!ok) return false;
    const QUrl url(m.value("url").toString(), QUrl::StrictMode);
    if (!url.isValid() || url.scheme() != "https" || vpnEndpoint::normalizeHost(url.host()).isEmpty()
        || !url.userInfo().isEmpty() || url.hasQuery() || url.hasFragment()
        || url.path() != "/v1/connections/" + m.value("id").toString() || url.port(443) < 1 || url.port(443) > 65535) return false;
    const auto cert = decode(m.value("certificate"));
    if (cert.isEmpty() || cert.size() > 16384 || QSslCertificate(cert, QSsl::Der).isNull()) return false;
    const auto containers = profile.value(configKey::containers).toArray();
    if (containers.size() != 1) return false;
    const auto c = containers.first().toObject(); const auto name = c.value(configKey::container).toString();
    if (!supported(name) || m.value("container").toString() != name || profile.value(configKey::defaultContainer).toString() != name) return false;
    const auto client = QJsonDocument::fromJson(c.value(protocol(name)).toObject().value(configKey::lastConfig).toString().toUtf8()).object();
    return identityMatches(client) && client.value(configKey::clientPubKey) == m.value("clientPublicKey")
        && validSettings(publicSettings(client, name != "amnezia-wireguard"), name != "amnezia-wireguard");
}
QString updateNativeConfig(const QString &native, const QJsonObject &settings, bool awg)
{
    // Rewrite only server-controlled fields. Preserve Interface keys, addresses,
    // routing/DNS and all local fields; never accept script hooks from a feed.
    auto lines = native.split('\n'); QStringList result; QString section;
    const auto awgKeys = configKey::awgProtocolKeys();
    auto appendSettings = [&] {
        if (section == "Interface" && awg) {
            for (const auto &k : awgKeys) if (settings.contains(k)) result << k + " = " + settings.value(k).toString();
        } else if (section == "Peer") {
            const auto host = settings.value("hostName").toString();
            result << "PublicKey = " + settings.value("server_pub_key").toString();
            result << "Endpoint = " + (host.contains(':') ? "[" + host + "]" : host) + ":" + QString::number(settings.value("port").toInt());
        }
    };
    for (const auto &line : lines) {
        const auto trimmed = line.trimmed();
        if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
            appendSettings(); section = trimmed.mid(1, trimmed.size() - 2); result << line; continue;
        }
        const auto key = trimmed.section('=', 0, 0).trimmed();
        if ((section == "Interface" && awg && awgKeys.contains(key)) || (section == "Peer" && (key == "Endpoint" || key == "PublicKey"))) continue;
        result << line;
    }
    appendSettings(); return result.join('\n');
}
QByteArray readinessProof(const QJsonObject &profile, const QByteArray &envelope, qint64 now)
{
    QJsonObject verified;
    if (!apply(profile, envelope, now, verified)) return {};
    const auto signedEnvelope = QJsonDocument::fromJson(envelope).object();
    const auto payload = decode(signedEnvelope.value("payload"));
    const auto data = QJsonDocument::fromJson(payload).object();
    const auto challenge = decode(data.value("ackChallenge"), 32);
    if (challenge.isEmpty()) return {};
    const auto container = profile.value(configKey::containers).toArray().at(0).toObject();
    const auto name = container.value(configKey::container).toString();
    const auto client = QJsonDocument::fromJson(container.value(protocol(name)).toObject().value(configKey::lastConfig).toString().toUtf8()).object();
    const auto privateBytes = decode(client.value(configKey::clientPrivKey), 32);
    Key privateKey(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, reinterpret_cast<const unsigned char *>(privateBytes.constData()), privateBytes.size()), EVP_PKEY_free);
    Key peer(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, reinterpret_cast<const unsigned char *>(challenge.constData()), challenge.size()), EVP_PKEY_free);
    using Derivation = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    Derivation context(privateKey ? EVP_PKEY_CTX_new(privateKey.get(), nullptr) : nullptr, EVP_PKEY_CTX_free);
    unsigned char shared[32] = {}; size_t sharedSize = sizeof(shared);
    if (!privateKey || !peer || !context || EVP_PKEY_derive_init(context.get()) != 1 || EVP_PKEY_derive_set_peer(context.get(), peer.get()) != 1
        || EVP_PKEY_derive(context.get(), shared, &sharedSize) != 1 || sharedSize != 32) { OPENSSL_cleanse(shared, sizeof(shared)); return {}; }
    const unsigned char zero[32] = {};
    if (CRYPTO_memcmp(shared, zero, sizeof(shared)) == 0) { OPENSSL_cleanse(shared, sizeof(shared)); return {}; }
    QByteArray message("amnezia-awg3-ready-v1"); message.append('\0'); message.append(payload);
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned int digestSize = 0;
    const bool ok = HMAC(EVP_sha256(), shared, sizeof(shared), reinterpret_cast<const unsigned char *>(message.constData()), message.size(), digest, &digestSize) != nullptr && digestSize == 32;
    OPENSSL_cleanse(shared, sizeof(shared));
    return ok ? QByteArray(reinterpret_cast<const char *>(digest), digestSize) : QByteArray();
}
bool attachInvitation(const QJsonObject &profile, const QJsonObject &invitation, QJsonObject &updated)
{
    if (invitation.value("type") != "amnezia-update-invitation" || invitation.value("version").toDouble(-1) != 1
        || !profile.value(configKey::userName).toString().isEmpty() || !profile.value(configKey::password).toString().isEmpty()) return false;
    const auto incoming = invitation.value(metadataKey).toObject();
    const auto containers = profile.value(configKey::containers).toArray();
    if (containers.size() != 1) return false;
    const auto container = containers[0].toObject();
    const auto name = container.value(configKey::container).toString();
    if (name != incoming.value("container").toString() || !supported(name)) return false;
    const auto client = QJsonDocument::fromJson(container.value(protocol(name)).toObject().value(configKey::lastConfig).toString().toUtf8()).object();
    if (!identityMatches(client) || client.value(configKey::clientPubKey) != incoming.value("clientPublicKey")
        || client.value(configKey::serverPubKey) != invitation.value("existingServerPublicKey")) return false;
    auto metadata = invitationMetadata(incoming);
    for (const auto *key : { "id", "token", "container", "clientPublicKey" }) metadata[key] = incoming.value(key);
    metadata["revision"] = "0";
    const auto old = profile.value(metadataKey).toObject();
    auto oldIdentity = old;
    for (const auto *key : { "revision", "issuedAt", "settingsHash" }) oldIdentity.remove(key);
    auto newIdentity = metadata; newIdentity.remove("revision");
    bool same = true;
    for (auto it = newIdentity.begin(); it != newIdentity.end(); ++it) if (oldIdentity.value(it.key()) != it.value()) same = false;
    if (validateProfile(profile) && same) metadata = old;
    auto result = profile; result[metadataKey] = metadata;
    if (!validateProfile(result)) return false;
    updated = result; return true;
}
bool clientIdentityMatches(const QJsonObject &client) { return identityMatches(client); }
bool mergeServerSettings(const QJsonObject &profile, const QString &name, const QJsonObject &settings,
                         bool preserveManagementHost, QJsonObject &updated)
{
    const bool awg = name != "amnezia-wireguard";
    if (!supported(name) || !validSettings(settings, awg)) return false;
    auto containers = profile.value(configKey::containers).toArray();
    int found = -1;
    for (int i = 0; i < containers.size(); ++i) {
        if (containers[i].toObject().value(configKey::container).toString() == name) {
            if (found >= 0) return false;
            found = i;
        }
    }
    if (found < 0) return false;
    auto container = containers[found].toObject();
    const auto protoName = protocol(name); auto proto = container.value(protoName).toObject();
    auto client = QJsonDocument::fromJson(proto.value(configKey::lastConfig).toString().toUtf8()).object();
    if (!preserveManagementHost && !identityMatches(client)) return false;
    if (awg) for (const auto &k : configKey::awgProtocolKeys()) { proto.remove(k); client.remove(k); }
    for (auto it = settings.begin(); it != settings.end(); ++it) {
        if (!client.isEmpty()) client[it.key()] = it.value();
        if (awg && configKey::awgProtocolKeys().contains(it.key())) proto[it.key()] = it.value();
    }
    if (!client.isEmpty()) {
        client[configKey::config] = updateNativeConfig(client.value(configKey::config).toString(), settings, awg);
        proto[configKey::lastConfig] = QString::fromUtf8(QJsonDocument(client).toJson(QJsonDocument::Compact));
    }
    proto[configKey::port] = QString::number(settings.value("port").toInt());
    container[protoName] = proto; containers[found] = container;
    auto result = profile; result[configKey::containers] = containers;
    if (!preserveManagementHost) result[configKey::hostName] = settings.value("hostName");
    updated = result; return true;
}
bool mergePathProbe(const QJsonObject &profile, const QString &name, const QJsonValue &target, QJsonObject &updated)
{
    if (!supported(name) || !validPathProbe(target)) return false;
    auto containers = profile.value(configKey::containers).toArray(); int found = -1;
    for (int i = 0; i < containers.size(); ++i) {
        if (containers[i].toObject().value(configKey::container).toString() == name) {
            if (found >= 0) return false;
            found = i;
        }
    }
    if (found < 0) return false;
    auto container = containers[found].toObject(); const auto protoName = protocol(name);
    auto proto = container.value(protoName).toObject();
    auto client = QJsonDocument::fromJson(proto.value(configKey::lastConfig).toString().toUtf8()).object();
    if (!identityMatches(client)) return false;
    // Optional control metadata never widens application routes.
    if (usablePathProbe(target, client)) client["path_mtu_probe"] = target;
    else client.remove("path_mtu_probe");
    proto[configKey::lastConfig] = QString::fromUtf8(QJsonDocument(client).toJson(QJsonDocument::Compact));
    container[protoName] = proto; containers[found] = container;
    auto result = profile; result[configKey::containers] = containers; updated = result; return true;
}
bool apply(const QJsonObject &profile, const QByteArray &envelope, qint64 now, QJsonObject &updated)
{
    if (envelope.size() > 65536 || !validateProfile(profile)) return false;
    const auto m = profile.value(metadataKey).toObject();
    const auto e = QJsonDocument::fromJson(envelope).object();
    const auto bytes = decode(e.value("payload")); const auto sig = decode(e.value("signature"), 64); const auto pub = decode(m.value("publicKey"), 32);
    if (bytes.isEmpty() || sig.isEmpty()) return false;
    Key key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(pub.constData()), pub.size()), EVP_PKEY_free);
    Context ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!key || !ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1
        || EVP_DigestVerify(ctx.get(), reinterpret_cast<const unsigned char *>(sig.constData()), sig.size(),
                            reinterpret_cast<const unsigned char *>(bytes.constData()), bytes.size()) != 1) return false;
    const auto p = QJsonDocument::fromJson(bytes).object();
    const auto issued = p.value("issuedAt").toInteger(-1), expires = p.value("expiresAt").toInteger(-1);
    if (p.value("type") != "amnezia-connection-update" || p.value("version").toDouble(-1) != 1 || p.value("id") != m.value("id")
        || p.value("clientPublicKey") != m.value("clientPublicKey") || p.value("container") != m.value("container")
        || p.value("issuedAt").toDouble(-1) != static_cast<double>(issued)
        || p.value("expiresAt").toDouble(-1) != static_cast<double>(expires)
        || issued < 0 || issued > now + 300 || expires <= now || expires <= issued || expires - issued > 600
        || issued < m.value("issuedAt").toInteger(0)) return false;
    bool ok; const auto revisionText = p.value("revision").toString(); const auto revision = revisionText.toULongLong(&ok);
    if (!ok || revision == 0 || QString::number(revision) != revisionText || revision < m.value("revision").toString().toULongLong()) return false;
    const auto settings = p.value("settings").toObject(); const bool awg = m.value("container") != "amnezia-wireguard";
    if (!validSettings(settings, awg)) return false;
    const auto hash = QString::fromLatin1(QCryptographicHash::hash(QJsonDocument(settings).toJson(QJsonDocument::Compact), QCryptographicHash::Sha256).toHex());
    if (revisionText == m.value("revision").toString() && hash != m.value("settingsHash").toString()) return false;
    QJsonObject result;
    if (!mergeServerSettings(profile, m.value("container").toString(), settings, false, result)) return false;
    auto metadata = m;
    if (p.contains("pathMtuProbe")) {
        const auto target = p.value("pathMtuProbe");
        if (revisionText == m.value("revision").toString() && m.contains("pathMtuProbe") && target != m.value("pathMtuProbe")) return false;
        QJsonObject withProbe;
        if (!mergePathProbe(result, m.value("container").toString(), target, withProbe)) return false;
        result = withProbe;
        metadata["pathMtuProbe"] = target;
    }
    metadata["revision"] = revisionText; metadata["issuedAt"] = issued; metadata["settingsHash"] = hash;
    result[metadataKey] = metadata;
    updated = result; return true;
}
}
