#pragma once
#include <QJsonObject>
#include <QJsonDocument>
#include <QJsonArray>
#include <openssl/evp.h>
#include <openssl/x509.h>
namespace connectionUpdateTestFixtures {
QByteArray publicKey(const QByteArray &seed, int type)
{
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(type, nullptr, reinterpret_cast<const unsigned char *>(seed.constData()), seed.size());
    QByteArray pub(32, '\0'); size_t size = 32;
    if (key) EVP_PKEY_get_raw_public_key(key, reinterpret_cast<unsigned char *>(pub.data()), &size);
    EVP_PKEY_free(key); return pub;
}
QByteArray certificate()
{
    // Synthetic certificate used only to exercise bootstrap validation.
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(QByteArray(32, 'T').constData()), 32);
    X509 *cert = X509_new(); X509_set_version(cert, 2); ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), -3600); X509_gmtime_adj(X509_getm_notAfter(cert), 86400);
    X509_set_pubkey(cert, key); auto *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("updates.example.test"), -1, -1, 0);
    X509_set_issuer_name(cert, name); X509_sign(cert, key, nullptr);
    unsigned char *der = nullptr; const int size = i2d_X509(cert, &der);
    const QByteArray result(reinterpret_cast<char *>(der), size); OPENSSL_free(der); X509_free(cert); EVP_PKEY_free(key); return result;
}
const QByteArray seed(32, 'S'), deviceSeed(32, 'D');
QJsonObject settings(bool awg = false)
{
    QJsonObject s { { "hostName", "vpn2.example.test" }, { "port", 51821 }, { "server_pub_key", QString::fromLatin1(QByteArray(32, 'P').toBase64()) } };
    if (awg) { s["H1"] = "10-20"; s["H2"] = "30-40"; s["S3"] = "0"; s["HeaderProtectionKey"] = "aabbcc"; }
    return s;
}
QJsonObject profile(bool awg = false)
{
    const QString container = awg ? "amnezia-awg2" : "amnezia-wireguard", proto = awg ? "awg" : "wireguard";
    auto client = settings(); client["hostName"] = "vpn1.example.test";
    client["client_priv_key"] = QString::fromLatin1(deviceSeed.toBase64()); client["client_pub_key"] = QString::fromLatin1(publicKey(deviceSeed, EVP_PKEY_X25519).toBase64());
    client["client_ip"] = "10.8.0.2"; client["psk_key"] = "local-psk"; client["mtu"] = "1380";
    client["allowed_ips"] = QJsonArray { "0.0.0.0/0" }; client["persistent_keep_alive"] = "25";
    client["config"] = "[Interface]\nPrivateKey = local-device-key\nAddress = 10.8.0.2/32\nDNS = 192.0.2.53\nH1 = 1\n[Peer]\nPublicKey = old\nEndpoint = vpn1.example.test:51820\nAllowedIPs = 0.0.0.0/0\nPresharedKey = local-psk\n";
    QJsonObject metadata { { "version", 1 }, { "id", "0123456789abcdef0123456789abcdef" }, { "token", QString(43, 'x') },
        { "url", "https://updates.example.test:8443/v1/connections/0123456789abcdef0123456789abcdef" },
        { "certificate", QString::fromLatin1(certificate().toBase64()) }, { "publicKey", QString::fromLatin1(publicKey(seed, EVP_PKEY_ED25519).toBase64()) },
        { "revision", "0" }, { "container", container }, { "clientPublicKey", client.value("client_pub_key") } };
    return { { "format_version", 1 }, { "description", "My local name" }, { "hostName", "vpn1.example.test" }, { "dns1", "192.0.2.53" },
        { "splitTunnelSites", QJsonArray { "*.corp.example.test" } }, { "defaultContainer", container }, { "connectionUpdates", metadata },
        { "containers", QJsonArray { QJsonObject { { "container", container }, { proto, QJsonObject { { "port", "51820" }, { "last_config", QString::fromUtf8(QJsonDocument(client).toJson(QJsonDocument::Compact)) } } } } } } };
}
QJsonObject payload(const QJsonObject &p, bool awg = false)
{
    const auto m = p.value("connectionUpdates").toObject();
    return { { "type", "amnezia-connection-update" }, { "version", 1 }, { "id", m.value("id") }, { "container", m.value("container") },
        { "clientPublicKey", m.value("clientPublicKey") }, { "revision", "1" }, { "issuedAt", 2000000000 }, { "expiresAt", 2000000600 }, { "settings", settings(awg) } };
}
QByteArray sign(const QJsonObject &p)
{
    const auto bytes = QJsonDocument(p).toJson(QJsonDocument::Compact);
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(seed.constData()), seed.size());
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key);
    QByteArray sig(64, '\0'); size_t size = 64;
    EVP_DigestSign(ctx, reinterpret_cast<unsigned char *>(sig.data()), &size, reinterpret_cast<const unsigned char *>(bytes.constData()), bytes.size());
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key);
    return QJsonDocument(QJsonObject { { "payload", QString::fromLatin1(bytes.toBase64()) }, { "signature", QString::fromLatin1(sig.toBase64()) } }).toJson(QJsonDocument::Compact);
}
QJsonObject client(const QJsonObject &p, bool awg)
{
    return QJsonDocument::fromJson(p.value("containers").toArray()[0].toObject().value(awg ? "awg" : "wireguard").toObject().value("last_config").toString().toUtf8()).object();
}
}
