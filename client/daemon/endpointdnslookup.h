#ifndef ENDPOINTDNSLOOKUP_H
#define ENDPOINTDNSLOOKUP_H

#include <QHostAddress>
#include <QObject>
#include <QRandomGenerator>
#include <QSet>
#include <QTimer>
#include <QUdpSocket>
#include <QUrl>
#include <functional>

// A private DNS socket in the privileged service. Its temporary firewall rule
// matches this bound source port, resolver IP and UDP/53, never general DNS or
// application traffic. Destruction/cancellation removes the rule before the
// socket releases its port. No system DNS cache or tunnel resolver is involved.
class EndpointDnsLookup : public QObject
{
public:
    using Firewall = std::function<bool(quint16, const QHostAddress &, bool)>;
    using Completion = std::function<void(QList<QHostAddress>)>;
    explicit EndpointDnsLookup(QObject *parent = nullptr) : QObject(parent) {
        m_deadline.setSingleShot(true);
        connect(&m_deadline, &QTimer::timeout, this, [this] { finish(); });
        connect(&m_socket, &QUdpSocket::readyRead, this, [this] { receive(); });
    }
    ~EndpointDnsLookup() override { cancel(); }
    void cancel() {
        m_deadline.stop();
        m_complete = nullptr;
        if (m_open && m_firewall) m_firewall(m_socket.localPort(), m_resolver, false);
        m_open = false;
        m_socket.close();
    }
    void start(const QString &host, const QHostAddress &resolver, Firewall firewall,
               Completion complete, quint16 dnsPort = 53, int timeoutMs = 8000) {
        cancel();
        m_firewall = std::move(firewall);
        m_complete = std::move(complete);
        m_resolver = resolver;
        m_port = dnsPort;
        m_addresses.clear(); m_replied.clear(); m_queries.clear();
        const auto ace = QUrl::toAce(host).toLower();
        QByteArray name;
        for (const auto &label : ace.split('.')) {
            if (label.isEmpty() || label.size() > 63) { finish(); return; }
            for (char c : label) if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-') { finish(); return; }
            name.append(char(label.size())); name.append(label);
        }
        if (ace.size() > 253 || name.isEmpty()) { finish(); return; }
        name.append(char(0));
        if (!m_socket.bind(QHostAddress::AnyIPv4, 0, QUdpSocket::DontShareAddress)) { finish(); return; }
        // On partial firewall failure attempt cleanup while still owning the port.
        m_open = true;
        if (!m_firewall || !m_firewall(m_socket.localPort(), resolver, true)) { finish(); return; }
        quint16 id = quint16(QRandomGenerator::system()->generate());
        for (quint16 type : {quint16(1), quint16(28)}) {
            QByteArray query;
            append16(query, id++); append16(query, 0x0100); append16(query, 1);
            append16(query, 0); append16(query, 0); append16(query, 0);
            query.append(name); append16(query, type); append16(query, 1);
            m_queries.append(query);
            m_socket.writeDatagram(query, resolver, dnsPort);
        }
        m_deadline.start(timeoutMs);
    }

private:
    static void append16(QByteArray &data, quint16 n) { data.append(char(n >> 8)); data.append(char(n)); }
    static quint16 read16(const QByteArray &data, int offset) {
        return (quint8(data[offset]) << 8) | quint8(data[offset + 1]);
    }
    static bool readName(const QByteArray &data, int &offset, QByteArray &name) {
        int cursor = offset, resume = -1;
        name.clear();
        for (int steps = 0; steps < 128; ++steps) {
            if (cursor >= data.size()) return false;
            const auto n = quint8(data[cursor++]);
            if (n == 0) { offset = resume < 0 ? cursor : resume; return true; }
            if ((n & 0xc0) == 0xc0) {
                if (cursor >= data.size()) return false;
                if (resume < 0) resume = cursor + 1;
                cursor = ((n & 63) << 8) | quint8(data[cursor]);
            } else {
                if (n > 63 || cursor + n > data.size() || name.size() + n > 253) return false;
                if (!name.isEmpty()) name.append('.');
                name.append(data.mid(cursor, n).toLower()); cursor += n;
            }
        }
        return false; // Compression loop or excessive labels.
    }
    void receive() {
        while (m_socket.hasPendingDatagrams()) {
            QHostAddress sender; quint16 port = 0;
            QByteArray packet(4096, char(0));
            const auto size = m_socket.readDatagram(packet.data(), packet.size(), &sender, &port);
            if (!m_complete || sender != m_resolver || port != m_port || size < 12) continue;
            packet.resize(int(size));
            int queryIndex = -1;
            for (int i = 0; i < m_queries.size(); ++i)
                if (read16(packet, 0) == read16(m_queries[i], 0)) queryIndex = i;
            if (queryIndex < 0 || m_replied.contains(queryIndex) || read16(packet, 4) != 1
                || (read16(packet, 2) & 0xfa0f) != 0x8000) continue;
            int offset = 12; QByteArray question;
            if (!readName(packet, offset, question) || offset + 4 > packet.size()) continue;
            const auto &query = m_queries[queryIndex];
            int qOffset = 12; QByteArray expected;
            if (!readName(query, qOffset, expected) || question != expected
                || packet.mid(offset, 4) != query.mid(qOffset, 4)) continue;
            offset += 4;
            struct Record { QByteArray owner, alias; QHostAddress address; };
            QList<Record> records;
            bool valid = true;
            const int count = read16(packet, 6);
            if (count > 128) continue;
            for (int i = 0; i < count; ++i) {
                Record record;
                if (!readName(packet, offset, record.owner) || offset + 10 > packet.size()) { valid = false; break; }
                const auto type = read16(packet, offset), cls = read16(packet, offset + 2), length = read16(packet, offset + 8);
                offset += 10;
                if (offset + length > packet.size()) { valid = false; break; }
                if (cls == 1) {
                    if (type == 1 && length == 4) {
                        const quint32 ip = (quint32(read16(packet, offset)) << 16) | read16(packet, offset + 2);
                        record.address = QHostAddress(ip);
                    } else if (type == 28 && length == 16) {
                        Q_IPV6ADDR ip;
                        for (int j = 0; j < 16; ++j) ip[j] = quint8(packet[offset + j]);
                        record.address = QHostAddress(ip);
                    } else if (type == 5) {
                        int aliasOffset = offset;
                        if (!readName(packet, aliasOffset, record.alias) || aliasOffset != offset + length) { valid = false; break; }
                    }
                }
                records.append(record); offset += length;
            }
            if (!valid) continue;
            QSet<QByteArray> owners{question};
            for (int i = 0; i < records.size(); ++i)
                for (const auto &record : records)
                    if (owners.contains(record.owner) && !record.alias.isEmpty()) owners.insert(record.alias);
            for (const auto &record : records)
                if (owners.contains(record.owner) && !record.address.isNull() && !m_addresses.contains(record.address)) m_addresses.append(record.address);
            m_replied.insert(queryIndex);
            if (m_replied.size() == 2) { finish(); return; }
        }
    }
    void finish() {
        const auto complete = std::move(m_complete);
        const auto addresses = m_addresses;
        cancel();
        if (complete) complete(addresses);
    }
    QUdpSocket m_socket;
    QTimer m_deadline;
    QHostAddress m_resolver;
    quint16 m_port = 53;
    bool m_open = false;
    Firewall m_firewall;
    Completion m_complete;
    QList<QByteArray> m_queries;
    QSet<int> m_replied;
    QList<QHostAddress> m_addresses;
};
#endif
