#ifndef DNSWIREFIXTURE_H
#define DNSWIREFIXTURE_H
#include <QHostAddress>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QNetworkInterface>
#include <QElapsedTimer>

namespace DnsWireFixture {
inline QByteArray query(int type)
{
    auto data = QByteArray::fromHex("123401000001000000000000076578616d706c6504746573740000000001");
    data[data.size() - 3] = char(type);
    return data;
}
inline bool reply(const QHostAddress &endpoint, bool tcp, int type, int rcode, bool expectedAnswer = false,
                  QString *diagnostic = nullptr)
{
    constexpr int clientWaitMs = 1000;
    QElapsedTimer elapsed;
    elapsed.start();
    const auto fail = [&](const QString &reason) {
        if (diagnostic) *diagnostic = reason + " elapsed_ms=" + QString::number(elapsed.elapsed());
        return false;
    };
    const auto request = query(type);
    QByteArray answer;
    if (tcp) {
        QTcpSocket socket;
        socket.connectToHost(endpoint, 53);
        if (!socket.waitForConnected(clientWaitMs)) return fail("TCP connect: " + socket.errorString());
        QByteArray frame;
        frame.append(char(request.size() >> 8));
        frame.append(char(request.size()));
        frame.append(request);
        if (socket.write(frame) != frame.size() || !socket.waitForBytesWritten(clientWaitMs))
            return fail("TCP write: " + socket.errorString());
        while (socket.bytesAvailable() < 2)
            if (!socket.waitForReadyRead(clientWaitMs)) return fail("TCP header: " + socket.errorString());
        const auto length = socket.read(2);
        const int size = (quint8(length[0]) << 8) | quint8(length[1]);
        while (answer.size() < size) {
            answer += socket.read(size - answer.size());
            if (answer.size() < size && !socket.waitForReadyRead(clientWaitMs))
                return fail("TCP body: " + socket.errorString());
        }
    } else {
        QUdpSocket socket;
        if (socket.writeDatagram(request, endpoint, 53) != request.size() || !socket.waitForReadyRead(clientWaitMs))
            return fail("UDP reply: " + socket.errorString());
        answer.resize(socket.pendingDatagramSize());
        if (socket.readDatagram(answer.data(), answer.size()) != answer.size())
            return fail("UDP read: " + socket.errorString());
    }
    const bool correct = answer.size() >= 12 && quint8(answer[0]) == 0x12 && quint8(answer[1]) == 0x34
        && (quint8(answer[2]) & 0x80) && (quint8(answer[3]) & 15) == rcode
        && answer[6] == 0 && answer[7] == (expectedAnswer ? 1 : 0)
        && (expectedAnswer ? bool(quint8(answer[3]) & 0x20) : !(quint8(answer[3]) & 0x20))
        && (!expectedAnswer || answer.right(4) == QByteArray::fromHex("c6336402"));
    if (!correct) return fail("DNS wire mismatch: " + QString::fromLatin1(answer.left(512).toHex()));
    if (diagnostic) *diagnostic = "DNS reply elapsed_ms=" + QString::number(elapsed.elapsed());
    return true;
}
inline bool present(const QHostAddress &ip)
{
    for (const auto &iface : QNetworkInterface::allInterfaces())
        for (const auto &entry : iface.addressEntries())
            if (entry.ip() == ip) return true;
    return false;
}
}
#endif
