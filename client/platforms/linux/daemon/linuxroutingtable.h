#pragma once

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QSet>
#include <QMap>
#include <QStringList>
#include <QDebug>

// Own only an unused routing table and its lookup rules. The system's original
// tables and rules remain intact; RTN_THROW exclusions fall through to them.
class LinuxRoutingTable {
public:
    LinuxRoutingTable() = default;
    Q_DISABLE_COPY_MOVE(LinuxRoutingTable)
    ~LinuxRoutingTable()
    {
        for (auto it = m_priorities.cbegin(); it != m_priorities.cend(); ++it) {
            const QString family = it.key();
            run({family, "rule", "del", "priority", QString::number(it.value()),
                 "lookup", QString::number(m_table)});
            run({family, "route", "flush", "table", QString::number(m_table)});
        }
    }

    unsigned int table() const { return m_table; }
    bool hasFamily(const QString &family) const { return m_priorities.contains(family); }

    bool ensureFamily(const QString &family)
    {
        if (hasFamily(family)) return true;
        if (!m_table && !allocate()) return false;
        QJsonArray rules;
        if (!read({family, "-N", "-j", "rule", "show"}, rules)) return false;
        QSet<int> occupied;
        int mainPriority = -1;
        for (const auto &value : rules) {
            const auto rule = value.toObject();
            const int priority = rule.value("priority").toInt(-1);
            occupied.insert(priority);
            const auto table = rule.value("table");
            if (table.toString() == "main" || table.toInt() == 254) {
                if (mainPriority < 0 || priority < mainPriority) mainPriority = priority;
            }
        }
        // Insert immediately before the normal main-table lookup, after local
        // delivery and earlier administrator/VPN policy rules. Never replace one.
        int priority = mainPriority - 1;
        while (priority > 0 && occupied.contains(priority)) --priority;
        if (priority <= 0) {
            qWarning() << "Cannot place VPN lookup before the main routing rule";
            return false;
        }
        if (!run({family, "rule", "add", "priority", QString::number(priority),
                  "lookup", QString::number(m_table)})) return false;
        m_priorities.insert(family, priority);
        return true;
    }

private:
    static bool run(const QStringList &arguments, QByteArray *output = nullptr)
    {
        QProcess process;
        process.start("ip", arguments);
        if (!process.waitForStarted(5000) || !process.waitForFinished(5000)) {
            process.kill();
            process.waitForFinished(1000);
            qWarning() << "Routing command failed or timed out:" << arguments;
            return false;
        }
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
            qWarning() << "Routing command failed:" << arguments << process.readAllStandardError();
            return false;
        }
        if (output) *output = process.readAllStandardOutput();
        return true;
    }

    static bool read(const QStringList &arguments, QJsonArray &values)
    {
        QByteArray output;
        if (!run(arguments, &output)) return false;
        QJsonParseError error;
        const auto document = QJsonDocument::fromJson(output, &error);
        if (error.error != QJsonParseError::NoError || !document.isArray()) return false;
        values = document.array();
        return true;
    }

    bool allocate()
    {
        QSet<int> used;
        for (const auto &family : {QStringLiteral("-4"), QStringLiteral("-6")}) {
            for (const auto &command : {QStringLiteral("route"), QStringLiteral("rule")}) {
                QStringList arguments{family, "-N", "-j", command, "show"};
                if (command == "route") arguments << "table" << "all";
                QJsonArray values;
                if (!read(arguments, values)) return false;
                for (const auto &value : values) {
                    const auto table = value.toObject().value("table");
                    bool numeric = false;
                    int number = table.toString().toInt(&numeric);
                    if (!numeric) number = table.toInt(-1);
                    if (number >= 0) used.insert(number);
                }
            }
        }
        for (int candidate = 51820; candidate < 51920; ++candidate) {
            if (!used.contains(candidate)) {
                m_table = candidate;
                return true;
            }
        }
        qWarning() << "No unused routing table available for VPN";
        return false;
    }

    unsigned int m_table = 0;
    QMap<QString, int> m_priorities;
};
