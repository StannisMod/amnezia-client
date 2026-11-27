#ifndef OPENVPNDNSSCRIPTS_H
#define OPENVPNDNSSCRIPTS_H

#include <QRegularExpression>
#include <QString>
#include <QStringList>

namespace openVpnNativeDns {
inline QString withoutBundledResolverScript(QString config, const QString &script)
{
    const auto path = QRegularExpression::escape(script);
    const QRegularExpression writer("^[\\t ]*(?:up|down)[\\t ]+(?:" + path + "|\"" + path
        + "\")[\\t ]*\\r?$");
    static const QRegularExpression opening(
        "^(?:<([A-Za-z0-9_-]+)>|\"<([A-Za-z0-9_-]+)>\"|'<([A-Za-z0-9_-]+)>')[\\t ]*(?:[#;].*)?$");
    auto lines = config.split('\n', Qt::KeepEmptyParts);
    QString inlineTag;
    for (auto &line : lines) {
        const auto text = line.trimmed();
        if (!inlineTag.isEmpty()) {
            // Match pinned options_parse.c: leading whitespace is ignored and
            // a literal closing-tag prefix terminates inline data.
            if (text.startsWith("</" + inlineTag + ">")) inlineTag.clear();
            continue;
        }
        const auto match = opening.match(text);
        if (match.hasMatch()) {
            for (int i = 1; i <= 3; ++i)
                if (!match.captured(i).isEmpty()) { inlineTag = match.captured(i); break; }
        } else if (writer.match(line).hasMatch()) line.clear();
    }
    return lines.join('\n');
}
}

#endif
