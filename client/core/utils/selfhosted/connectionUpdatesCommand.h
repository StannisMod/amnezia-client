#ifndef CONNECTIONUPDATESCOMMAND_H
#define CONNECTIONUPDATESCOMMAND_H
#include <QString>

namespace amnezia::connectionUpdates {
// Resolve the immutable image of the owned service, including after migration.
// A private untagged snapshot must never turn administration into a registry pull.
inline QString adminCommandScript(const QString &action, const QString &path)
{
    if (action != "issue" && action != "publish" && action != "publish-live" && action != "revoke" && action != "info") return {};
    QString quoted = path; quoted.replace("'", "'\\''"); quoted = "'"+quoted+"/request.json'";
    return "chmod 600 "+quoted+
        " && delivery_id=$(sudo docker inspect -f '{{.Id}}' amnezia-connection-updates)"
        " && printf '%s\\n' \"$delivery_id\" | grep -Eq '^[a-f0-9]{64}$'"
        " && test \"$(sudo docker inspect -f '{{index .Config.Labels \"org.amnezia.connection-updates\"}}' \"$delivery_id\")\" = 1"
        " && delivery_image=$(sudo docker inspect -f '{{.Image}}' \"$delivery_id\")"
        " && printf '%s\\n' \"$delivery_image\" | grep -Eq '^sha256:[a-f0-9]{64}$'"
        " && sudo docker run --pull=never --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges"
        " --mount type=volume,source=amnezia-connection-updates-state,target=/data \"$delivery_image\" "+action+" < "+quoted;
}
}
#endif
