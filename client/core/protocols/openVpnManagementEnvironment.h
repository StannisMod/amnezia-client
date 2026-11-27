#ifndef OPENVPNMANAGEMENTENVIRONMENT_H
#define OPENVPNMANAGEMENTENVIRONMENT_H

#include <map>
#include <string>

// UPDOWN is a framed native environment, not a PUSH_REPLY log. Preserve values
// verbatim (domains and future DNS metadata may contain spaces or '=').
class OpenVpnManagementEnvironment {
public:
    enum class Result { Ignored, Pending, Complete, Invalid };

    Result consume(const std::string &line)
    {
        if (line == ">UPDOWN:UP" || line == ">UPDOWN:DOWN") {
            m_values.clear();
            m_up = line == ">UPDOWN:UP";
            m_active = true;
            m_bytes = 0;
            return Result::Pending;
        }
        const std::string prefix = ">UPDOWN:ENV,";
        if (line.compare(0, prefix.size(), prefix) != 0) {
            if (line.compare(0, 8, ">UPDOWN:") == 0) {
                reset();
                return Result::Invalid;
            }
            return Result::Ignored;
        }
        if (!m_active) {
            reset();
            return Result::Invalid;
        }
        const auto entry = line.substr(prefix.size());
        if (entry == "END") {
            m_active = false;
            return Result::Complete;
        }
        const auto separator = entry.find('=');
        // Bound privileged-peer data and reject ambiguous duplicate keys.
        if (separator == std::string::npos || separator == 0
            || entry.size() > 65536 || m_bytes + entry.size() > 1048576
            || m_values.size() >= 4096
            || !m_values.emplace(entry.substr(0, separator), entry.substr(separator + 1)).second) {
            reset();
            return Result::Invalid;
        }
        m_bytes += entry.size();
        return Result::Pending;
    }

    void reset()
    {
        m_values.clear();
        m_active = false;
        m_up = false;
        m_bytes = 0;
    }
    bool isUp() const { return m_up; }
    bool nativeRoutesSucceeded() const
    {
        const auto status = m_values.find("amnezia_native_routes");
        return !m_active && m_up && status != m_values.end() && status->second == "success";
    }
    const std::map<std::string, std::string> &values() const { return m_values; }

private:
    std::map<std::string, std::string> m_values;
    bool m_active = false;
    bool m_up = false;
    std::size_t m_bytes = 0;
};

#endif
