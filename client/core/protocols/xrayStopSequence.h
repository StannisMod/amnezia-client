#pragma once

#include <array>
#include <functional>

// A failed phase retains ownership and is retryable. In particular, no native
// resource or protection may be removed while DNS restoration is uncertain.
class XrayStopSequence
{
public:
    using Operation = std::function<bool()>;
    bool run(const std::array<Operation, 5> &operations)
    {
        if (m_running) return false;
        m_running = true;
        while (m_phase < operations.size()) {
            if (!operations[m_phase]()) {
                m_running = false;
                return false;
            }
            ++m_phase;
        }
        m_running = false;
        return true;
    }
    bool complete() const { return m_phase == 5; }
    void reset() { m_phase = 0; }
private:
    unsigned m_phase = 0;
    bool m_running = false;
};
