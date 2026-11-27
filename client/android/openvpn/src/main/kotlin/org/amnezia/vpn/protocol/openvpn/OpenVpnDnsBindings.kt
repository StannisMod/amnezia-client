package org.amnezia.vpn.protocol.openvpn

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import org.amnezia.vpn.protocol.NativeDnsBinding

/** Numeric native handles retain exact resolver occurrences, never a pool. */
internal class OpenVpnDnsBindings {
    internal class Generation(
        private val bind: (NativeDnsBinding, Int) -> Boolean,
        private val failed: () -> Unit,
        private val retired: () -> Unit
    ) {
        private val failure = AtomicBoolean(false)
        private val retirement = AtomicBoolean(false)
        private val handles = ConcurrentHashMap.newKeySet<Long>()
        private val live: Boolean get() = !failure.get() && !retirement.get()

        fun admit(handle: Long) {
            check(live) { "OpenVPN DNS generation is already retiring" }
            check(handles.add(handle)) { "Duplicate OpenVPN DNS handle" }
        }
        fun bind(binding: NativeDnsBinding, fd: Int): Boolean {
            if (!live || fd < 0) return false
            return try { bind.invoke(binding, fd) && live } catch (_: Exception) { false }
        }
        fun fail() {
            if (!retirement.get() && failure.compareAndSet(false, true)) failed()
        }
        fun nativeRetired(handle: Long) {
            if (handles.remove(handle) && handles.isEmpty()) retireConfirmed()
        }
        fun retireConfirmed() {
            if (retirement.compareAndSet(false, true)) {
                handles.clear()
                retired()
            }
        }
    }

    private data class Entry(val generation: Generation, val binding: NativeDnsBinding)
    private val entries = ConcurrentHashMap<Long, Entry>()
    private val highestHandle = AtomicLong(0)

    fun register(handle: Long, generation: Generation, binding: NativeDnsBinding) {
        check(handle > 0) { "Native OpenVPN DNS preparation failed" }
        while (true) {
            val before = highestHandle.get()
            check(handle > before) { "Stale or reused OpenVPN DNS handle" }
            if (highestHandle.compareAndSet(before, handle)) break
        }
        generation.admit(handle)
        check(entries.putIfAbsent(handle, Entry(generation, binding)) == null)
    }

    fun bind(handle: Long, fd: Int): Boolean =
        entries[handle]?.let { it.generation.bind(it.binding, fd) } ?: false

    fun failed(handle: Long) { entries[handle]?.generation?.fail() }

    /** Called only AFTER native packet, exchange and binding callbacks join. */
    fun retired(handle: Long) {
        val entry = entries.remove(handle) ?: return
        entry.generation.nativeRetired(handle)
    }

    /** The caller must first obtain confirmed amnezia_dns_stop() return. */
    fun allNativeJoined() {
        val generations = entries.values.map { it.generation }.distinct()
        entries.clear()
        generations.forEach { it.retireConfirmed() }
    }
    val hasNativeBindings: Boolean get() = entries.isNotEmpty()
}
