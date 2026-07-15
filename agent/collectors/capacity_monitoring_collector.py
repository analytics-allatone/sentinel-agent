"""
Resource / capacity collector  (production, lightweight, cross-platform).

Emits periodic 'resource_snapshot' events with CPU, memory, disk, network
bandwidth, connection and disk-IO metrics, plus the agent's own footprint.
Trends / averages / peaks are derived later in SQL over these rows — this
collector only produces accurate point-in-time snapshots.

Accuracy model
--------------
Rate metrics (bandwidth, disk IO, CPU%) are DELTAS and need two samples
spaced by a real interval. So the collector primes all counters once, then
waits a full `poll_interval` BEFORE emitting the first snapshot. This is why
the first sample is already correct instead of showing 0% CPU or absurd
TB/s rates.

Lightweight model
-----------------
Cheap metrics (cpu/mem/disk-usage/io/net counters) run every poll. The two
expensive calls — enumerating all sockets and iterating every process — run
only every `heavy_every` polls. Set heavy_every=1 to collect them every time.

Cross-platform: Windows + Linux. OS branches are isolated to disk root,
open-handle name, and load average (real on POSIX, omitted on Windows).
"""

import os
import time
import platform
import threading
from datetime import datetime, timezone
import psutil


_IS_WINDOWS = platform.system() == "Windows"
_DISK_ROOT = "C:\\" if _IS_WINDOWS else "/"

# read-only / pseudo filesystems that always report 100% — excluded so they
# don't raise false "disk critical" alerts.
_PSEUDO_FSTYPES = {
    "squashfs", "iso9660", "overlay", "tmpfs", "devtmpfs",
    "ramfs", "aufs", "cgroup", "cgroup2", "proc", "sysfs", "fuse.snapfuse",
}

# remote-port -> protocol bucket (approximation, fine for a breakdown chart)
_PORT_PROTOCOL = {
    443: "HTTPS", 80: "HTTP", 53: "DNS", 22: "SSH", 3389: "RDP",
    5432: "PostgreSQL", 3306: "MySQL", 6379: "Redis", 1883: "MQTT", 8883: "MQTT",
}

_MB = 1024 * 1024
_GB = 1024 ** 3


class ResourceCollector:
    def __init__(
        self,
        dispatch,
        machine_info,
        poll_interval: float = 5.0,
        heavy_every: int = 1,          # run connections+process scan every Nth poll
        cpu_warn: float = 70.0,
        cpu_critical: float = 85.0,
        memory_warn: float = 70.0,
        memory_critical: float = 85.0,
        disk_warn: float = 75.0,
        disk_critical: float = 90.0,
        collect_connections: bool = True,
        collect_top_process: bool = True,
    ):
        self.dispatch = dispatch
        self.machine_info = machine_info
        self.poll_interval = poll_interval
        self.heavy_every = max(1, int(heavy_every))

        self.cpu_warn, self.cpu_critical = cpu_warn, cpu_critical
        self.memory_warn, self.memory_critical = memory_warn, memory_critical
        self.disk_warn, self.disk_critical = disk_warn, disk_critical

        self.collect_connections = collect_connections
        self.collect_top_process = collect_top_process

        self._proc = psutil.Process(os.getpid())
        self._cpu_count = psutil.cpu_count() or 1
        self._thread = None
        self._stop = threading.Event()
        self._cycle = 0

        # delta baselines
        self._last_net = None
        self._last_disk = None
        self._last_ts = None

    # ---- lifecycle -------------------------------------------------------

    def start(self):
        self._prime()
        self._thread = threading.Thread(
            target=self._run, name="resource-collector", daemon=True
        )
        self._thread.start()

    def _prime(self):
        """Establish all delta baselines so the first emitted sample is real."""
        psutil.cpu_percent(interval=None)              # system CPU baseline
        psutil.cpu_percent(interval=None, percpu=True)
        self._proc.cpu_percent(interval=None)          # agent CPU baseline
        if self.collect_top_process:
            for p in psutil.process_iter():            # per-process CPU baseline
                try:
                    p.cpu_percent(None)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        self._last_net = psutil.net_io_counters()
        self._last_disk = psutil.disk_io_counters()
        self._last_ts = time.monotonic()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.poll_interval + 2)

    def _run(self):
        # wait a full interval BEFORE the first read so deltas span real time
        while not self._stop.wait(self.poll_interval):
            try:
                event = self._collect()
                self.dispatch(event, self.machine_info)
            except Exception as e:
                self.dispatch(
                    {"category": "resource", "action": "resource_error",
                     "severity": "warning", "message": f"resource collect failed: {e}"},
                    self.machine_info,
                )

    # ---- collection ------------------------------------------------------

    def _collect(self) -> dict:
        self._cycle += 1
        heavy = (self._cycle % self.heavy_every == 0)

        now = time.monotonic()
        elapsed = max(now - self._last_ts, 1e-6)

        # CPU
        cpu_percent = psutil.cpu_percent(interval=None)
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        load1, load5, load15 = self._loadavg()

        # Memory
        vm = psutil.virtual_memory()
        sm = psutil.swap_memory()

        # Disk usage (all real partitions)
        partitions = self._disk_metrics()
        primary = next((p for p in partitions if p["mountpoint"] == _DISK_ROOT),
                       partitions[0] if partitions else None)
        disk_percent_max = max((p["percent"] for p in partitions), default=0.0)

        # Network + disk IO rates (guarded deltas)
        net = psutil.net_io_counters()
        bandwidth_mbps = self._rate(
            (net.bytes_sent + net.bytes_recv),
            (self._last_net.bytes_sent + self._last_net.bytes_recv), elapsed)

        dio = psutil.disk_io_counters()
        disk_write_mbps = disk_read_mbps = None
        write_total = read_total = None
        if dio and self._last_disk:
            disk_write_mbps = self._rate(dio.write_bytes, self._last_disk.write_bytes, elapsed)
            disk_read_mbps = self._rate(dio.read_bytes, self._last_disk.read_bytes, elapsed)
            write_total, read_total = dio.write_bytes, dio.read_bytes

        # advance baselines
        self._last_net, self._last_disk, self._last_ts = net, dio, now

        # heavy metrics (only every Nth cycle)
        active_connections, protocol_counts = None, None
        top_cpu = top_mem = None
        if heavy and self.collect_connections:
            active_connections, protocol_counts = self._connections()
        if heavy and self.collect_top_process:
            top_cpu, top_mem = self._top_processes()

        # agent self
        with self._proc.oneshot():
            rss = self._proc.memory_info().rss
            agent = {
                "agent_cpu_percent": round(self._proc.cpu_percent(interval=None) / self._cpu_count, 2),
                "agent_rss_mb": round(rss / _MB, 2),
                "agent_num_threads": self._proc.num_threads(),
                "agent_open_files": self._open_handle_count(),
            }

        severity, reason = self._severity(cpu_percent, vm.percent, disk_percent_max)

        final_data = {
            "category": "resource",
            "action": "resource_snapshot",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),

            "cpu_percent": cpu_percent,
            "cpu_per_core": per_core,
            "cpu_count": self._cpu_count,

            "memory_percent": vm.percent,
            "memory_used_mb": round(vm.used / _MB, 2),
            "memory_total_mb": round(vm.total / _MB, 2),
            "memory_available_mb": round(vm.available / _MB, 2),
            "swap_percent": sm.percent,

            "disk_percent": primary["percent"] if primary else None,
            "disk_used_gb": primary["used_gb"] if primary else None,
            "disk_total_gb": primary["total_gb"] if primary else None,
            "disk_free_gb": primary["free_gb"] if primary else None,
            "disk_percent_max": disk_percent_max,
            "disk_partitions": partitions,

            "bandwidth_mbps": bandwidth_mbps,
            "bytes_sent_total": net.bytes_sent,
            "bytes_recv_total": net.bytes_recv,
            "active_connections": active_connections,
            "connections_by_protocol": protocol_counts,

            "disk_write_mbps": disk_write_mbps,
            "disk_read_mbps": disk_read_mbps,
            "disk_write_bytes_total": write_total,
            "disk_read_bytes_total": read_total,

            "top_cpu_process": top_cpu,
            "top_memory_process": top_mem,

            **agent,
        }
        return final_data
    # ---- helpers ---------------------------------------------------------

    @staticmethod
    def _rate(cur, prev, elapsed):
        """MB/s between two cumulative counters; None if the counter reset."""
        delta = cur - prev
        if delta < 0:          # NIC/disk removed or counter wrapped
            return None
        return round(delta / 1e6 / elapsed, 3)

    def _loadavg(self):
        # real kernel value on POSIX only; Windows' is simulated + needs warmup
        if _IS_WINDOWS:
            return None, None, None
        try:
            a, b, c = psutil.getloadavg()
            return round(a, 2), round(b, 2), round(c, 2)
        except (OSError, AttributeError):
            return None, None, None

    def _connections(self):
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return None, None
        counts = {}
        for c in conns:
            if c.raddr:
                proto = _PORT_PROTOCOL.get(c.raddr.port, "Other")
                counts[proto] = counts.get(proto, 0) + 1
        return len(conns), counts

    def _top_processes(self):
        best_c = best_m = -1.0
        top_cpu = top_mem = None
        for p in psutil.process_iter(["pid", "name"]):
            try:
                c = p.cpu_percent(None)          # since last call (primed)
                m = p.memory_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if c > best_c:
                best_c = c
                top_cpu = {"pid": p.info["pid"], "name": p.info["name"],
                           "cpu_percent": round(c, 1)}   # relative to one core
            if m > best_m:
                best_m = m
                top_mem = {"pid": p.info["pid"], "name": p.info["name"],
                           "memory_percent": round(m, 1)}
        return top_cpu, top_mem

    def _disk_metrics(self):
        out = []
        for part in psutil.disk_partitions(all=False):
            if _IS_WINDOWS and ("cdrom" in part.opts or not part.fstype):
                continue
            if part.fstype.lower() in _PSEUDO_FSTYPES:
                continue
            try:
                u = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                continue
            out.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "percent": u.percent,
                "used_gb": round(u.used / _GB, 2),
                "total_gb": round(u.total / _GB, 2),
                "free_gb": round(u.free / _GB, 2),
            })
        return out

    def _open_handle_count(self):
        try:
            return self._proc.num_handles() if _IS_WINDOWS else self._proc.num_fds()
        except (psutil.AccessDenied, AttributeError):
            return None

    def _severity(self, cpu, mem, disk):
        reasons, level = [], "info"

        def bump(cur, warn, crit, label, val):
            if val >= crit:
                reasons.append(f"{label} {val:.0f}% >= critical {crit:.0f}%")
                return "critical"
            if val >= warn:
                reasons.append(f"{label} {val:.0f}% >= warn {warn:.0f}%")
                return "warning" if cur != "critical" else cur
            return cur

        level = bump(level, self.cpu_warn, self.cpu_critical, "CPU", cpu)
        level = bump(level, self.memory_warn, self.memory_critical, "Memory", mem)
        level = bump(level, self.disk_warn, self.disk_critical, "Disk", disk)
        return level, ("; ".join(reasons) if reasons else None)