"""
Resource / capacity collector.

Emits periodic 'resource_snapshot' events carrying CPU, memory, disk,
network bandwidth, connection, disk-IO and agent self-metrics. Trends,
averages and peaks are meant to be derived later via SQL over these
snapshots — this collector only produces the raw point-in-time rows.

Cross-platform: works on Windows and Linux. OS branches are isolated to
three spots (disk root, open-file handle name, load average fallback).

Interface matches the other collectors:
    ResourceCollector(dispatch, machine_info, poll_interval=..., ...).start()/.stop()
"""

import os
import time
import platform
import threading

import psutil


_IS_WINDOWS = platform.system() == "Windows"
_DISK_ROOT = "C:\\" if _IS_WINDOWS else "/"

# read-only / pseudo filesystems that always report 100% full — exclude from
# disk metrics so they don't trigger false "disk critical" alerts.
_PSEUDO_FSTYPES = {
    "squashfs", "iso9660", "overlay", "tmpfs", "devtmpfs",
    "ramfs", "aufs", "cgroup", "proc", "sysfs",
}

# remote-port -> protocol bucket (approximation; good enough for a breakdown)
_PORT_PROTOCOL = {
    443: "HTTPS",
    80: "HTTP",
    53: "DNS",
    22: "SSH",
    3389: "RDP",
    5432: "PostgreSQL",
    3306: "MySQL",
    6379: "Redis",
    1883: "MQTT",
    8883: "MQTT",
}


class ResourceCollector:
    def __init__(
        self,
        dispatch,
        machine_info,
        poll_interval: float = 30.0,
        # threshold config -> drives event severity
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

        self.cpu_warn = cpu_warn
        self.cpu_critical = cpu_critical
        self.memory_warn = memory_warn
        self.memory_critical = memory_critical
        self.disk_warn = disk_warn
        self.disk_critical = disk_critical

        self.collect_connections = collect_connections
        self.collect_top_process = collect_top_process

        self._proc = psutil.Process(os.getpid())
        self._thread = None
        self._stop = threading.Event()

        # state for delta-based metrics (bandwidth, disk io)
        self._last_net = None
        self._last_disk = None
        self._last_ts = None

    # ---- lifecycle -------------------------------------------------------

    def start(self):
        # prime the CPU counters so the first real reading isn't 0.0
        psutil.cpu_percent(interval=None)
        self._proc.cpu_percent(interval=None)
        self._last_net = psutil.net_io_counters()
        self._last_disk = psutil.disk_io_counters()
        self._last_ts = time.monotonic()

        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.poll_interval + 2)

    def _run(self):
        while not self._stop.is_set():
            try:
                event = self._collect()
                self.dispatch(event, self.machine_info)
            except Exception as e:
                # never let the collector thread die on a transient error
                self.dispatch(
                    {
                        "category": "resource",
                        "action": "resource_error",
                        "severity": "warning",
                        "message": f"resource collection failed: {e}",
                    },
                    self.machine_info,
                )
            self._stop.wait(self.poll_interval)

    # ---- collection ------------------------------------------------------

    def _collect(self) -> dict:
        now = time.monotonic()
        elapsed = max(now - self._last_ts, 1e-6)

        # --- CPU ---
        cpu_percent = psutil.cpu_percent(interval=None)
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        try:
            load1, load5, load15 = psutil.getloadavg()
        except (OSError, AttributeError):
            load1 = load5 = load15 = None

        # --- Memory ---
        vm = psutil.virtual_memory()
        sm = psutil.swap_memory()

        # --- Disk usage (all partitions, not just the system drive) ---
        partitions = self._disk_metrics()
        # primary = the system/root drive, for the single-value gauge
        primary = next(
            (p for p in partitions if p["mountpoint"] == _DISK_ROOT),
            partitions[0] if partitions else None,
        )
        # worst partition drives alerting (a full D:\ or /data still matters)
        disk_percent_max = max((p["percent"] for p in partitions), default=0.0)

        # --- Network bandwidth (delta) ---
        net = psutil.net_io_counters()
        sent_delta = net.bytes_sent - self._last_net.bytes_sent
        recv_delta = net.bytes_recv - self._last_net.bytes_recv
        bandwidth_mbps = round((sent_delta + recv_delta) / 1e6 / elapsed, 4)

        # --- Disk IO (delta) ---
        disk_write_mbps = disk_read_mbps = None
        write_bytes_total = read_bytes_total = None
        dio = psutil.disk_io_counters()
        if dio and self._last_disk:
            write_delta = dio.write_bytes - self._last_disk.write_bytes
            read_delta = dio.read_bytes - self._last_disk.read_bytes
            disk_write_mbps = round(write_delta / 1e6 / elapsed, 4)
            disk_read_mbps = round(read_delta / 1e6 / elapsed, 4)
            write_bytes_total = dio.write_bytes
            read_bytes_total = dio.read_bytes

        # advance delta state
        self._last_net = net
        self._last_disk = dio
        self._last_ts = now

        # --- Connections + protocol breakdown ---
        active_connections = None
        protocol_counts = {}
        if self.collect_connections:
            try:
                conns = psutil.net_connections(kind="inet")
                active_connections = len(conns)
                for c in conns:
                    if c.raddr and len(c.raddr) >= 2:
                        proto = _PORT_PROTOCOL.get(c.raddr.port, "Other")
                        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            except (psutil.AccessDenied, PermissionError):
                # needs root/admin on some systems; degrade gracefully
                active_connections = None

        # --- Top CPU / memory process ---
        top_cpu = top_mem = None
        if self.collect_top_process:
            top_cpu, top_mem = self._top_processes()

        # --- Agent self-metrics ---
        with self._proc.oneshot():
            mem_info = self._proc.memory_info()
            agent = {
                "agent_cpu_percent": self._proc.cpu_percent(interval=None),
                "agent_rss_mb": round(mem_info.rss / (1024 * 1024), 2),
                "agent_num_threads": self._proc.num_threads(),
                "agent_open_files": self._open_handle_count(),
            }

        # --- Severity from thresholds (worst partition counts) ---
        severity, reason = self._severity(cpu_percent, vm.percent, disk_percent_max)

        return {
            "category": "resource",
            "action": "resource_snapshot",
            "severity": severity,
            "reason": reason,
            "timestamp": time.time(),

            # cpu
            "cpu_percent": cpu_percent,
            "cpu_per_core": per_core,
            "cpu_count": psutil.cpu_count(),
            "load_avg_1m": round(load1, 2) if load1 is not None else None,
            "load_avg_5m": round(load5, 2) if load5 is not None else None,
            "load_avg_15m": round(load15, 2) if load15 is not None else None,

            # memory
            "memory_percent": vm.percent,
            "memory_used_mb": round(vm.used / (1024 * 1024), 2),
            "memory_total_mb": round(vm.total / (1024 * 1024), 2),
            "memory_available_mb": round(vm.available / (1024 * 1024), 2),
            "swap_percent": sm.percent,

            # disk usage — primary (system) drive as the single-value gauge...
            "disk_percent": primary["percent"] if primary else None,
            "disk_used_gb": primary["used_gb"] if primary else None,
            "disk_total_gb": primary["total_gb"] if primary else None,
            "disk_free_gb": primary["free_gb"] if primary else None,
            # ...plus the fullest drive, and the full per-partition breakdown
            "disk_percent_max": disk_percent_max,
            "disk_partitions": partitions,

            # network
            "bandwidth_mbps": bandwidth_mbps,
            "bytes_sent_total": net.bytes_sent,
            "bytes_recv_total": net.bytes_recv,
            "active_connections": active_connections,
            "connections_by_protocol": protocol_counts,

            # disk io
            "disk_write_mbps": disk_write_mbps,
            "disk_read_mbps": disk_read_mbps,
            "disk_write_bytes_total": write_bytes_total,
            "disk_read_bytes_total": read_bytes_total,

            # top processes
            "top_cpu_process": top_cpu,
            "top_memory_process": top_mem,

            # agent self
            **agent,
        }

    # ---- helpers ---------------------------------------------------------

    def _top_processes(self):
        """Return (top_cpu, top_mem) as {pid,name,value} dicts."""
        procs = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
            try:
                procs.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        top_cpu = top_mem = None
        if procs:
            c = max(procs, key=lambda x: x.get("cpu_percent") or 0)
            m = max(procs, key=lambda x: x.get("memory_percent") or 0)
            top_cpu = {"pid": c["pid"], "name": c["name"],
                       "cpu_percent": round(c.get("cpu_percent") or 0, 1)}
            top_mem = {"pid": m["pid"], "name": m["name"],
                       "memory_percent": round(m.get("memory_percent") or 0, 1)}
        return top_cpu, top_mem

    def _disk_metrics(self):
        """Usage for every real mounted partition, cross-platform."""
        out = []
        for part in psutil.disk_partitions(all=False):
            # Windows: skip empty CD/DVD or card-reader slots that error on read
            if _IS_WINDOWS and ("cdrom" in part.opts or not part.fstype):
                continue
            # skip read-only / pseudo filesystems (always 100%, not real usage)
            if part.fstype.lower() in _PSEUDO_FSTYPES:
                continue
            try:
                u = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                # removable/unready drive, or no access — skip it
                continue
            out.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "percent": u.percent,
                "used_gb": round(u.used / (1024 ** 3), 2),
                "total_gb": round(u.total / (1024 ** 3), 2),
                "free_gb": round(u.free / (1024 ** 3), 2),
            })
        return out

    def _open_handle_count(self):
        """num_fds on Linux/Mac, num_handles on Windows."""
        try:
            if _IS_WINDOWS:
                return self._proc.num_handles()
            return self._proc.num_fds()
        except (psutil.AccessDenied, AttributeError):
            return None

    def _severity(self, cpu, mem, disk):
        reasons = []
        level = "info"

        def bump(current, warn, crit, label, value):
            nonlocal level
            if value >= crit:
                reasons.append(f"{label} {value:.0f}% >= critical {crit:.0f}%")
                return "critical"
            if value >= warn:
                reasons.append(f"{label} {value:.0f}% >= warn {warn:.0f}%")
                return "warning" if current != "critical" else current
            return current

        level = bump(level, self.cpu_warn, self.cpu_critical, "CPU", cpu)
        level = bump(level, self.memory_warn, self.memory_critical, "Memory", mem)
        level = bump(level, self.disk_warn, self.disk_critical, "Disk", disk)
        return level, "; ".join(reasons) if reasons else None
