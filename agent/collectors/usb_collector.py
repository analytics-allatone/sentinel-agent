import os
import re
import time
import platform
import logging
import threading
import json
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

import psutil

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Import the new flat schema definitions
from schema.usb_schema import USBEvent, EventCategory, EventOutcome, Severity

OS = platform.system()   # "Linux" | "Windows" | "Darwin"


_log = logging.getLogger("usb_collector")
_warned: Set[str] = set()


def _warn_once(where: str, err: Exception):
    """Log an error the first time it happens per (place, error type), then stay
    quiet. Failures are visible, but a 3-second poll loop cannot flood the log."""
    key = f"{where}:{type(err).__name__}"
    if key not in _warned:
        _warned.add(key)
        _log.warning("%s failed: %r (further identical errors suppressed)", where, err)

# ──────────────────────────────────────────────────────────────
#  CONSTANTS
# ──────────────────────────────────────────────────────────────

SUSPICIOUS_LABELS: Set[str] = {
    "rubber ducky", "hak5", "bashbunny", "malware", "payload",
    "autorun", "hack", "exploit", "pentest", "badusb", "pwnagotchi",
}

AUTORUN_FILES: Set[str] = {
    "autorun.inf", "autorun.bat", "autorun.exe",
    "launch.bat", "start.bat", "run.exe", ".autorun",
}

EXECUTABLE_EXTS: Set[str] = {
    # Windows
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".hta", ".scr", ".pif", ".com", ".lnk", ".msi", ".wsf",
    # Linux / macOS
    ".sh", ".py", ".pl", ".rb", ".elf", ".bin",
    ".dmg", ".pkg", ".app",
}

REMOVABLE_FS: Set[str] = {
    "fat", "fat16", "fat32", "vfat", "exfat",
    "ntfs", "ntfs-3g",
    "hfs", "hfs+", "hfsplus", "apfs",
    "udf", "iso9660",
    "f2fs", "ext2", "ext3", "ext4",
}

SKIP_FS: Set[str] = {
    "tmpfs", "devtmpfs", "squashfs", "overlay", "aufs",
    "proc", "sysfs", "cgroup", "cgroup2", "pstore",
    "debugfs", "securityfs", "configfs", "fusectl",
    "efivarfs", "hugetlbfs", "mqueue", "devfs",
    "autofs", "binfmt_misc", "tracefs",
}

LARGE_TRANSFER_BYTES = 500 * 1024 * 1024   # 500 MB


# ──────────────────────────────────────────────────────────────
#  PLATFORM-SPECIFIC HELPERS
# ──────────────────────────────────────────────────────────────

def _linux_removable_flag(device: str) -> bool:
    try:
        name = Path(device).name
        # nvme0n1p1 -> nvme0n1 , mmcblk0p1 -> mmcblk0 , sda1 -> sda
        m = re.match(r'^((?:nvme\d+n\d+|mmcblk\d+|loop\d+))p\d+$', name)
        base = m.group(1) if m else re.sub(r'\d+$', '', name)
        flag = Path(f"/sys/block/{base}/removable").read_text().strip()
        return flag == "1"
    except Exception:
        return False


def _linux_usb_raw_devices() -> List[dict]:
    results = []
    base = Path("/sys/bus/usb/devices")
    if not base.exists():
        return results

    def _read(p: Path) -> str:
        try:
            return p.read_text().strip()
        except Exception:
            return ""

    for dev_path in base.iterdir():
        for iface_path in dev_path.glob("*:*"):
            if _read(iface_path / "bInterfaceClass") == "08":   # Mass Storage
                entry = {
                    "vendor":   _read(dev_path / "idVendor"),
                    "product":  _read(dev_path / "idProduct"),
                    "serial":   _read(dev_path / "serial"),
                    "mfr":      _read(dev_path / "manufacturer"),
                    "prod_name":_read(dev_path / "product"),
                    "syspath":  str(dev_path),
                }
                results.append(entry)
                break
    return results


_SYSFS = "/sys"                      # overridable for tests
_IDENT_CACHE: Dict[str, tuple] = {}  # key -> (timestamp, info)


def _cached(key: str, fn, ok_ttl: float = 3600.0, miss_ttl: float = 60.0):
    """Identity lookups spawn processes; the poll loop runs every few seconds,
    so remember the answer (a miss is retried after a minute)."""
    hit = _IDENT_CACHE.get(key)
    now = time.time()
    if hit and now - hit[0] < (ok_ttl if hit[1] else miss_ttl):
        return hit[1]
    val = fn()
    _IDENT_CACHE[key] = (now, val)
    return val


def _sysfs_usb_identity(device: str) -> dict:
    """Walk /sys/class/block/<dev> up to the USB device node and read its
    descriptors (manufacturer, product, serial, idVendor, idProduct).
    Plain file reads, no dependency."""
    out: dict = {}
    try:
        node = (Path(_SYSFS) / "class" / "block" / Path(device).name).resolve()
        for parent in [node, *node.parents]:
            if (parent / "idVendor").exists():
                def rd(f):
                    try:
                        return (parent / f).read_text().strip()
                    except Exception:
                        return ""
                out = {"manufacturer": rd("manufacturer"), "product": rd("product"),
                       "serial": rd("serial"), "vid": rd("idVendor"), "pid": rd("idProduct")}
                break
    except Exception as e:
        _warn_once("rd", e)
    return out


def _udev_props(device: str) -> dict:
    """udev properties of the block device (ID_VENDOR, ID_MODEL, ID_FS_LABEL...).
    Read with the udevadm command (no extra Python package needed)."""
    props: dict = {}
    try:
        out = subprocess.check_output(
            ["udevadm", "info", "--query=property", f"--name={device}"],
            stderr=subprocess.DEVNULL, timeout=4, text=True)
        for line in out.splitlines():
            k, _, v = line.partition("=")
            props[k] = v
    except Exception as e:
        _warn_once("_udev_props", e)
    return props


def _lsblk_label_size(device: str) -> dict:
    """Fallback for label when udev has none. -P gives KEY="value" pairs, so an
    empty LABEL can no longer shift the other columns (the old split() bug)."""
    info: dict = {}
    try:
        out = subprocess.check_output(
            ["lsblk", "-ndP", "-o", "LABEL,SIZE", device],
            stderr=subprocess.DEVNULL, timeout=4, text=True)
        for k, v in re.findall(r'(\w+)="([^"]*)"', out):
            info[k.lower()] = v
    except Exception as e:
        _warn_once("_lsblk_label_size", e)
    return info


def _linux_device_info(device: str) -> dict:
    def fetch():
        u = _udev_props(device)
        d = _sysfs_usb_identity(device)
        clean = lambda v: (v or "").replace("_", " ").strip()
        vid, pid = d.get("vid") or u.get("ID_VENDOR_ID", ""), d.get("pid") or u.get("ID_MODEL_ID", "")
        # vendor: USB descriptor -> hwdb name for the VID -> raw udev -> bare VID
        vendor = (clean(d.get("manufacturer")) or clean(u.get("ID_VENDOR_FROM_DATABASE"))
                  or clean(u.get("ID_VENDOR")) or (f"VID_{vid.upper()}" if vid else ""))
        model = (clean(d.get("product")) or clean(u.get("ID_MODEL_FROM_DATABASE"))
                 or clean(u.get("ID_MODEL")) or (f"PID_{pid.upper()}" if pid else ""))
        serial = d.get("serial") or u.get("ID_SERIAL_SHORT") or u.get("ID_SERIAL", "")
        label = u.get("ID_FS_LABEL", "")
        if not label:
            label = _lsblk_label_size(device).get("label", "")
        return {"label": label, "serial": serial, "model": model, "vendor": vendor,
                "usb_id": f"{vid}:{pid}" if vid and pid else "", "size_bytes": 0}
    return _cached(f"linux:{device}", fetch) or {
        "label": "", "serial": "", "model": "", "vendor": "", "usb_id": "", "size_bytes": 0}


def _parse_pnp(pnp: str) -> dict:
    """USBSTOR\\DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0&REV_PMAP\\0019E06B&0
       -> vendor KINGSTON, model DATATRAVELER 3.0, serial 0019E06B"""
    out = {"vendor": "", "model": "", "serial": ""}
    m = re.search(r'VEN_([^&\\]+)', pnp or "", re.I)
    if m: out["vendor"] = m.group(1).replace("_", " ").strip()
    m = re.search(r'PROD_([^&\\]+)', pnp or "", re.I)
    if m: out["model"] = m.group(1).replace("_", " ").strip()
    parts = (pnp or "").split("\\")
    if len(parts) >= 3:
        out["serial"] = parts[-1].rsplit("&", 1)[0]
    return out


def _windows_device_info(drive_letter: str) -> dict:
    """Drive letter -> partition -> physical disk, via PowerShell CIM."""
    def fetch():
        letter = drive_letter.rstrip("\\/:").upper()
        ps = ("$d=Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='%s:'\";"
              "$d|%%{Get-CimAssociatedInstance -InputObject $_ -ResultClassName Win32_DiskPartition}"
              "|%%{Get-CimAssociatedInstance -InputObject $_ -ResultClassName Win32_DiskDrive}"
              "|Select-Object Model,Manufacturer,SerialNumber,PNPDeviceID|ConvertTo-Json -Compress") % letter
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                stderr=subprocess.DEVNULL, timeout=15, text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            data = json.loads(out) if out.strip() else {}
            if isinstance(data, list):
                data = data[0] if data else {}
        except Exception:
            return {}
        pnp = _parse_pnp(data.get("PNPDeviceID", ""))
        manu = (data.get("Manufacturer") or "").strip()
        if manu.startswith("("):               # "(Standard disk drives)" is useless
            manu = ""
        vid = re.search(r'VID_([0-9A-F]{4})', data.get("PNPDeviceID", ""), re.I)
        return {"vendor": pnp["vendor"] or manu,
                "model": (data.get("Model") or "").strip() or pnp["model"],
                "serial": (data.get("SerialNumber") or "").strip() or pnp["serial"],
                "usb_id": ""}
    return _cached(f"win:{drive_letter}", fetch) or {}


def _windows_removable_drives() -> List[dict]:
    drives = []
    try:
        import win32api, win32con
        drive_bits = win32api.GetLogicalDrives()
        for i in range(26):
            if drive_bits & (1 << i):
                letter = chr(65 + i) + ":\\"
                try:
                    dtype = win32api.GetDriveType(letter)
                    if dtype == 2:
                        vol_info = ("", "", "")
                        try:
                            vol_info = win32api.GetVolumeInformation(letter)
                        except Exception as e:
                            _warn_once("_windows_removable_drives", e)
                        drives.append({
                            "mountpoint": letter,
                            "label": vol_info[0],
                            "serial_num": hex(vol_info[1]) if vol_info[1] else "",
                            "fstype": vol_info[4] if len(vol_info) > 4 else "",
                        })
                except Exception as e:
                    _warn_once("_windows_removable_drives", e)
    except ImportError:
        for part in psutil.disk_partitions(all=True):
            opts = part.opts.lower()
            if "removable" in opts or "cdrom" in opts:
                drives.append({
                    "mountpoint": part.mountpoint,
                    "label": "",
                    "serial_num": "",
                    "fstype": part.fstype,
                })
    return drives


def _macos_disk_info(mountpoint: str) -> dict:
    info = {"label": "", "kind": "", "removable": False, "protocol": ""}
    try:
        out = subprocess.check_output(
            ["diskutil", "info", mountpoint],
            stderr=subprocess.DEVNULL, timeout=6, text=True,
        )
        for line in out.splitlines():
            k, _, v = line.partition(":")
            k, v = k.strip().lower(), v.strip()
            if "volume name"         in k: info["label"]     = v
            if "type (bundle)"       in k: info["kind"]      = v
            if "removable media"     in k: info["removable"] = v.lower() == "yes"
            if "protocol"            in k: info["protocol"]  = v
    except Exception as e:
        _warn_once("_macos_disk_info", e)
    return info


# ──────────────────────────────────────────────────────────────
#  PARTITION FILTER
# ──────────────────────────────────────────────────────────────

def _is_removable_partition(part) -> bool:
    fs   = part.fstype.lower()
    opts = part.opts.lower()
    mp   = part.mountpoint

    if fs in SKIP_FS or not mp:
        return False

    if OS == "Linux":
        mp_l = mp.lower()
        if mp_l.startswith("/media/") or mp_l.startswith("/run/media/"):
            return True
        if mp_l.startswith("/mnt/"):
            dev = part.device
            if _linux_removable_flag(dev):
                return True
        if fs in REMOVABLE_FS and _linux_removable_flag(part.device):
            return True
        return False

    if OS == "Windows":
        if not fs:                      # empty card-reader slot / no media
            return False
        return "removable" in opts      # psutil sets this only for DRIVE_REMOVABLE

    if OS == "Darwin":
        mp_l = mp.lower()
        if mp_l.startswith("/volumes/") and "macintosh hd" not in mp_l:
            info = _macos_disk_info(mp)
            if info["removable"] or "usb" in info["protocol"].lower():
                return True
            if fs in REMOVABLE_FS:
                return True
        return False

    return False


# ──────────────────────────────────────────────────────────────
#  SNAPSHOT BUILDER
# ──────────────────────────────────────────────────────────────

def _build_snapshot(part) -> dict:
    mp  = part.mountpoint
    dev = part.device

    snap = {
        "device":     dev,
        "mountpoint": mp,
        "fstype":     part.fstype,
        "opts":       part.opts,
        "label":      "",
        "vendor":     "",
        "model":      "",
        "serial":     "",
        "size_bytes": 0,
        "used_bytes": None,
    }

    try:
        if OS == "Linux":
            info = _linux_device_info(dev)
            snap["label"]  = info.get("label", "")
            snap["serial"] = info.get("serial", "")
            snap["model"]  = info.get("model", "")
            snap["vendor"] = info.get("vendor", "")
            snap["usb_id"] = info.get("usb_id", "")

        elif OS == "Darwin":
            info = _macos_disk_info(mp)
            snap["label"]  = info.get("label", "")
            snap["vendor"] = info.get("protocol", "")

        elif OS == "Windows":
            try:
                import win32api
                vol = win32api.GetVolumeInformation(mp)
                snap["label"]  = vol[0]
                snap["serial"] = hex(vol[1]) if vol[1] else ""
                snap["fstype"] = vol[4] if len(vol) > 4 else part.fstype
            except Exception as e:
                _warn_once("_build_snapshot", e)
            ident = _windows_device_info(mp)
            if ident:
                snap["vendor"] = ident.get("vendor", "")
                snap["model"]  = ident.get("model", "")
                snap["serial"] = ident.get("serial") or snap["serial"]
    except Exception as e:
        print(f"Snapshot enrichment error on {mp}: {e}")

    try:
        usage = psutil.disk_usage(mp)
        snap["used_bytes"] = usage.used
        snap["size_bytes"] = usage.total
    except Exception as e:
        _warn_once("_build_snapshot", e)

    return snap


HIGH_RISK_EXTS: Set[str] = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".hta", ".scr",
    ".pif", ".com", ".lnk", ".msi", ".wsf", ".elf",
}


def _file_severity(name: str) -> "Severity":
    """autorun.* -> critical, Windows executables/scripts -> high,
    generic scripts/installers (.py .sh .js ...) -> low (just worth a note)."""
    n = name.lower()
    if n in AUTORUN_FILES:
        return Severity.CRITICAL
    if Path(n).suffix in HIGH_RISK_EXTS:
        return Severity.HIGH
    return Severity.LOW


def _scan_autorun_files(mountpoint: str) -> List[str]:
    found = []
    try:
        root = Path(mountpoint)
        for child in root.iterdir():
            n = child.name.lower()
            if n in AUTORUN_FILES:
                found.append(child.name)
            elif child.is_file() and Path(n).suffix in EXECUTABLE_EXTS:
                found.append(child.name)
    except PermissionError as e:
        _warn_once("_scan_autorun_files(permission denied)", e)
    except Exception as e:
        print(f"Autorun scan error on {mountpoint}: {e}")
    return found


# ──────────────────────────────────────────────────────────────
#  COLLECTOR CLASS
# ──────────────────────────────────────────────────────────────

class USBCollector:
    """
    Polls device topology and filesystems for dynamic external USB media mutations.
    Emits structural records adhering directly to USBEvent validation layers.
    """

    def __init__(
        self,
        dispatch: Callable[[dict], None],
        machine_info: dict,
        poll_interval: float = 3.0,
        scan_on_connect: bool = True,
        transfer_threshold_bytes: int = LARGE_TRANSFER_BYTES,
    ):
        self._dispatch   = dispatch
        self._interval   = poll_interval
        self._scan       = scan_on_connect
        self._xfer_limit = transfer_threshold_bytes
        self._stop       = threading.Event()
        self._threads: List[threading.Thread] = []

        self._known: Dict[str, dict] = {}
        self._known_raw: Dict[str, dict] = {}
        self._xfer_base: Dict[str, int] = {}       # mountpoint -> used_bytes at connect
        self._xfer_reported: Dict[str, int] = {}   # mountpoint -> bytes already alerted
        self._machine_info = machine_info

    def _emit(
        self,
        action: str,
        snap: dict,
        severity: Severity = Severity.INFO,
        outcome: EventOutcome = EventOutcome.SUCCESS,
        tags: List[str] = None,
        notes: str = None,
        extra_file_fields: dict = None,
        delta_bytes: int = None
    ):
        mp    = snap.get("mountpoint", snap.get("device", "unknown"))
        label = snap.get("label") or Path(mp).name or mp

        # Map dynamic snapshot values directly to the top-level flat schema attributes
        event = USBEvent(
            action=action,
            outcome=outcome,
            severity=severity,
            tags=(tags or []) + ["usb", "removable_media"],
            notes=notes,
            usb_device_path=snap.get("device"),
            usb_mountpoint=snap.get("mountpoint"),
            usb_fstype=snap.get("fstype"),
            usb_mount_options=snap.get("opts"),
            usb_label=snap.get("label"),
            usb_vendor=snap.get("vendor"),
            usb_model=snap.get("model"),
            usb_serial_number=snap.get("serial"),
            usb_size_bytes=snap.get("size_bytes"),
            usb_used_bytes=snap.get("used_bytes"),
            usb_transfer_delta_bytes=delta_bytes
        )

        # File context (e.g. the autorun file found on the stick)
        for k, v in (extra_file_fields or {}).items():
            if hasattr(event, k):
                setattr(event, k, v)

        if not event.notes:
            auto_notes = f"device={event.usb_device_path} fs={event.usb_fstype} label='{event.usb_label}'"
            if event.usb_serial_number: auto_notes += f" serial={event.usb_serial_number}"
            if event.usb_model:          auto_notes += f" model={event.usb_model}"
            if event.usb_vendor:         auto_notes += f" vendor={event.usb_vendor}"
            if snap.get("usb_id"):       auto_notes += f" usb_id={snap['usb_id']}"
            if event.usb_size_bytes:     auto_notes += f" size={event.usb_size_bytes / (1024**3):.1f}GB"
            event.notes = auto_notes
        self._dispatch(event.to_dict(), self._machine_info)

    def _track(self, snap: dict):
        """Remember how full the stick was when we first saw it."""
        mp = snap.get("mountpoint")
        if snap.get("used_bytes") is not None:
            self._xfer_base[mp] = snap["used_bytes"]
            self._xfer_reported[mp] = 0

    def _check_connect(self, snap: dict, present: bool = False):
        """present=True: stick was already plugged in when monitoring started."""
        mp    = snap["mountpoint"]
        self._track(snap)
        label = (snap.get("label") or "").lower()
        action = "usb_present" if present else "usb_connected"
        tags  = [action] + (["already_connected"] if present else [])

        if any(bad in label for bad in SUSPICIOUS_LABELS):
            tags.append("suspicious_label")
            self._emit(
                action, snap,
                severity=Severity.HIGH,
                tags=tags,
                notes=f"Suspicious USB label detected: '{snap.get('label')}' on {mp}",
            )
            print(f"Suspicious USB label '{snap.get('label')}' on {mp}")
        else:
            self._emit(action, snap, severity=Severity.LOW, tags=tags)
            print(f"USB connected: {snap.get('device')} → {mp} label='{snap.get('label')}'")

        if self._scan:
            bad = _scan_autorun_files(mp)
            for file_name in bad:
                sev = _file_severity(file_name)
                file_fields = {
                    "file_path": str(Path(mp) / file_name),
                    "file_name": file_name,
                    "file_directory": mp
                }
                
                self._emit(
                    "usb_autorun_found", snap,
                    severity=sev,
                    outcome=EventOutcome.UNKNOWN,
                    tags=["usb", "autorun", "potential_malware"],
                    notes=f"Suspicious file discovered at USB root on {mp}: {file_name}",
                    extra_file_fields=file_fields
                )
                print(f"USB root risk file on {mp}: {file_name}")

    def _check_disconnect(self, snap: dict):
        mp = snap.get("mountpoint", "unknown")
        self._xfer_base.pop(mp, None)
        self._xfer_reported.pop(mp, None)
        self._emit(
            "usb_disconnected", snap,
            severity=Severity.LOW,
            tags=["usb_disconnected"],
            notes=f"USB removed: device={snap.get('device','')} was mounted at {mp} label='{snap.get('label','')}'",
        )
        print(f"USB disconnected: {snap.get('device')} ← {mp}")

    def _check_transfer(self, snap: dict, prev: dict):
        """Cumulative: alert every time another `limit` bytes were written since
        the stick was connected, so slow copies are caught too."""
        mp   = snap.get("mountpoint")
        curr = snap.get("used_bytes")
        base = self._xfer_base.get(mp)
        if curr is None or base is None:
            return
        if curr < base:                       # files were deleted -> re-base
            self._xfer_base[mp] = curr
            self._xfer_reported[mp] = 0
            return
        pending = (curr - base) - self._xfer_reported.get(mp, 0)
        if pending >= self._xfer_limit:
            self._xfer_reported[mp] = self._xfer_reported.get(mp, 0) + pending
            total_mb = (curr - base) / (1024 * 1024)
            mb = pending / (1024 * 1024)
            sev = Severity.HIGH if total_mb > 1024 else Severity.MEDIUM
            self._emit(
                "usb_data_transfer", snap,
                severity=sev,
                tags=["usb", "large_transfer", "data_exfiltration_risk"],
                notes=f"Large USB write: +{mb:.1f} MB (total {total_mb:.1f} MB since connect) on {mp}",
                delta_bytes=pending,
            )
            print(f"Large USB write on {mp}: +{mb:.1f} MB (total {total_mb:.1f} MB)")

    def _poll_raw_linux(self):
        print("USBCollector raw-device watcher started (Linux)")
        try:   # devices already present at start are reported via usb_present
            self._known_raw = {e["syspath"]: e for e in _linux_usb_raw_devices()}
        except Exception:
            self._known_raw = {}
        while not self._stop.is_set():
            try:
                current_raw = {e["syspath"]: e for e in _linux_usb_raw_devices()}
                for syspath, entry in current_raw.items():
                    if syspath not in self._known_raw:
                        snap = {
                            "device":     syspath,
                            "mountpoint": "(not mounted)",
                            "fstype":     "unknown",
                            "opts":       "",
                            "label":      entry.get("prod_name", ""),
                            "vendor":     entry.get("mfr", ""),
                            "model":      entry.get("prod_name", ""),
                            "serial":     entry.get("serial", ""),
                            "size_bytes": 0,
                            "used_bytes": None,
                        }
                        self._emit(
                            "usb_raw_device", snap,
                            severity=Severity.MEDIUM,
                            tags=["usb_raw", "not_mounted"],
                            notes=f"USB storage raw hardware detected (unmounted): vendor={entry.get('mfr')} product={entry.get('prod_name')}",
                        )
                        print(f"Raw USB hardware found: {entry.get('mfr')} {entry.get('prod_name')}")
                for syspath, entry in self._known_raw.items():
                    if syspath not in current_raw:
                        self._emit(
                            "usb_raw_removed",
                            {"device": syspath, "mountpoint": "(not mounted)",
                             "label": entry.get("prod_name", ""), "vendor": entry.get("mfr", ""),
                             "model": entry.get("prod_name", ""), "serial": entry.get("serial", "")},
                            severity=Severity.LOW, tags=["usb_raw", "removed"],
                            notes=f"USB storage hardware removed: {entry.get('mfr')} {entry.get('prod_name')}",
                        )
                self._known_raw = current_raw
            except Exception as e:
                print(f"Raw USB hardware poll error: {e}")
            time.sleep(self._interval)

    def _poll(self):
        print("USBCollector started — polling storage configurations")
        try:
            for part in psutil.disk_partitions(all=True):
                if _is_removable_partition(part):
                    snap = _build_snapshot(part)
                    self._known[part.mountpoint] = snap
                    self._check_connect(snap, present=True)
            print(f"USBCollector seeded {len(self._known)} existing device(s): " + ", ".join(self._known.keys()))
        except Exception as e:
            print(f"USB baseline seed error: {e}")

        while not self._stop.is_set():
            try:
                current: Dict[str, dict] = {}
                for part in psutil.disk_partitions(all=True):
                    if _is_removable_partition(part):
                        snap = _build_snapshot(part)
                        current[part.mountpoint] = snap

                # Connected mutations
                for mp, snap in current.items():
                    if mp not in self._known:
                        self._check_connect(snap)

                # Disconnected mutations
                for mp, snap in list(self._known.items()):
                    if mp not in current:
                        self._check_disconnect(snap)

                # IO Data Delta shifts
                for mp, snap in current.items():
                    if mp in self._known:
                        self._check_transfer(snap, self._known[mp])

                self._known = current
            except Exception as e:
                print(f"USB monitoring cluster poll error: {e}")

            time.sleep(self._interval)

    def start(self):
        t_main = threading.Thread(target=self._poll, daemon=True, name="usb-monitor")
        self._threads = [t_main]
        t_main.start()

        if OS == "Linux":
            t_raw = threading.Thread(target=self._poll_raw_linux, daemon=True, name="usb-raw")
            self._threads.append(t_raw)
            t_raw.start()

    def stop(self):
        self._stop.set()
