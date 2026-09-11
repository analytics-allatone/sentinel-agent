import threading
import time

from config.config import SEVERITY_ORDER

from output.writer import EventDispatcher
from collectors.file_collector import FileCollector
from collectors.auth_collector import create_auth_collector
from collectors.network_collector import NetworkCollector
from collectors.process_collector import ProcessCollector
from collectors.usb_collector import USBCollector
# from collectors.harddisk_collector import HardDiskCollector   # see block at end of start()
from collectors.capacity_monitoring_collector import ResourceCollector
from collectors.engines_handler import EnginesHandler
from collectors.web_inspector import WebInspector
from collectors.fly_inspector import FlyInspector
from collectors.appserver_inspector import AppServerInspector

from utils.utils import get_machine_info
from utils.command_registry import (register, add_static_collector,
                                    stop_dynamic_collectors, get_status)
from utils.shutdown import call_with_timeout, force_exit_if_stuck, install_signal_handlers


class SentinelAgent:
    def __init__(self, config: dict, agent_name: str):
        self.config = config
        self._collectors = []
        self._dispatcher = None
        self._running = False
        self._stopping = False
        self._stop_lock = threading.Lock()      # stop() can arrive from signal + command
        self.machine_info = get_machine_info()
        self.machine_info["agent_name"] = agent_name

    # ----------------------------------------------------------------- setup --

    def _build_dispatcher(self):
        cfg = self.config["output"]
        return EventDispatcher(stdout=cfg.get("stdout", False))

    def _make_dispatch(self):
        """Returns a filtered dispatch function."""
        cfg = self.config.get("filters", {})
        min_sev_str = cfg.get("min_severity", "info")
        min_sev_idx = SEVERITY_ORDER.index(min_sev_str) if min_sev_str in SEVERITY_ORDER else 0
        excl_cats = set(cfg.get("exclude_categories", []))
        excl_actions = set(cfg.get("exclude_actions", []))

        def dispatch(event_dict: dict, machine_info):
            sev = event_dict.get("severity", "info")
            if SEVERITY_ORDER.index(sev) < min_sev_idx:
                return
            if event_dict.get("category") in excl_cats:
                return
            if event_dict.get("action") in excl_actions:
                return
            self._dispatcher.push(event_dict, machine_info)

        return dispatch

    def _add_handler(self, name, factory):
        """On-demand inspector: constructed and registered, started later by a
        start_* command."""
        try:
            register(name, factory())
        except Exception as e:
            print(f"Engine Handler error: {e}")
        try:
            wi = WebInspector(dispatch=dispatch, machine_info=self.machine_info)
            # wi.start({"server": "apache", "host": "127.0.0.1", "port": 8080})
            register("web_inspector", wi)
            self._collectors.append(wi)
        except Exception as e:
            print(f"Web_Server inspector error: {e}")
        try:
            rc = ResourceCollector(
                dispatch      = dispatch,
                machine_info  = self.machine_info,
                poll_interval = 10.0,
            )
            rc.start()
            add_static_collector(rc)
            self._collectors.append(rc)
            print("Resource Collector started")
        except Exception as e:
            print(f"Resource collector error: {e}")


        try:
            
            fc = FileCollector(
                dispatch    = dispatch,
                machine_info= self.machine_info,
                watch_paths = None,
                ignore_dirs = None,
                recursive   = True,
                use_polling = False,
            )
            add_static_collector(fc)
            fc.start()
            self._collectors.append(fc)
            print("File Collector started")
        except ImportError as e:
            print(f"File collector unavailable: {e}")
        except Exception as e:
            print(f"File collector error: {e}")


        try:
            
            ac = create_auth_collector(
                dispatch       = dispatch,
                machine_info = self.machine_info
            )
            add_static_collector(ac)
            ac.start()
            self._collectors.append(ac)
            print("Auth Collector started")
        except Exception as e:
            print(f"Auth collector error: {e}")

        try:
            
            nc = NetworkCollector(
                dispatch        = dispatch,
                machine_info= self.machine_info,
                poll_interval   = 2.0,
                track_bandwidth = True
            )
            add_static_collector(nc)
            nc.start()

            self._collectors.append(nc)
            print(" Network Collector started")
        except Exception as e:
            print(f"Network collector error: {e}")

        try:
            
            pc = ProcessCollector(
                dispatch          = dispatch,
                machine_info= self.machine_info,
                poll_interval     = 1.5,
                resource_interval = 30.0,
                hash_executables  = True
            )
            add_static_collector(pc)
            pc.start()
            self._collectors.append(pc)
            print("Process Collector started")
        except Exception as e:
            print(f"Process collector error: {e}")


        try:
            uc = USBCollector(
                dispatch                 = dispatch,
                machine_info= self.machine_info,
                poll_interval            = 3.0,
                scan_on_connect          = True,
                transfer_threshold_bytes = 524288000,
            )
            add_static_collector(uc)
            uc.start()
            self._collectors.append(uc)
            print("USB Collector started")
        except Exception as e:
            print(f"USB collector error: {e}")




        # found = run_detect(dispatch, self.machine_info)

        # Database discovery collector (detects local engines: postgres/mysql/oracle...)
        # dd_cfg = self.config.get("collectors", {}).get("db_discovery", {})
        # if dd_cfg.get("enabled", True):
        #     try:
        #         self._db_inspector = DatabaseInspector(
        #         dispatch=dispatch, machine_info=self.machine_info,
        #         config_file=dd_cfg.get("config_file"),
        #         poll_interval=dd_cfg.get("poll_interval", 300.0),
        #         control_url=os.getenv("DB_CONTROL_URL"),
        #         )
        #         self._db_inspector.set_detected(found)
        #         self._db_inspector.start()          # exits by itself while nothing is ticked
        #         self._collectors.append(self._db_inspector)

        # Hard disk collector — re-enable by uncommenting the import above too.
        # hd = self.config.get("collectors", {}).get("harddisk", {})
        # if hd.get("enabled", True):
        #     self._add_collector("HardDisk collector", lambda: HardDiskCollector(
        #         dispatch=dispatch, machine_info=mi,
        #         poll_interval=hd.get("poll_interval", 30.0),
        #         smart_interval=hd.get("smart_interval", 300.0),
        #         warn_percent=hd.get("warn_percent", 85.0),
        #         critical_percent=hd.get("critical_percent", 95.0),
        #         enable_smart=hd.get("enable_smart", True)))

        self._running = True
        print("Agent running. Press Ctrl+C to stop.")

    # -------------------------------------------------------------- shutdown --

    def stop(self):
        with self._stop_lock:
            if self._stopping:          # second Ctrl+C, or pause-then-Ctrl+C
                return
            self._stopping = True
        self._running = False           # releases wait()

        print("Stopping collectors...")

        # 1. per-service inspectors first: they push events, and they are the
        #    ones the control server thinks it started.
        call_with_timeout(stop_dynamic_collectors, 20.0, "dynamic collectors")

        # 2. always-on collectors. Skipped if a global pause already stopped
        #    them — otherwise a collector with a slow stop() costs the timeout
        #    twice for no reason. (stop() should still be idempotent.)
        if get_status() != "pause":
            for c in self._collectors:
                call_with_timeout(c.stop, 5.0, type(c).__name__)
        else:
            print("Agent is paused; collectors are already stopped.")

        # 3. flush queued events BEFORE any hard exit, or they are lost.
        if self._dispatcher:
            call_with_timeout(self._dispatcher.flush_and_stop, 10.0, "dispatcher")

        print("Sentinel Agent stopped.")

        # 4. last resort, and it must be last: os._exit kills everything above.
        force_exit_if_stuck(grace=3.0)

    def wait(self):
        """Block the main thread until stopped. Call from the main thread."""
        install_signal_handlers(self.stop)      # handles SIGINT and SIGTERM
        try:
            while self._running:
                time.sleep(0.5)
        except KeyboardInterrupt:               # fallback if handlers didn't install
            print("\nCtrl+C received.")
            self.stop()


def deep_merge(base: dict, override: dict) -> dict:
    result = base.copy()
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = deep_merge(result[k], v)
        else:
            result[k] = v
    return result