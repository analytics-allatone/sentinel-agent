import argparse
from .config import SEVERITY_ORDER , DEFAULT_CONFIG
import json
from .agent import deep_merge , SentinelAgent
import signal
import sys
from .logger import Logger




logger = Logger.get_logger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Sentinel Security Log Agent")
    parser.add_argument("--config",   help="Path to config JSON", default=None)
    parser.add_argument("--log-dir",  help="Output log directory", default=None)
    parser.add_argument("--stdout",   help="Also print events to stdout", action="store_true")
    parser.add_argument("--no-file",  help="Disable file collector", action="store_true")
    parser.add_argument("--no-auth",  help="Disable auth collector", action="store_true")
    parser.add_argument("--no-net",   help="Disable network collector", action="store_true")
    parser.add_argument("--no-proc",      help="Disable process collector",              action="store_true")
    parser.add_argument("--no-usb",       help="Disable USB/pendrive collector",         action="store_true")
    parser.add_argument("--usb-only",     help="Enable ONLY the USB/pendrive collector (all others disabled)", action="store_true")
    parser.add_argument("--no-harddisk",  help="Disable hard disk collector",            action="store_true")
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER, default=None)
    args = parser.parse_args()

   
    config = DEFAULT_CONFIG.copy()

    if args.config:
        with open(args.config) as f:
            user_config = json.load(f)
        config = deep_merge(config, user_config)

    if args.log_dir:
        config["output"]["log_dir"] = args.log_dir
    if args.stdout:
        config["output"]["stdout"] = True
    if args.no_file:
        config["collectors"]["file"]["enabled"] = False
    if args.no_auth:
        config["collectors"]["auth"]["enabled"] = False
    if args.no_net:
        config["collectors"]["network"]["enabled"] = False
    if args.no_proc:
        config["collectors"]["process"]["enabled"] = False

    # --usb-only: disable every collector except USB
    if args.usb_only:
        config["collectors"]["file"]["enabled"]     = False
        config["collectors"]["auth"]["enabled"]     = False
        config["collectors"]["network"]["enabled"]  = False
        config["collectors"]["process"]["enabled"]  = False
        config["collectors"]["harddisk"]["enabled"] = False
        config["collectors"]["usb"]["enabled"]      = True
        logger.info("USB-only mode: all collectors disabled except USB/pendrive")

    # --no-usb: disable USB collector
    if args.no_usb:
        config["collectors"]["usb"]["enabled"] = False

    # --no-harddisk: disable hard disk collector
    if args.no_harddisk:
        config["collectors"]["harddisk"]["enabled"] = False

    if args.min_severity:
        config["filters"]["min_severity"] = args.min_severity

    agent = SentinelAgent(config)

    def _sig_handler(sig, frame):
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT,  _sig_handler)

    agent.start()
    agent.wait()


if __name__ == "__main__":
    main()
