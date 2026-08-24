import os
import json
import base64
import shutil
import subprocess
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


def jsonable(o: Any) -> Any:
    if isinstance(o, dict):
        return {k: jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [jsonable(v) for v in o]
    if isinstance(o, (bytes, bytearray)):
        return bytes(o).decode("utf-8", "ignore")
    return o


def safe(fn, default=None):
    try:
        return fn()
    except Exception as ex:
        return {"error": str(ex)[:200]} if default is None else default


def na(reason: str) -> Dict[str, Any]:
    return {"not_applicable": reason}


# ── management API (HTTP :9990) — local or remote ───────────────────────────
def mgmt_call(host: str, port: int, op: Dict[str, Any],
              user: Optional[str] = None, password: Optional[str] = None,
              timeout: float = 8.0, scheme: str = "http") -> Any:
    """POST a management operation to WildFly/JBoss :9990/management.

    WildFly management uses HTTP Digest auth. urllib handles it via an opener
    with an HTTPDigestAuthHandler when user/password are given.
    """
    url = f"{scheme}://{host}:{port}/management"
    data = json.dumps(op).encode("utf-8")
    headers = {"Content-Type": "application/json"}

    if user:
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, url, user, password or "")
        opener = urllib.request.build_opener(
            urllib.request.HTTPDigestAuthHandler(mgr),
            urllib.request.HTTPBasicAuthHandler(mgr))
    else:
        opener = urllib.request.build_opener()

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise RuntimeError("HTTP 401 Unauthorized — management user/password wrong "
                               "or no management user created (run add-user)")
        raise
    parsed = json.loads(body) if body else {}
    # WildFly wraps success as {"outcome":"success","result":...}
    if isinstance(parsed, dict) and parsed.get("outcome") == "failed":
        raise RuntimeError(parsed.get("failure-description") or "management op failed")
    return parsed.get("result", parsed) if isinstance(parsed, dict) else parsed


def read_resource(host, port, address: List[Any], user=None, password=None,
                  include_runtime=True, recursive=False, **kw) -> Any:
    op = {"operation": "read-resource",
          "address": address,
          "include-runtime": include_runtime,
          "recursive": recursive}
    return mgmt_call(host, port, op, user, password, **kw)


def read_attr(host, port, address: List[Any], name: str, user=None, password=None, **kw) -> Any:
    op = {"operation": "read-attribute", "address": address, "name": name}
    return mgmt_call(host, port, op, user, password, **kw)


# ── jboss-cli (local only) ──────────────────────────────────────────────────
def find_cli() -> Optional[str]:
    # 1) on PATH
    for name in ("jboss-cli.sh", "jboss-cli.bat", "jboss-cli"):
        p = shutil.which(name)
        if p:
            return p
    # 2) from env vars
    for base in (os.getenv("JBOSS_HOME"), os.getenv("WILDFLY_HOME")):
        if base:
            for rel in ("bin/jboss-cli.sh", "bin/jboss-cli.bat"):
                cand = os.path.join(base, rel)
                if os.path.isfile(cand):
                    return cand
    # 3) derive from a running WildFly process: its cmdline carries
    #    -Djboss.home.dir=<path>; jboss-cli lives at <path>/bin/
    home = _jboss_home_from_process()
    if home:
        for name in ("jboss-cli.bat", "jboss-cli.sh"):
            cand = os.path.join(home, "bin", name)
            if os.path.isfile(cand):
                return cand
    return None


def _jboss_home_from_process() -> Optional[str]:
    
    try:
        import psutil
    except Exception:
        return None
    for proc in psutil.process_iter(["cmdline", "exe", "name"]):
        try:
            # 1) -Djboss.home.dir= in cmdline (standalone.bat / java run)
            for arg in (proc.info.get("cmdline") or []):
                if arg.startswith("-Djboss.home.dir="):
                    home = arg.split("=", 1)[1].strip('"')
                    if home and os.path.isdir(home):
                        return home
            # 2) derive from the exe path of a wildfly/jboss process
            exe = proc.info.get("exe") or ""
            name = (proc.info.get("name") or "").lower()
            low = exe.lower()
            if ("wildfly" in low or "jboss" in low or "standalone" in low
                    or "wildfly" in name or "jboss" in name):
                home = _home_from_exe(exe)
                if home:
                    return home
        except Exception:
            continue
    return None


def _home_from_exe(exe: str) -> Optional[str]:
    """Walk up from an exe path to the WildFly home (a dir containing bin/jboss-cli.*)."""
    if not exe:
        return None
    d = os.path.dirname(exe)
    # climb up to ~5 levels looking for <dir>/bin/jboss-cli.*
    for _ in range(6):
        for name in ("jboss-cli.bat", "jboss-cli.sh"):
            if os.path.isfile(os.path.join(d, "bin", name)):
                return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def cli_command(cli: str, command: str, controller: Optional[str] = None,
                user: Optional[str] = None, password: Optional[str] = None,
                timeout: float = 20.0) -> Any:
    """Run one jboss-cli command with --output-json and parse it."""
    args = [cli, "--connect", "--output-json", f"--command={command}"]
    # guard against placeholder strings ("None"/"string"/blank) leaking in
    def _real(v):
        s = str(v or "").strip()
        return s if s.lower() not in ("", "none", "null", "string") else None
    controller = _real(controller)
    user = _real(user)
    password = _real(password)
    if controller:
        args.append(f"--controller={controller}")
    if user:
        args.append(f"--user={user}")
    if password:
        args.append(f"--password={password}")
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           input="")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as ex:
        raise RuntimeError(f"jboss-cli could not run: {str(ex)[:180]}")

    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()

    for noise in ("Press any key to continue . . .",
                  "Press any key to continue...",
                  "Press any key to continue"):
        out = out.replace(noise, "").strip()

    def _extract_json(text):
        text = (text or "").strip()
        if not text:
            return None

        try:
            return json.loads(text)
        except Exception:
            pass
        starts = [i for i in (text.find("{"), text.find("[")) if i >= 0]
        if not starts:
            return None
        start = min(starts)
        ends = [i for i in (text.rfind("}"), text.rfind("]")) if i >= 0]
        if not ends:
            return None
        end = max(ends)
        chunk = text[start:end + 1]
        return json.loads(chunk)

    if p.returncode != 0 and not out:
        detail = err or out or f"exit code {p.returncode}"
        low = detail.lower()
        if "authentic" in low or "username" in low or "password" in low:
            hint = " (management user needed: run add-user, pass user/password)"
        elif "connect" in low or "refused" in low or "timeout" in low:
            hint = " (mgmt port not reachable — is :9990 up? for remote pass controller=host:9990)"
        else:
            hint = ""
        raise RuntimeError(f"jboss-cli failed: {detail[:200]}{hint}")

    if not out:
        raise RuntimeError(f"jboss-cli: no output (stderr: {err[:150]})")

    try:
        parsed = _extract_json(out)
    except Exception:
        parsed = None
    if parsed is None:
        raise RuntimeError(f"jboss-cli non-JSON output: {out[:180]}")

    if isinstance(parsed, dict) and parsed.get("outcome") == "failed":
        raise RuntimeError(parsed.get("failure-description") or "cli op failed")
    return parsed.get("result", parsed) if isinstance(parsed, dict) else parsed