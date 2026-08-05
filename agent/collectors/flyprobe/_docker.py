import json
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

_SDK = None          # cached: docker SDK client or False


def _run(args: List[str], timeout: float = 20.0) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as ex:
        return 1, "", str(ex)


def _sdk():
    """Return a docker SDK client, or None. Cached."""
    global _SDK
    if _SDK is not None:
        return _SDK or None
    try:
        import docker
        c = docker.from_env()
        c.ping()
        _SDK = c
        return c
    except Exception:
        _SDK = False
        return None


def docker_available() -> Dict[str, Any]:
    """Which docker backend can we use?"""
    if _sdk():
        return {"available": True, "backend": "sdk"}
    if shutil.which("docker"):
        rc, out, err = _run(["docker", "info", "--format", "{{.ServerVersion}}"])
        if rc == 0:
            return {"available": True, "backend": "cli", "server_version": out.strip()}
    return {"available": False, "backend": None}


def list_containers() -> List[Dict[str, Any]]:
    """Running containers: [{id, name, image}]."""
    c = _sdk()
    if c:
        try:
            return [{"id": x.short_id, "name": x.name,
                     "image": (x.image.tags[0] if x.image.tags else x.image.short_id)}
                    for x in c.containers.list()]
        except Exception:
            pass
    if shutil.which("docker"):
        rc, out, err = _run(["docker", "ps", "--format",
                             "{{.ID}}\t{{.Names}}\t{{.Image}}"])
        if rc == 0:
            rows = []
            for line in out.strip().splitlines():
                parts = line.split("\t")
                if len(parts) >= 3:
                    rows.append({"id": parts[0], "name": parts[1], "image": parts[2]})
            return rows
    return []


def exec_in(container: str, cmd: List[str], timeout: float = 25.0) -> Tuple[int, str, str]:
    """Run a command inside a container. Returns (rc, stdout, stderr)."""
    c = _sdk()
    if c:
        try:
            cont = c.containers.get(container)
            res = cont.exec_run(cmd, demux=True)
            code = res.exit_code
            out, err = res.output if isinstance(res.output, tuple) else (res.output, b"")
            return (code or 0,
                    (out or b"").decode("utf-8", "ignore"),
                    (err or b"").decode("utf-8", "ignore"))
        except Exception as ex:
            return 1, "", str(ex)
    if shutil.which("docker"):
        return _run(["docker", "exec", container] + cmd, timeout=timeout)
    return 1, "", "no docker backend"


def container_has_flyctl(container: str) -> Optional[str]:
    """Return the flyctl path inside the container, or None."""
    for probe in (["which", "fly"], ["which", "flyctl"]):
        rc, out, err = exec_in(container, probe, timeout=10)
        if rc == 0 and out.strip():
            return out.strip().splitlines()[0]
    return None


def container_fly_authed(container: str, fly_bin: str) -> bool:
    rc, out, err = exec_in(container, [fly_bin, "auth", "whoami"], timeout=15)
    return rc == 0 and out.strip() and "not logged in" not in (out + err).lower()


def fly_json_in(container: str, fly_bin: str, args: List[str]) -> Any:
    rc, out, err = exec_in(container, [fly_bin] + args + ["--json"], timeout=25)
    if rc != 0:
        raise RuntimeError((err or out or "flyctl error in container").strip()[:300])
    out = out.strip()
    return json.loads(out) if out else None


def find_flyctl_containers() -> List[Dict[str, Any]]:
    """Scan running containers; return those that have flyctl.
    [{container, name, image, fly_bin, authenticated}]"""
    found = []
    for cont in list_containers():
        fly_bin = container_has_flyctl(cont["id"])
        if fly_bin:
            found.append({"container": cont["id"], "name": cont["name"],
                          "image": cont["image"], "fly_bin": fly_bin,
                          "authenticated": container_fly_authed(cont["id"], fly_bin)})
    return found


# ---- unified flyctl JSON runner (host OR container) -------------------------
def fly_json(fly_bin: str, args=None, container: Optional[str] = None,
             timeout: float = 25.0):
    """Run `<fly_bin> <args> --json` on the host, or inside `container` if given.
    Returns parsed JSON or raises RuntimeError. One code path for every extra
    flyctl command the probe needs (status/releases/checks/volumes/ips/scale/certs)."""
    import json as _json
    args = args or []
    if container:
        rc, out, err = exec_in(container, [fly_bin] + args + ["--json"], timeout=timeout)
    else:
        rc, out, err = _run([fly_bin] + args + ["--json"], timeout=timeout)
    if rc != 0:
        raise RuntimeError((err or out or "flyctl error").strip()[:300])
    out = (out or "").strip()
    return _json.loads(out) if out else None