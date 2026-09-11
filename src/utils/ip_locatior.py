import ipaddress
import json
import urllib.request


def locate(ip, timeout=5):
    """Return {"lat","lng","city","region","country"} for a public IP,
    or None. Stdlib only, no API key, no database file. Never raises.
    """
    if not ip or not isinstance(ip, str):
        return None
    ip = ip.strip()

    # private/reserved addresses have no public location - don't waste a call
    try:
        p = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if (p.is_private or p.is_loopback or p.is_link_local
            or p.is_multicast or p.is_reserved or p.is_unspecified):
        return None

    try:
        req = urllib.request.Request(
            f"https://freeipapi.com/api/json/{ip}",
            headers={"User-Agent": "sentinel-agent"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            d = json.loads(resp.read().decode())
    except Exception:
        return None

    lat = d.get("latitude", d.get("lat"))
    lng = d.get("longitude", d.get("lon", d.get("lng")))
    if lat in (None, "") or lng in (None, ""):
        return None

    try:
        lat, lng = float(lat), float(lng)
    except (TypeError, ValueError):
        return None
    if lat == 0 and lng == 0:
        return None                      # null island = failed lookup

    return {
        "lat": lat,
        "lng": lng,
        "city": d.get("cityName") or d.get("city"),
        "region": d.get("regionName") or d.get("region"),
        "country": d.get("countryCode") or d.get("countryName"),
    }