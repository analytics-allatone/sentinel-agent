from typing import List, Dict, Any, Optional
from collections import defaultdict
from sqlalchemy import text
from .sigma_compiler import load_rules
from datetime import datetime

_RULES_BY_TABLE = None

def _load_rules_grouped(rules_path=None):
    global _RULES_BY_TABLE
    if _RULES_BY_TABLE is not None:
        return _RULES_BY_TABLE
    import os
    path = rules_path or os.getenv("SIGMA_RULES_DIR",
        os.path.join(os.path.dirname(__file__), "sigma", "rules", "windows"))
    res = load_rules(path)
    grouped = {}
    for rule in res["rules"]:
        for t in getattr(rule, "tables", [rule.table]):
            grouped.setdefault(t, []).append(rule)
    _RULES_BY_TABLE = grouped
    print(f"[sigma-mem] compiled {res['loaded']} rules across {len(grouped)} tables")
    return grouped


CATEGORY_TABLE = {
    "process": "process_events", "auth": "auth_events", "network": "network_events",
    "file": "file_events", "usb": "usb_events",
    "mysql": "mysql_db_events", "postgres": "postgres_db_events",
    "redis": "redis_db_events", "oracle": "oracle_db_events", "mongo": "mongo_db_events",
}

def _to_dt(v):
    """timestamp ko real datetime banao (string/ISO/Z handle karke)."""
    if v is None or isinstance(v, datetime):
        return v
    s = str(v).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except Exception:
        try:
            return datetime.fromisoformat(s[:19])
        except Exception:
            return None
 

async def run_sigma_on_batch(session, category: str, rows: List[Dict[str, Any]],
                             rules_path: Optional[str] = None, **_) -> dict:
    
    """MEMORY-based: har rule ko batch ke rows pe check karo, DB scan nahi."""
    table = CATEGORY_TABLE.get(category, category)
    grouped = _load_rules_grouped(rules_path)
    # print(table)
    rules = grouped.get(table, [])
    if not rules or not rows:
        return {"ran": 0, "findings": 0, "reason": "no rules or no rows"}
    
    # if rows:
    #     print("RECORD KEYS:", sorted(rows[0].keys()))
    # for rule in rules[:1]:
    #     det = rule.doc.get("detection", {})
    #     # print("RULE:", rule.title[:50])
    #     # print("  detection:", det)
    #     # print("  fieldmap :", rule.fieldmap)
    #     # rule kis column me dhoondh raha hai:
    #     for name, block in det.items():
    #         if name == "condition": continue
    #         if isinstance(block, dict):
    #             for raw_field in block:
    #                 f = raw_field.split("|")[0]
    #                 col = rule.fieldmap.get(f)
                    # have = col.split(".")[-1] in rows[0] if col else False
                    # print(f"    field '{f}' -> column {col} -> record me hai? {have}")
    # har rule -> matching rows -> ek alert (agent+entity ke hisaab se group)
    alerts = []
    findings = 0
    for rule in rules:
        # group matched rows by (agent, entity) -> count/first/last
        groups = defaultdict(list)
        for r in rows:
            try:
                if rule.matches(r):                      # <-- MEMORY match, no DB
                    agent = r.get("agent_name") or r.get("agent_id")
                    entity = (r.get("process_name") or r.get("user_name")
                              or r.get("network_src_ip") or agent)
                    groups[(agent, entity)].append(r)
            except Exception:
                continue
        technique = next((t for t in rule.tags if str(t).startswith("attack.t")), "")
        for (agent, entity), matched in groups.items():
            dts = sorted(d for d in (_to_dt(m.get("timestamp")) for m in matched) if d)
            alerts.append({
                "rule_id": f"SIGMA_{(rule.id or rule.title)[:40]}",
                "severity": int(rule.severity),          # int pakka karo
                "agent_name": agent,
                "entity": str(entity) if entity is not None else None,
                "event_count": len(matched),             # int
                "first_seen": dts[0] if dts else None,    # datetime, NOT str
                "last_seen":  dts[-1] if dts else None,   # datetime, NOT str
                "detail": rule.title[:200],
                "technique": technique,
                "phase": "sigma",
            })
            findings += 1
    if alerts:
        try:
            await session.execute(text("""
                INSERT INTO security_alerts
                  (rule_id, severity, agent_name, entity, event_count,
                   first_seen, last_seen, detail, technique, phase)
                VALUES
                  (:rule_id, :severity, :agent_name, :entity, :event_count,
                   :first_seen, :last_seen, :detail, :technique, :phase)
                ON CONFLICT (rule_id, agent_name, entity, first_seen)
                DO UPDATE SET event_count = EXCLUDED.event_count,
                              last_seen   = EXCLUDED.last_seen
            """), alerts)
            await session.commit()
        except Exception as e:
            await session.rollback()
            return {"ran": len(rules), "findings": 0, "errors": 1,
                    "first_error": str(e)[:160], "batch_size": len(rows)}

    return {"ran": len(rules), "findings": findings, "errors": 0,
            "table": table, "batch_size": len(rows)}
