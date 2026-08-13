"""Junos version parsing + upgrade-target recommendation.

Handles the common release formats seen in Juniper SIRT `affectedVersions`:

    22.4R3              major.minor R<n>
    22.4R3-S5           major.minor R<n> service-pack
    23.4R2-S1-EVO       EVO variant
    22.4X8-D30          X-train development drop
    20.3X75-D51         X-train extended drop
    23.4X30-D10         X-train -Dxx variant
    25.2X30             X-train base

The recommender finds the device's current train (same major.minor, same
release letter R or X, same R/X number, same EVO flag) inside the set of
affected versions, picks the highest service-pack / D-drop that's still
affected, and recommends one step beyond it. If the device's train is
entirely unaffected we say so; if every release in the train is affected
we suggest jumping to the next stable train.
"""
from __future__ import annotations
import re
from typing import Iterable, Optional, Tuple, List


_PATTERNS = [
    # 22.4R3, 22.4R3-S5, 22.4R3.25, 23.4R2-S4.11-EVO, 23.4R2-S1-EVO
    # Order: train -> service pack -> dot build -> EVO suffix.
    re.compile(r"^(?P<maj>\d+)\.(?P<min>\d+)R(?P<rel>\d+)(?:-S(?P<sp>\d+))?(?:\.\d+)?(?P<evo>-EVO)?$"),
    # 25.2X30, 22.4X8-D30, 20.3X75-D51, 25.2X100-D10-EVO
    re.compile(r"^(?P<maj>\d+)\.(?P<min>\d+)X(?P<rel>\d+)(?:-D(?P<sp>\d+))?(?:\.\d+)?(?P<evo>-EVO)?$"),
]


def parse_version(v: str) -> Optional[dict]:
    """Return a dict describing a Junos release, or None if it can't be parsed."""
    if not v:
        return None
    v = v.strip()
    for i, pat in enumerate(_PATTERNS):
        m = pat.match(v)
        if not m:
            continue
        return {
            "raw": v,
            "kind": "R" if i == 0 else "X",
            "major": int(m.group("maj")),
            "minor": int(m.group("min")),
            "release": int(m.group("rel")),
            "service": int(m.group("sp")) if m.group("sp") else 0,
            "evo": bool(m.group("evo")),
        }
    return None


def _train_key(p: dict) -> Tuple:
    return (p["major"], p["minor"], p["kind"], p["release"], p["evo"])


def _format(p: dict, service: int) -> str:
    base = f"{p['major']}.{p['minor']}{p['kind']}{p['release']}"
    suffix = f"-S{service}" if p["kind"] == "R" else f"-D{service}"
    evo = "-EVO" if p["evo"] else ""
    if service == 0:
        return f"{base}{evo}"
    return f"{base}{suffix}{evo}"


def recommend_upgrade(current: str, affected: Iterable[str]) -> dict:
    """Recommend an upgrade target given the device's current release and the
    pooled `affectedVersions` from every advisory affecting it.

    Returns a dict:
      {
        "current": <current>,
        "recommendation": <human string>,
        "target": <release string or None>,
        "rationale": <short text>
      }
    """
    cur = parse_version(current or "")
    affected_parsed: List[dict] = [p for p in (parse_version(a) for a in affected) if p]

    if not affected_parsed:
        return {
            "current": current,
            "recommendation": "No affected releases reported for the exposed advisories.",
            "target": None,
            "rationale": "No data."
        }

    # If we can't parse the device's current version, give a generic answer
    # based on the most-recent affected R-train in the pool.
    if not cur:
        latest = max(affected_parsed, key=lambda p: (p["major"], p["minor"],
                                                      p["release"], p["service"]))
        nxt = _format(latest, latest["service"] + 1)
        return {
            "current": current,
            "recommendation": f"Upgrade beyond {latest['raw']} (e.g. {nxt} or later).",
            "target": nxt,
            "rationale": "Device firmware string could not be parsed; recommendation based on the highest affected release across all advisories.",
        }

    # Pool affected versions inside the device's current train.
    cur_train = _train_key(cur)
    same_train = [p for p in affected_parsed if _train_key(p) == cur_train]

    if not same_train:
        return {
            "current": current,
            "recommendation": f"{current} is not on the published affected-versions list for any exposed advisory in this device's train. Verify each JSA's affected-versions list directly and apply patches if Juniper lists a fix specific to your build.",
            "target": current,
            "rationale": "Current train not present in affectedVersions.",
        }

    # Find the highest service / D-drop inside the same train that's affected.
    max_service = max(p["service"] for p in same_train)
    target_service = max_service + 1
    target = _format(cur, target_service)

    # If the device is already past the highest affected service, no upgrade
    # is needed inside this train.
    if cur["service"] > max_service:
        return {
            "current": current,
            "recommendation": f"{current} is newer than every affected build in the {cur['major']}.{cur['minor']}{cur['kind']}{cur['release']} train; no upgrade required in this train for the listed advisories.",
            "target": current,
            "rationale": f"Highest affected build in train is {_format(cur, max_service)}.",
        }

    return {
        "current": current,
        "recommendation": f"Upgrade to {target} or later (next service-pack beyond the highest affected build {_format(cur, max_service)} in the {cur['major']}.{cur['minor']}{cur['kind']}{cur['release']} train).",
        "target": target,
        "rationale": f"Highest affected build in current train is {_format(cur, max_service)}.",
    }


SEVERITY_LEVEL_MAP = {
    "CVSS_LEVEL_CRITICAL": "Critical",
    "CVSS_LEVEL_HIGH": "High",
    "CVSS_LEVEL_MEDIUM": "Medium",
    "CVSS_LEVEL_LOW": "Low",
    "CVSS_LEVEL_NONE": "None",
}


def normalize_severity(level: Optional[str], score: Optional[str]) -> Optional[str]:
    """Pick a human severity string from the SIRT severityLevel field, falling
    back to a CVSS-score bucket if needed."""
    if level and level in SEVERITY_LEVEL_MAP:
        return SEVERITY_LEVEL_MAP[level]
    try:
        s = float(score) if score is not None else None
    except (TypeError, ValueError):
        s = None
    if s is None:
        return None
    if s >= 9.0:
        return "Critical"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    if s > 0:
        return "Low"
    return "None"


# --- Workaround / configuration extraction ---------------------------------

# Detects Junos CLI prompts that may appear inline before a configuration command.
_PROMPT_RE = re.compile(r"^(?:[\w.-]+@[\w.-]+[>#]\s*)+", re.MULTILINE)
# A line is treated as a configuration command if it starts with one of these
# verbs (allowing leading whitespace and an optional bracket).
_CFG_VERBS = (
    "set", "delete", "deactivate", "activate", "rename", "insert", "edit",
    "commit", "rollback", "load", "file change-permission",
)
_VERB_RE = re.compile(
    r"^\s*\[?\s*(" + "|".join(re.escape(v) for v in _CFG_VERBS) + r")\b",
    re.IGNORECASE,
)


def extract_config_commands(workaround: str) -> List[str]:
    """Pull Junos-style CLI / configuration lines out of an advisory workaround.

    Returns an ordered list of unique command strings with CLI prompts and the
    occasional wrapping square brackets stripped. Returns an empty list when
    the workaround is purely advisory text (e.g. "disable J-Web" with no
    config snippet).
    """
    if not workaround:
        return []
    text = _PROMPT_RE.sub("", workaround)
    lines = [ln.strip() for ln in text.splitlines()]
    out: List[str] = []
    seen = set()
    for ln in lines:
        if not ln:
            continue
        # Bracket-shorthand for a Junos config hierarchy
        # (e.g. "[ system root-authentication no-public-keys ]") — Juniper SIRT
        # uses this to mean "set this knob". Re-emit as an explicit `set` line.
        if (ln.startswith("[") and ln.endswith("]")
                and re.fullmatch(r"\[\s*[a-z0-9][a-z0-9 \-]*\]", ln)):
            inner = ln[1:-1].strip()
            ln = f"set {inner}"
        if not _VERB_RE.match(ln):
            continue
        # Strip wrapping brackets that may surround a real verb line.
        if ln.startswith("[") and ln.endswith("]"):
            ln = ln[1:-1].strip()
        # Drop trailing punctuation that often follows in prose.
        ln = ln.rstrip(" .;")
        if ln and ln not in seen:
            seen.add(ln)
            out.append(ln)
    return out

