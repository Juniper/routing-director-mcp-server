"""Security-report generator.

Produces a SIRT-vs-active-config exposure report as two artifacts that match
the conventions used by the existing reports under ``reports/``:

  * A styled Word document rendered into the corporate HPE template
    (``HPE_Graphik_A4.dotx``) sitting at the repository root.
  * A JSON snapshot of the raw correlation result for reproducibility.

This module is the single source of truth for security-report generation.
``scripts/security_report.py`` is a thin CLI shim around
``generate_security_report``; the MCP server registers the same function as
an LLM-callable tool (see ``utils/mcp/trust.py``) so any client of the MCP
server gets the styled ``.docx`` + ``.json`` pair directly — never a
plain-text report.
"""
from __future__ import annotations

import datetime as dt
import io
import json
import os
import re
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor
from utils.lm_calls.tools.helper import validate_org_id

REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_TEMPLATE = REPO_ROOT / "utils/lm_calls/tools/HPE_Graphik_A4.dotx"
DEFAULT_REPORTS_DIR = REPO_ROOT / "security-reports"


# ---------------------------------------------------------------------------
# Device grouping (collapse devices that share model / firmware / exposure).
# ---------------------------------------------------------------------------

def _exposure_signature(d: dict) -> frozenset:
    sig = set()
    for f in d.get("exposed_findings") or []:
        key = f.get("sirtId") or f.get("advisoryId") or ""
        matches = tuple(sorted(f.get("matches") or []))
        sig.add((key, matches))
    return frozenset(sig)


def _group_key(d: dict) -> Tuple:
    return (
        d.get("model") or "",
        d.get("firmware") or "",
        d.get("recommended_release") or "",
        _exposure_signature(d),
    )


def group_devices(devices: List[dict]) -> List[Dict[str, Any]]:
    """Collapse devices with identical model/firmware/exposure into groups."""
    buckets: Dict[Tuple, Dict[str, Any]] = {}
    order: List[Tuple] = []
    for d in devices:
        if not d.get("exposed_findings"):
            continue
        k = _group_key(d)
        if k not in buckets:
            buckets[k] = {"key": k, "representative": d, "members": []}
            order.append(k)
        buckets[k]["members"].append({
            "hostname": d.get("hostname") or "",
            "management_ip": d.get("management_ip") or "",
            "ems_uuid": d.get("ems_uuid"),
        })

    groups: List[Dict[str, Any]] = []
    for k in order:
        b = buckets[k]
        b["members"].sort(key=lambda m: (m["hostname"] or "", m["management_ip"] or ""))
        groups.append(b)

    groups.sort(key=lambda g: (
        -len(g["representative"].get("exposed_findings") or []),
        -len(g["members"]),
        (g["representative"].get("hostname") or ""),
    ))
    return groups


# ---------------------------------------------------------------------------
# Word rendering helpers.
# ---------------------------------------------------------------------------

# python-docx will not open a .dotx directly because its [Content_Types].xml
# advertises the wordprocessingml *template* content type. The file is
# structurally a normal Office Open XML package, so we rewrite the content
# type to the *document* one and let python-docx open the resulting bytes.
TEMPLATE_CT = "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml"
DOCUMENT_CT = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"


def _dotx_to_docx_bytes(path: Path) -> bytes:
    src = zipfile.ZipFile(path, "r")
    buf = io.BytesIO()
    dst = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    try:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "[Content_Types].xml":
                data = data.replace(TEMPLATE_CT.encode(), DOCUMENT_CT.encode())
            dst.writestr(item, data)
    finally:
        src.close()
        dst.close()
    return buf.getvalue()


def _clear_body(doc) -> None:
    body = doc.element.body
    for child in list(body):
        if child.tag == qn("w:sectPr"):
            continue
        body.remove(child)


SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, None: 4, "": 4, "Unrated": 4}
SEV_COLOR = {
    "Critical": RGBColor(0xC0, 0x00, 0x00),
    "High":     RGBColor(0xE8, 0x6C, 0x00),
    "Medium":   RGBColor(0xB8, 0x86, 0x0B),
    "Low":      RGBColor(0x2E, 0x7D, 0x32),
    "Unrated":  RGBColor(0x55, 0x55, 0x55),
}


def _clean(text: str, limit: int = 800) -> str:
    if not text:
        return ""
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _shade_cell(cell, hex_rgb: str) -> None:
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_rgb)
    tcPr.append(shd)


def _set_cell_lines(cell, lines, bold_first: bool = False, size: int = 10) -> None:
    lines = [ln for ln in lines if ln is not None and ln != ""]
    cell.text = ""
    if not lines:
        return
    first_p = cell.paragraphs[0]
    first_run = first_p.add_run(lines[0])
    first_run.font.size = Pt(size)
    if bold_first:
        first_run.bold = True
    for ln in lines[1:]:
        p = cell.add_paragraph()
        r = p.add_run(ln)
        r.font.size = Pt(size)


def _use_style(doc, style_name: str, fallback: str = "Normal") -> str:
    try:
        _ = doc.styles[style_name]
        return style_name
    except KeyError:
        return fallback


def _heading(doc, text: str, level: int):
    style = _use_style(doc, f"Heading {level}", "Heading 1")
    return doc.add_paragraph(text, style=style)


def _para(doc, text: str, bold: bool = False, size: int = 10) -> None:
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.bold = bold
    r.font.size = Pt(size)


def _device_severity_summary(device) -> dict:
    counts: Dict[str, int] = defaultdict(int)
    for f in device["exposed_findings"]:
        counts[f.get("severity") or "Unrated"] += 1
    return counts


def _add_summary_table(doc, groups) -> None:
    if not groups:
        _para(doc, "No devices have confirmed configuration-relevant SIRT exposure.")
        return
    table = doc.add_table(rows=1, cols=6)
    table.style = _use_style(doc, "Light Grid Accent 1", "Table Grid")
    hdr = table.rows[0].cells
    hdr[0].text = "Devices"
    hdr[1].text = "Model"
    hdr[2].text = "Current firmware"
    hdr[3].text = "Findings"
    hdr[4].text = "Top severity"
    hdr[5].text = "Recommended release"
    for cell in hdr:
        for p in cell.paragraphs:
            for r in p.runs:
                r.bold = True
        _shade_cell(cell, "1F3864")
        for p in cell.paragraphs:
            for r in p.runs:
                r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
    for g in groups:
        d = g["representative"]
        counts = _device_severity_summary(d)
        top_sev = min(counts.keys(), key=lambda s: SEV_RANK.get(s, 4)) if counts else "Unrated"
        row = table.add_row().cells
        member_names = [m["hostname"] for m in g["members"]]
        if len(member_names) == 1:
            row[0].text = member_names[0]
        else:
            _set_cell_lines(row[0],
                            [f"{len(member_names)} devices:", ", ".join(member_names)],
                            bold_first=True)
        row[1].text = d["model"] or ""
        row[2].text = d["firmware"] or ""
        row[3].text = str(len(d["exposed_findings"]))
        row[4].text = top_sev
        row[5].text = d.get("recommended_release") or "n/a"


def _add_device_section(doc, group) -> None:
    d = group["representative"]
    members = group["members"]
    if len(members) == 1:
        m = members[0]
        heading = f"{m['hostname']}  ({m['management_ip'] or 'no mgmt ip'})"
    else:
        heading = (f"{len(members)} devices with identical exposure — "
                   f"{d['model'] or 'unknown model'} / {d['firmware'] or 'unknown firmware'}")
    _heading(doc, heading, 2)

    if len(members) > 1:
        intro = doc.add_paragraph()
        intro.add_run("The following devices share the same model, running release, and exposed advisories. "
                      "The findings and recommended actions below apply to all of them:").italic = True
        member_tbl = doc.add_table(rows=1, cols=2)
        member_tbl.style = _use_style(doc, "Light Grid Accent 1", "Table Grid")
        mh = member_tbl.rows[0].cells
        mh[0].text = "Hostname"
        mh[1].text = "Management IP"
        for cell in mh:
            _shade_cell(cell, "1F3864")
            for p in cell.paragraphs:
                for r in p.runs:
                    r.bold = True
                    r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        for m in members:
            row = member_tbl.add_row().cells
            row[0].text = m["hostname"] or ""
            row[1].text = m["management_ip"] or ""

    meta = doc.add_paragraph()
    meta.add_run("Model: ").bold = True
    meta.add_run(d['model'] or 'unknown').italic = True
    meta.add_run("   Firmware: ").bold = True
    meta.add_run(d['firmware'] or 'unknown').italic = True
    meta.add_run("   Exposed findings: ").bold = True
    meta.add_run(str(len(d['exposed_findings'])))

    rec = d.get("upgrade_recommendation")
    if rec:
        p = doc.add_paragraph()
        p.add_run("Recommended release: ").bold = True
        r = p.add_run(d.get("recommended_release") or "n/a")
        r.bold = True
        r.font.color.rgb = RGBColor(0x1F, 0x38, 0x64)
        p2 = doc.add_paragraph(rec)
        for run in p2.runs:
            run.font.size = Pt(9)
            run.italic = True

    if not d["exposed_findings"]:
        _para(doc, "No configuration-relevant exposure.")
        return

    findings = sorted(
        d["exposed_findings"],
        key=lambda f: (SEV_RANK.get(f.get("severity"), 4),
                       -float(f.get("cvssScore") or 0))
    )
    table = doc.add_table(rows=1, cols=5)
    table.style = _use_style(doc, "Light Grid Accent 1", "Table Grid")
    hdr = table.rows[0].cells
    hdr[0].text = "Severity"
    hdr[1].text = "CVSS"
    hdr[2].text = "JSA / CVE"
    hdr[3].text = "Exposed via"
    hdr[4].text = "Recommendation"
    for cell in hdr:
        _shade_cell(cell, "1F3864")
        for p in cell.paragraphs:
            for r in p.runs:
                r.bold = True
                r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    for f in findings:
        sev = f.get("severity") or "Unrated"
        row = table.add_row().cells
        row[0].text = sev
        for p in row[0].paragraphs:
            for r in p.runs:
                r.bold = True
                r.font.color.rgb = SEV_COLOR.get(sev, RGBColor(0x33, 0x33, 0x33))
        row[1].text = str(f.get("cvssScore") or "")
        jsa = f.get("sirtId") or ""
        cves = ", ".join(f.get("cveIds") or [])
        if cves:
            _set_cell_lines(row[2], [jsa, cves])
        else:
            row[2].text = jsa
        row[3].text = ", ".join(f.get("matches") or [])
        wa = _clean(f.get("workaround"), 600)
        if not wa:
            wa = (f"Upgrade Junos to a release that fixes {jsa or 'this advisory'} "
                  f"(see Juniper SIRT). No vendor workaround published.")
        rec_cell = row[4]
        rec_cell.text = ""
        p_title = rec_cell.paragraphs[0]
        r_title = p_title.add_run(f.get("title") or "")
        r_title.bold = True
        r_title.font.size = Pt(9)
        p_wa = rec_cell.add_paragraph(wa)
        for r in p_wa.runs:
            r.font.size = Pt(9)

    _add_config_subsection(doc, findings)


def _add_config_subsection(doc, findings) -> None:
    blocks = [(f.get("sirtId") or f.get("advisoryId"),
               f.get("title") or "",
               f.get("configCommands") or [])
              for f in findings if f.get("configCommands")]
    heading_style = _use_style(doc, "Heading 3", "Heading 2")
    doc.add_paragraph("Recommended configuration changes", style=heading_style)

    if not blocks:
        note = doc.add_paragraph(
            "No published workaround for the exposed findings on this device includes "
            "a configuration snippet. Mitigation is limited to the operational guidance "
            "in the table above (e.g. disable affected service, restrict access via "
            "firewall filters) and/or the upgrade recommendation."
        )
        for r in note.runs:
            r.italic = True
            r.font.size = Pt(9)
        return

    intro = doc.add_paragraph(
        "Apply the following Junos configuration commands. Each block is labelled "
        "with the JSA it addresses; commit only after reviewing for impact in your "
        "environment."
    )
    for r in intro.runs:
        r.font.size = Pt(9)

    code_style = _use_style(doc, "HTML Preformatted", "Normal")
    for sirt, title, cmds in blocks:
        h = doc.add_paragraph()
        rh = h.add_run(f"{sirt} — {title}")
        rh.bold = True
        rh.font.size = Pt(10)
        rh.font.color.rgb = RGBColor(0x1F, 0x38, 0x64)
        for cmd in cmds:
            cp = doc.add_paragraph(style=code_style)
            cr = cp.add_run(cmd)
            cr.font.name = "Consolas"
            rPr = cr._element.get_or_add_rPr()
            rFonts = rPr.find(qn("w:rFonts"))
            if rFonts is None:
                rFonts = OxmlElement("w:rFonts")
                rPr.append(rFonts)
            rFonts.set(qn("w:ascii"), "Consolas")
            rFonts.set(qn("w:hAnsi"), "Consolas")
            rFonts.set(qn("w:cs"), "Consolas")
            cr.font.size = Pt(9)


def _add_org_priorities(doc, rep) -> None:
    org_wide: Dict[str, dict] = defaultdict(lambda: {"sirtId": None, "title": None, "severity": None,
                                                       "cvss": None, "workaround": None, "matches": set(),
                                                       "devices": []})
    for d in rep["devices"]:
        for f in d["exposed_findings"]:
            key = f["sirtId"] or f["advisoryId"]
            e = org_wide[key]
            e["sirtId"] = f["sirtId"]
            e["title"] = f["title"]
            e["severity"] = f["severity"] or e["severity"]
            e["cvss"] = f.get("cvssScore") or e["cvss"]
            e["workaround"] = f.get("workaround") or e["workaround"]
            e["matches"].update(f.get("matches") or [])
            e["devices"].append(d["hostname"])

    ranked = sorted(org_wide.values(),
                    key=lambda e: (SEV_RANK.get(e["severity"], 4),
                                   -float(e.get("cvss") or 0),
                                   -len(e["devices"])))
    if not ranked:
        return

    table = doc.add_table(rows=1, cols=5)
    table.style = _use_style(doc, "Light Grid Accent 1", "Table Grid")
    hdr = table.rows[0].cells
    hdr[0].text = "Severity"
    hdr[1].text = "JSA"
    hdr[2].text = "Title"
    hdr[3].text = "Features"
    hdr[4].text = "Affected devices"
    for cell in hdr:
        _shade_cell(cell, "1F3864")
        for p in cell.paragraphs:
            for r in p.runs:
                r.bold = True
                r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
    for e in ranked[:20]:
        sev = e["severity"] or "Unrated"
        row = table.add_row().cells
        row[0].text = sev + (f"  ({e['cvss']})" if e["cvss"] else "")
        for p in row[0].paragraphs:
            for r in p.runs:
                r.bold = True
                r.font.color.rgb = SEV_COLOR.get(sev, RGBColor(0x33, 0x33, 0x33))
        row[1].text = e["sirtId"] or ""
        row[2].text = _clean(e["title"], 180)
        row[3].text = ", ".join(sorted(e["matches"]))
        devs = sorted(set(e["devices"]))
        header = f"{len(devs)} device{'s' if len(devs)!=1 else ''}"
        _set_cell_lines(row[4], [header, ", ".join(devs)], bold_first=True)


def build_report(template: Path, out_path: Path, rep: dict) -> Path:
    if template.suffix.lower() == ".dotx":
        doc = Document(io.BytesIO(_dotx_to_docx_bytes(template)))
    else:
        doc = Document(str(template))

    _clear_body(doc)

    title_style = _use_style(doc, "Title", "Heading 1")
    p = doc.add_paragraph("Network Security Vulnerability Report", style=title_style)
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    subtitle = doc.add_paragraph()
    subtitle.add_run("Juniper SIRT exposure cross-referenced with active configuration"
                     ).italic = True
    meta = doc.add_paragraph()
    meta.add_run(f"Generated: {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}\n").bold = True
    s = rep["summary"]
    meta.add_run(
        f"Devices evaluated: {s['devices_evaluated']}    "
        f"Devices with exposure: {s['devices_with_exposure']}    "
        f"Total exposed findings: {s['total_exposed_findings']}"
    )

    groups = group_devices(rep["devices"])
    meta.add_run(f"    Distinct exposure groups: {len(groups)}")

    _heading(doc, "Executive summary", 1)
    doc.add_paragraph(
        "This report lists only the Juniper SIRT advisories whose subject overlaps "
        "with features actually enabled in each device's latest configuration "
        "as reported by Routing Director. Devices that share the same model, "
        "running release, and exposed advisories are grouped into a single "
        "section so identical guidance is not repeated. Per-group recommendations "
        "include the next stable Junos release in the devices' current train, "
        "derived from the union of affectedVersions across every confirmed exposure."
    )

    _add_summary_table(doc, groups)

    _heading(doc, "Per-device findings", 1)
    for g in groups:
        _add_device_section(doc, g)

    _heading(doc, "Top organisation-wide priorities", 1)
    _add_org_priorities(doc, rep)

    _heading(doc, "Methodology", 1)
    doc.add_paragraph(
        "1. Trust component vulnerability advisories are listed per device via the "
        "Routing Director Trust API.\n"
        "2. Each advisory's full definition (severityLevel, CVSS score, CVE IDs, "
        "workaround text, affectedVersions) is fetched.\n"
        "3. The device's latest committed configuration is retrieved through the "
        "Routing Director EMS latest_config endpoint.\n"
        "4. A regex feature-map is applied: an advisory is reported as an active "
        "exposure for the device only when its subject feature (e.g. SNMP, DHCP "
        "relay, BGP, NETCONF) is present in the running config.\n"
        "5. The recommended release per device is the next service-pack beyond "
        "the highest affected build in the device's current Junos train, computed "
        "from the union of affectedVersions across all of its exposed advisories."
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out_path))
    return out_path


# ---------------------------------------------------------------------------
# Public entrypoint (CLI + MCP tool both call this).
# ---------------------------------------------------------------------------

@validate_org_id
def generate_security_report(
        org_id: str,
        out_dir: Optional[str] = None,
        template_path: Optional[str] = None,
        cached_json: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate the canonical network-security vulnerability report.

    Cross-references Juniper SIRT advisories with each device's active
    configuration (via ``correlate_sirt_with_active_config``) and writes two
    artifacts into ``out_dir``:

      * ``network_security_report_<YYYY-MM-DD>.docx`` — styled Word report
        rendered into the HPE corporate template (``HPE_Graphik_A4.dotx``).
      * ``network_security_report_<YYYY-MM-DD>.json`` — raw correlation
        result, suitable for diffing day-over-day or re-rendering offline.

    This is the canonical security-report tool. Prefer this single call over
    invoking ``correlate_sirt_with_active_config`` and post-processing the
    result yourself — it guarantees the styled .docx + .json pair that
    operators expect in ``reports/``.

    param org_id: ORG ID of the organization. Mandatory.
    param out_dir: Directory to write artifacts into. Defaults to the
                   ``reports/`` directory at the repository root.
    param template_path: Optional override for the Word template. Defaults to
                         ``HPE_Graphik_A4.dotx`` at the repository root.
    param cached_json: Optional path to a previously-written JSON snapshot. If
                       provided, the report is regenerated from that snapshot
                       without re-calling the Routing Director APIs.
    return: {
      "docx_path":    "<absolute path to the .docx artifact>",
      "json_path":    "<absolute path to the .json artifact>",
      "summary":      {devices_evaluated, devices_with_exposure,
                       total_exposed_findings},
      "exposure_groups": <int — number of distinct device groups>,
      "unique_advisories": <int — distinct CVE/JSA advisories with exposure>
    }
    """
    template = Path(template_path) if template_path else DEFAULT_TEMPLATE
    if not template.exists():
        return {"error": f"Word template not found: {template}"}

    out_directory = Path(out_dir) if out_dir else DEFAULT_REPORTS_DIR
    out_directory.mkdir(parents=True, exist_ok=True)

    today = dt.date.today().strftime("%Y-%m-%d")
    docx_path = out_directory / f"network_security_report_{today}.docx"
    json_path = docx_path.with_suffix(".json")

    if cached_json:
        with open(cached_json) as f:
            rep = json.load(f)
    else:
        # Local import to avoid a circular import at module load time
        # (utils.mcp.trust imports from this module).
        from utils.lm_calls.tools.trust.trust import correlate_sirt_with_active_config
        rep = correlate_sirt_with_active_config(org_id=org_id)
        if isinstance(rep, dict) and rep.get("error"):
            return rep

    with open(json_path, "w") as f:
        json.dump(rep, f, default=str, indent=2)

    build_report(template, docx_path, rep)

    unique_advisories = {
        f.get("sirtId") or f.get("advisoryId")
        for d in rep.get("devices", [])
        for f in d.get("exposed_findings") or []
    }
    return {
        "docx_path": str(docx_path),
        "json_path": str(json_path),
        "summary": rep.get("summary", {}),
        "exposure_groups": len(group_devices(rep.get("devices", []))),
        "unique_advisories": len(unique_advisories),
    }
