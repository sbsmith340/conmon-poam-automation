"""
Continuous monitoring pipeline: monthly scan exports in, POA&M and ConMon report out.

  python tools/conmon.py            # process every month, write poam/, oscal/, reports/
  python tools/conmon.py --check    # same, but write nothing; fail if outputs are stale or invalid (CI)

For each scan month, in order, it:
  1. Normalizes findings and drops informational results.
  2. Opens a POA&M item the first time a weakness is detected, tracks every affected asset,
     closes an asset only when a later scan reaches that asset and no longer finds the weakness,
     closes the item when every affected asset is closed, and reopens it if the weakness returns.
  3. Treats an inventoried asset the scanner did not reach as a coverage gap (not as a fix),
     and a scanned asset missing from the inventory as an inventory finding.
  4. Applies deviation requests and vendor dependencies (deviations.yaml) by their dates.
  5. Computes due dates from the policy (config/policy.yaml) and flags overdue items.
Outputs: a FedRAMP-style POA&M CSV, an OSCAL 1.1.2 POA&M validated against the NIST schema,
and a Markdown ConMon report for every month.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import uuid
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
OSCAL_VERSION = "1.1.2"
# Same namespace and system ID as the companion oscal-ato-package repo, so the system UUIDs match.
NS = uuid.UUID("6f1c4a2e-0b7d-4e55-9a3c-5d8f0e2b7c11")
SYSTEM_ID = "FIP-2026-001"
SSP_HREF = "https://raw.githubusercontent.com/sbsmith340/oscal-ato-package/main/oscal/ssp.json"
FEDRAMP_NS = "https://fedramp.gov/ns/oscal"
RISK_ORDER = ["Critical", "High", "Moderate", "Low"]


def uid(*parts: str) -> str:
    return str(uuid.uuid5(NS, "/".join(parts)))


def d(s) -> date:
    return s if isinstance(s, date) else date.fromisoformat(str(s))


# --------------------------------------------------------------------------- inputs
def load_inputs(root: Path = ROOT):
    policy = yaml.safe_load((root / "config" / "policy.yaml").read_text())
    dev = yaml.safe_load((root / "deviations.yaml").read_text()) or {}
    with open(root / "data" / "inventory.csv", newline="") as f:
        inventory = {r["asset"]: r for r in csv.DictReader(f)}
    scans = {}
    for p in sorted((root / "data" / "scans").glob("*.csv")):
        with open(p, newline="") as f:
            scans[p.stem] = list(csv.DictReader(f))
    return policy, dev.get("deviations", []) or [], dev.get("vendor_dependencies", []) or [], inventory, scans


def validate_deviations(deviations, vds, findings_by_plugin) -> list[str]:
    """Rules a ConMon reviewer would reject a deviation package for."""
    errs = []
    seen = set()
    for dv in deviations:
        tag = dv.get("id", "?")
        if tag in seen:
            errs.append(f"{tag}: duplicate deviation ID")
        seen.add(tag)
        if dv["type"] not in {"FP", "RA", "OR"}:
            errs.append(f"{tag}: type must be FP, RA or OR (vendor dependencies are not deviations)")
        if dv["plugin_id"] not in findings_by_plugin:
            errs.append(f"{tag}: plugin {dv['plugin_id']} never appears in any scan")
            continue
        if dv["status"] not in {"approved", "pending", "rejected"}:
            errs.append(f"{tag}: unknown status {dv['status']!r}")
        if dv["status"] == "approved" and not dv.get("approved_on"):
            errs.append(f"{tag}: approved without an approval date")
        if dv["status"] != "approved" and dv.get("approved_on"):
            errs.append(f"{tag}: has an approval date but status is {dv['status']}")
        if not str(dv.get("rationale", "")).strip():
            errs.append(f"{tag}: missing rationale")
        original = findings_by_plugin[dv["plugin_id"]]["severity"]
        if dv["type"] == "RA":
            adj = dv.get("adjusted_risk")
            if adj not in RISK_ORDER or RISK_ORDER.index(adj) <= RISK_ORDER.index(original):
                errs.append(f"{tag}: a risk adjustment must lower the rating (from {original}, got {adj})")
        if dv["type"] == "OR":
            effective = original
            for other in deviations:
                if other["plugin_id"] == dv["plugin_id"] and other["type"] == "RA" and other["status"] == "approved":
                    effective = other["adjusted_risk"]
            if effective in {"Critical", "High"}:
                errs.append(f"{tag}: an operational requirement cannot be approved for a {effective} risk")
            if not dv.get("reassess_by"):
                errs.append(f"{tag}: an operational requirement needs a reassess_by date")
    for vd in vds:
        if vd["plugin_id"] not in findings_by_plugin:
            errs.append(f"vendor dependency {vd['plugin_id']}: plugin never appears in any scan")
        if not vd.get("checkins"):
            errs.append(f"vendor dependency {vd['plugin_id']}: no vendor check-ins recorded")
    return errs


# --------------------------------------------------------------------------- state
@dataclass
class AssetState:
    first_seen: date
    last_seen: date
    closed_on: date | None = None


@dataclass
class Item:
    poam_id: str
    key: str                      # scanner plugin ID, or COV-/INV-<asset> for program findings
    title: str
    cve: str
    category: str
    controls: list[str]
    original_risk: str
    solution: str
    first_detected: date
    detected: date                # start of the current open episode (resets on reopen)
    assets: dict[str, AssetState] = field(default_factory=dict)
    closed_on: date | None = None
    recurrences: int = 0
    events: list[tuple[date, str]] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        return self.closed_on is None

    def open_assets(self) -> list[str]:
        return sorted(a for a, s in self.assets.items() if s.closed_on is None)


@dataclass
class View:
    """An item as it stands on a given report date, after deviations are applied."""
    item: Item
    status: str                   # Open | Closed | Risk accepted (OR)
    closure: str                  # "", remediated, false positive
    closed_on: date | None
    risk: str                     # adjusted risk
    due: date
    overdue: bool
    days_overdue: int
    deviation: dict | None
    deviation_note: str
    vd: dict | None
    vd_note: str
    unverified_assets: list[str]


class Pipeline:
    def __init__(self, policy, deviations, vds, inventory, scans):
        self.policy, self.deviations, self.vds = policy, deviations, vds
        self.inventory, self.scans = inventory, scans
        self.items: dict[str, Item] = {}
        self.counter = 0
        self.snapshots: dict[str, dict] = {}
        ignore = set(policy.get("ignore_severities", []))
        self.findings_by_plugin = {}
        for rows in scans.values():
            for r in rows:
                if r["severity"] not in ignore:
                    self.findings_by_plugin.setdefault(r["plugin_id"], r)

    # ---- helpers
    def _new_item(self, key, title, cve, category, risk, solution, when) -> Item:
        self.counter += 1
        it = Item(poam_id=f"V-{self.counter:04d}", key=key, title=title, cve=cve, category=category,
                  controls=self.policy["category_controls"][category], original_risk=risk,
                  solution=solution, first_detected=when, detected=when)
        it.events.append((when, "opened"))
        self.items[key] = it
        return it

    def _deviation_for(self, key, on: date):
        """The deviation that applies on a date: an approved one in force, else the latest pending one."""
        approved = [x for x in self.deviations if x["plugin_id"] == key and x["status"] == "approved"
                    and d(x["approved_on"]) <= on]
        if approved:
            return approved[-1]
        pending = [x for x in self.deviations if x["plugin_id"] == key and x["status"] == "pending"
                   and d(x["requested_on"]) <= on]
        return pending[-1] if pending else None

    def _vd_for(self, key, on: date):
        for vd in self.vds:
            if vd["plugin_id"] == key and d(vd["opened_on"]) <= on:
                return vd
        return None

    # ---- monthly processing
    def process(self, month: str, rows: list[dict]) -> None:
        scan_date = d(rows[0]["scan_date"])
        ignore = set(self.policy.get("ignore_severities", []))
        scanned = {r["asset"] for r in rows}
        detected: dict[str, list[dict]] = {}
        for r in rows:
            if r["severity"] not in ignore:
                detected.setdefault(r["plugin_id"], []).append(r)

        # program findings: coverage gaps and unknown assets become their own pseudo-findings
        for asset in self.inventory:
            if asset not in scanned:
                detected.setdefault(f"COV-{asset}", []).append({
                    "asset": asset, "title": "Inventoried asset not reached by the monthly scan",
                    "cve": "", "category": "coverage", "severity": "Moderate",
                    "solution": "Confirm the asset is powered on and reachable with credentials, then rescan."})
        for asset in sorted(scanned - set(self.inventory)):
            detected.setdefault(f"INV-{asset}", []).append({
                "asset": asset, "title": "Scanned asset missing from the system inventory",
                "cve": "", "category": "inventory", "severity": "Moderate",
                "solution": "Add the asset to the inventory with an owner, or decommission it."})

        program_keys = {k for k in detected if k.startswith(("COV-", "INV-"))}
        for key in sorted(detected):
            hits = detected[key]
            first = hits[0]
            it = self.items.get(key)
            if it is None:
                it = self._new_item(key, first["title"], first.get("cve", ""), first["category"],
                                    first["severity"], first.get("solution", ""), scan_date)
            elif not it.is_open:
                it.closed_on = None
                it.detected = scan_date
                it.recurrences += 1
                it.events.append((scan_date, "reopened: weakness detected again after closure"))
                for a in it.assets.values():
                    a.closed_on = a.closed_on or scan_date
            for h in hits:
                a = it.assets.get(h["asset"])
                if a is None or a.closed_on is not None:
                    if a is None and it.assets:
                        it.events.append((scan_date, f"new affected asset {h['asset']}"))
                    it.assets[h["asset"]] = AssetState(first_seen=scan_date, last_seen=scan_date)
                else:
                    a.last_seen = scan_date

        # anything open but not detected: close only where the scan actually reached the asset
        for key, it in self.items.items():
            if not it.is_open or key in detected:
                if it.is_open and key in detected:
                    seen = {h["asset"] for h in detected[key]}
                    self._close_absent_assets(it, seen, scanned, scan_date, key in program_keys)
                continue
            self._close_absent_assets(it, set(), scanned, scan_date, key.startswith(("COV-", "INV-")))

        # freeze the month's view so later months mutating the items can't change it
        prev = list(self.snapshots.values())[-1]["date"] if self.snapshots else date.min
        self.snapshots[month] = {"date": scan_date, "prev": prev, "scanned": sorted(scanned),
                                 "frozen": {k: _freeze(self.view(it, scan_date)) for k, it in self.items.items()}}

    def _close_absent_assets(self, it: Item, seen: set, scanned: set, when: date, program: bool) -> None:
        for name, a in it.assets.items():
            if a.closed_on is None and name not in seen and (program or name in scanned):
                a.closed_on = when
                it.events.append((when, f"no longer detected on {name}"))
        if it.assets and all(a.closed_on is not None for a in it.assets.values()):
            it.closed_on = when
            it.events.append((when, "closed: not detected on any affected asset"))

    # ---- evaluation on a date
    def view(self, it: Item, on: date) -> View:
        pol = self.policy
        dev = self._deviation_for(it.key, on)
        vd = self._vd_for(it.key, on)
        risk, status, closure, dev_note, vd_note = it.original_risk, "Open", "", "", ""
        if not it.is_open:
            status, closure = "Closed", "remediated"
        if dev:
            if dev["status"] == "pending":
                dev_note = f"{dev['id']} {dev['type']} pending approval (requested {dev['requested_on']})"
            elif dev["type"] == "FP":
                status, closure = "Closed", "false positive"
                dev_note = f"{dev['id']} false positive approved {dev['approved_on']}"
            elif dev["type"] == "RA":
                risk = dev["adjusted_risk"]
                dev_note = f"{dev['id']} risk adjusted {it.original_risk} to {risk}, approved {dev['approved_on']}"
            elif dev["type"] == "OR" and it.is_open:
                status = "Risk accepted (OR)"
                dev_note = f"{dev['id']} operational requirement approved {dev['approved_on']}; reassess by {dev['reassess_by']}"
                if d(dev["reassess_by"]) < on:
                    dev_note += " (REASSESSMENT OVERDUE)"
        due = it.detected + timedelta(days=pol["remediation_days"][risk])
        closed_on = it.closed_on
        if closure == "false positive":
            closed_on = d(dev["approved_on"])
        vd_excused = False
        if vd and it.is_open:
            vp = pol["vendor_dependency"]
            checkins = sorted(d(c) for c in vd["checkins"] if d(c) <= on)
            last = checkins[-1] if checkins else None
            current = last is not None and (on - last).days <= vp["checkin_max_days"]
            mitigated = vd.get("mitigated_on") and d(vd["mitigated_on"]) <= on
            if mitigated:
                risk = vd.get("mitigated_to", risk)
                due = it.detected + timedelta(days=pol["remediation_days"][risk])
            parts = [f"vendor {vd['vendor']} ticket {vd['vendor_ticket']}",
                     f"last check-in {last}" + ("" if current else " (CHECK-IN OVERDUE)")]
            if it.original_risk in {"Critical", "High"}:
                deadline = it.detected + timedelta(days=vp["high_mitigation_days"])
                if mitigated:
                    late = d(vd["mitigated_on"]) > deadline
                    parts.append(f"mitigated to {risk} on {vd['mitigated_on']}" + (" (LATE)" if late else ""))
                else:
                    parts.append(f"must be mitigated to Moderate by {deadline}"
                                 + (" (OVERDUE)" if on > deadline else ""))
            vd_note = "; ".join(parts)
            vd_excused = current
            status = "Open (vendor dependency)" if status == "Open" else status
        countable = status.startswith("Open") and not vd_excused
        days_over = (on - due).days if countable and on > due else 0
        unverified = [a for a in it.open_assets() if a not in self._scanned_on(on)] if it.is_open else []
        return View(item=it, status=status, closure=closure, closed_on=closed_on, risk=risk, due=due,
                    overdue=days_over > 0, days_overdue=days_over, deviation=dev, deviation_note=dev_note,
                    vd=vd, vd_note=vd_note, unverified_assets=unverified)

    def _scanned_on(self, on: date) -> set:
        for rows in self.scans.values():
            if rows and d(rows[0]["scan_date"]) == on:
                return {r["asset"] for r in rows}
        return set()

    def run(self):
        for month, rows in self.scans.items():
            self.process(month, rows)
        return self


def _freeze(v: View) -> dict:
    it = v.item
    return {
        "poam_id": it.poam_id, "key": it.key, "title": it.title, "cve": it.cve, "category": it.category,
        "controls": list(it.controls), "original_risk": it.original_risk, "risk": v.risk,
        "status": v.status, "closure": v.closure, "detected": it.detected, "first_detected": it.first_detected,
        "closed_on": v.closed_on, "due": v.due, "overdue": v.overdue, "days_overdue": v.days_overdue,
        "assets": it.open_assets() if it.is_open else sorted(it.assets),
        "unverified": list(v.unverified_assets), "recurrences": it.recurrences,
        "deviation": v.deviation, "deviation_note": v.deviation_note, "vd": v.vd, "vd_note": v.vd_note,
        "solution": it.solution, "events": list(it.events),
    }


# --------------------------------------------------------------------------- outputs
POAM_COLUMNS = [
    "POAM ID", "Controls", "Weakness Name", "Weakness Source Identifier", "Asset Identifier",
    "Original Detection Date", "Current Detection Date", "Scheduled Completion Date", "Status",
    "Status Date", "Original Risk Rating", "Adjusted Risk Rating", "Risk Adjustment", "False Positive",
    "Operational Requirement", "Deviation Rationale", "Vendor Dependency", "Last Vendor Check-in Date",
    "Vendor Dependent Product Name", "Overdue", "Days Overdue", "Recurrences", "Remediation Plan", "Comments",
]


def poam_csv(snapshot: dict, policy: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(POAM_COLUMNS)
    for v in sorted(snapshot["frozen"].values(), key=lambda v: v["poam_id"]):
        dv, vd = v["deviation"], v["vd"]
        approved = dv and dv["status"] == "approved"
        last_ci = max((str(c) for c in vd["checkins"] if d(c) <= snapshot["date"]), default="") if vd else ""
        w.writerow([
            v["poam_id"], " ".join(v["controls"]), v["title"], v["cve"] or v["key"], " ".join(v["assets"]),
            v["first_detected"], v["detected"], v["due"], v["status"],
            v["closed_on"] or snapshot["date"], v["original_risk"], v["risk"],
            "Yes" if approved and dv["type"] == "RA" else ("Pending" if dv and dv["type"] == "RA" else "No"),
            "Yes" if approved and dv["type"] == "FP" else ("Pending" if dv and dv["type"] == "FP" else "No"),
            "Yes" if approved and dv["type"] == "OR" else ("Pending" if dv and dv["type"] == "OR" else "No"),
            " ".join(str(dv["rationale"]).split()) if dv else "",
            "Yes" if vd else "No", last_ci, vd["vendor"] if vd else "",
            "Yes" if v["overdue"] else "No", v["days_overdue"], v["recurrences"], v["solution"],
            "; ".join(x for x in [v["deviation_note"], v["vd_note"],
                                  f"not scanned this cycle: {', '.join(v['unverified'])}" if v["unverified"] else ""] if x),
        ])
    return buf.getvalue()


def oscal_poam(snapshot: dict, policy: dict) -> dict:
    ts = f"{snapshot['date']}T00:00:00Z"
    observations, risks, items = [], [], []
    status_map = {"Open": "open", "Open (vendor dependency)": "open", "Closed": "closed",
                  "Risk accepted (OR)": "deviation-approved"}
    for v in sorted(snapshot["frozen"].values(), key=lambda v: v["poam_id"]):
        pid = v["poam_id"]
        obs, rk = uid("conmon-obs", pid), uid("conmon-risk", pid)
        observations.append({
            "uuid": obs, "title": v["title"],
            "description": f"Detected by monthly vulnerability scan on: {', '.join(v['assets'])}.",
            "methods": ["TEST"], "types": ["finding"],
            "collected": f"{v['first_detected']}T00:00:00Z",
            "remarks": f"Scanner identifier: {v['cve'] or v['key']}.",
        })
        status = status_map[v["status"]]
        if v["status"].startswith("Open") and v["deviation"] and v["deviation"]["status"] == "pending":
            status = "deviation-requested"
        risk = {
            "uuid": rk, "title": v["title"],
            "description": f"{v['title']} ({v['cve'] or v['key']}).",
            "statement": f"Affects controls {', '.join(v['controls'])}. Original risk {v['original_risk']}; "
                         f"current risk {v['risk']}.",
            "props": [{"name": "risk-level", "value": v["risk"].lower()},
                      {"name": "original-risk-level", "ns": FEDRAMP_NS, "value": v["original_risk"].lower()}],
            "status": status,
            "related-observations": [{"observation-uuid": obs}],
        }
        if v["status"] != "Closed":
            risk["deadline"] = f"{v['due']}T00:00:00Z"
            risk["remediations"] = [{
                "uuid": uid("conmon-rem", pid), "lifecycle": "planned", "title": "Remediation",
                "description": v["solution"] or "See POA&M remediation plan.",
            }]
        risks.append(risk)
        notes = [n for n in (v["deviation_note"], v["vd_note"]) if n]
        items.append({
            "uuid": uid("conmon-item", pid), "title": v["title"],
            "description": f"{v['title']}. Status: {v['status']}{' (' + v['closure'] + ')' if v['closure'] else ''}.",
            "props": [{"name": "POAM-ID", "ns": FEDRAMP_NS, "value": pid}],
            "related-observations": [{"observation-uuid": obs}],
            "related-risks": [{"risk-uuid": rk}],
            **({"remarks": " ".join(notes)} if notes else {}),
        })
    return {"plan-of-action-and-milestones": {
        "uuid": uid("conmon-poam", SYSTEM_ID),
        "metadata": {
            "title": f"{policy['system']['name']} Continuous Monitoring POA&M",
            "last-modified": ts, "version": str(snapshot["date"]), "oscal-version": OSCAL_VERSION,
            "remarks": "Generated from synthetic monthly scan data for a portfolio demonstration.",
        },
        "import-ssp": {"href": SSP_HREF},
        "system-id": {"identifier-type": "https://ietf.org/rfc/rfc4122", "id": uid("system", SYSTEM_ID)},
        "observations": observations, "risks": risks, "poam-items": items,
    }}


def _py_compatible(schema):
    """OSCAL schemas use \\p{L} / \\p{N} Unicode classes that Python's `re` lacks; translate them."""
    if isinstance(schema, dict):
        return {k: (v.replace(r"\p{L}", "[^\\W\\d_]").replace(r"\p{N}", "\\d")
                    if k == "pattern" and isinstance(v, str) else _py_compatible(v))
                for k, v in schema.items()}
    if isinstance(schema, list):
        return [_py_compatible(x) for x in schema]
    return schema


def schema_errors(doc: dict) -> list[str]:
    schema = _py_compatible(json.loads((ROOT / "schemas" / "oscal_poam_schema.json").read_text()))
    v = jsonschema.Draft7Validator(schema)
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message[:200]}"
            for e in sorted(v.iter_errors(doc), key=lambda e: list(e.absolute_path))]


def metrics(snapshot: dict, inventory: dict) -> dict:
    vs = list(snapshot["frozen"].values())
    open_ = [v for v in vs if v["status"] != "Closed"]
    m = {f"open_{r.lower()}": sum(1 for v in open_ if v["risk"] == r) for r in RISK_ORDER}
    m["open_total"] = len(open_)
    m["overdue"] = sum(1 for v in vs if v["overdue"])
    m["risk_accepted"] = sum(1 for v in vs if v["status"] == "Risk accepted (OR)")
    m["opened"] = sum(1 for v in vs if v["detected"] == snapshot["date"])
    m["closed"] = sum(1 for v in vs if v["closed_on"] and snapshot["prev"] < v["closed_on"] <= snapshot["date"])
    m["closed_fp"] = sum(1 for v in vs if v["closure"] == "false positive")
    m["reopened"] = sum(1 for v in vs if v["recurrences"] and v["detected"] == snapshot["date"])
    inv = set(inventory)
    m["coverage_pct"] = round(100 * len(inv & set(snapshot["scanned"])) / len(inv), 1)
    return m


def report_md(month: str, pipe: Pipeline) -> str:
    snap = pipe.snapshots[month]
    on, vs = snap["date"], sorted(snap["frozen"].values(), key=lambda v: v["poam_id"])
    sysname = pipe.policy["system"]["name"]
    m = metrics(snap, pipe.inventory)
    inv = set(pipe.inventory)
    missing = sorted(inv - set(snap["scanned"]))
    unknown = sorted(set(snap["scanned"]) - inv)
    title_month = on.strftime("%B %Y")
    L = [f"# Continuous Monitoring Report: {sysname}, {title_month}", "",
         f"Scan date **{on}**. Generated by `tools/conmon.py` from synthetic data; do not edit by hand.", "",
         "## Summary", "",
         "| Measure | Value |", "|---|---|",
         f"| Open POA&M items | {m['open_total']} (Critical {m['open_critical']}, High {m['open_high']}, "
         f"Moderate {m['open_moderate']}, Low {m['open_low']}) |",
         f"| Overdue | {m['overdue']} |",
         f"| Opened this month | {m['opened']} (of which reopened: {m['reopened']}) |",
         f"| Closed since the last scan | {m['closed']} |",
         f"| Accepted risks (operational requirements) | {m['risk_accepted']} |",
         f"| Scan coverage of inventory | {m['coverage_pct']}% ({len(inv & set(snap['scanned']))} of {len(inv)} assets) |",
         ""]
    if missing or unknown:
        L += ["## Coverage and inventory", ""]
        for a in missing:
            L.append(f"- **Not scanned:** `{a}`. Its open findings stay open; absence from a scan is not proof of a fix.")
        for a in unknown:
            L.append(f"- **Not in inventory:** `{a}` answered the scan but has no inventory record or owner.")
        L.append("")
    # trend across every month up to this one
    L += ["## Trend", "", "| Month | Open | Critical/High | Moderate | Low | Overdue | Opened | Closed | Coverage |",
          "|---|---|---|---|---|---|---|---|---|"]
    for mon, s in pipe.snapshots.items():
        mm = metrics(s, pipe.inventory)
        L.append(f"| {mon} | {mm['open_total']} | {mm['open_critical'] + mm['open_high']} | {mm['open_moderate']} | "
                 f"{mm['open_low']} | {mm['overdue']} | {mm['opened']} | {mm['closed']} | {mm['coverage_pct']}% |")
        if mon == month:
            break
    L.append("")
    overdue = [v for v in vs if v["overdue"]]
    L += ["## Overdue items", ""]
    if overdue:
        L += ["| POA&M | Weakness | Risk | Due | Days late | Assets |", "|---|---|---|---|---|---|"]
        for v in sorted(overdue, key=lambda v: -v["days_overdue"]):
            L.append(f"| {v['poam_id']} | {v['title']} | {v['risk']} | {v['due']} | {v['days_overdue']} | "
                     f"{', '.join(v['assets'])} |")
    else:
        L.append("None.")
    L.append("")
    closed_now = [v for v in vs if v["closed_on"] and snap["prev"] < v["closed_on"] <= on]
    if closed_now:
        L += ["## Closed since the last scan", "", "| POA&M | Weakness | Detected | Due | Closed | How | On time |",
              "|---|---|---|---|---|---|---|"]
        for v in closed_now:
            L.append(f"| {v['poam_id']} | {v['title']} | {v['detected']} | {v['due']} | {v['closed_on']} | "
                     f"{v['closure']} | {'Yes' if v['closed_on'] <= v['due'] else 'No'} |")
        L.append("")
    devs = [v for v in vs if v["deviation_note"] or v["vd_note"]]
    if devs:
        L += ["## Deviations and vendor dependencies", "", "| POA&M | Weakness | Status |", "|---|---|---|"]
        for v in devs:
            L.append(f"| {v['poam_id']} | {v['title']} | {'; '.join(x for x in (v['deviation_note'], v['vd_note']) if x)} |")
        L.append("")
    L += ["## All open items", "", "| POA&M | Weakness | Controls | Risk | Detected | Due | Status | Assets |",
          "|---|---|---|---|---|---|---|---|"]
    for v in vs:
        if v["status"] == "Closed":
            continue
        risk = v["risk"] if v["risk"] == v["original_risk"] else f"{v['risk']} (was {v['original_risk']})"
        assets = ", ".join(f"{a} (not scanned)" if a in v["unverified"] else a for a in v["assets"])
        L.append(f"| {v['poam_id']} | {v['title']} | {' '.join(v['controls'])} | {risk} | {v['detected']} | "
                 f"{v['due']} | {v['status']}{' (overdue)' if v['overdue'] else ''} | {assets} |")
    L.append("")
    return "\n".join(L)


def build(root: Path = ROOT):
    policy, deviations, vds, inventory, scans = load_inputs(root)
    pipe = Pipeline(policy, deviations, vds, inventory, scans)
    errors = validate_deviations(deviations, vds, pipe.findings_by_plugin)
    if errors:
        return pipe, {}, errors
    pipe.run()
    latest = list(pipe.snapshots)[-1]
    outputs = {
        "poam/poam.csv": poam_csv(pipe.snapshots[latest], policy),
        "oscal/poam.json": json.dumps(oscal_poam(pipe.snapshots[latest], policy), indent=2) + "\n",
    }
    for month in pipe.snapshots:
        outputs[f"reports/conmon-{month}.md"] = report_md(month, pipe)
    errors += [f"oscal/poam.json: {e}" for e in schema_errors(json.loads(outputs["oscal/poam.json"]))]
    return pipe, outputs, errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--check", action="store_true", help="write nothing; fail if outputs are stale or invalid")
    args = ap.parse_args()
    pipe, outputs, errors = build()
    for path, text in outputs.items():
        p = ROOT / path
        if args.check:
            if not p.exists() or p.read_text() != text:
                errors.append(f"{path} is out of date; run python tools/conmon.py")
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
    if errors:
        print("FAILED:\n  " + "\n  ".join(errors))
        return 1
    latest = list(pipe.snapshots)[-1]
    m = metrics(pipe.snapshots[latest], pipe.inventory)
    print(f"OK: {len(pipe.items)} POA&M items across {len(pipe.snapshots)} months; as of {latest}: "
          f"{m['open_total']} open, {m['overdue']} overdue, coverage {m['coverage_pct']}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
