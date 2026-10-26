"""Every lifecycle rule the pipeline claims is checked against the scripted scenario."""
import copy
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import conmon  # noqa: E402

PIPE, OUTPUTS, ERRORS = conmon.build()
SEP = PIPE.snapshots["2026-09"]["frozen"]
AUG = PIPE.snapshots["2026-08"]["frozen"]


def item(snapshot, key):
    return snapshot[key]


def rebuild(mutate_deviations=None, mutate_vds=None):
    policy, devs, vds, inv, scans = conmon.load_inputs()
    devs, vds = copy.deepcopy(devs), copy.deepcopy(vds)
    if mutate_deviations:
        mutate_deviations(devs)
    if mutate_vds:
        mutate_vds(vds)
    pipe = conmon.Pipeline(policy, devs, vds, inv, scans)
    errs = conmon.validate_deviations(devs, vds, pipe.findings_by_plugin)
    return pipe, errs


def test_build_is_clean_and_outputs_are_current():
    assert ERRORS == []
    for path, text in OUTPUTS.items():
        assert (ROOT / path).read_text() == text, f"{path} is stale"


def test_dataset_is_reproducible():
    files = [ROOT / "data" / "inventory.csv", *sorted((ROOT / "data" / "scans").glob("*.csv"))]
    before = {p: p.read_bytes() for p in files}
    subprocess.run([sys.executable, str(ROOT / "data" / "generate.py")], check=True)
    assert {p: p.read_bytes() for p in files} == before


def test_oscal_links_to_the_companion_ssp_system():
    import json
    doc = json.loads(OUTPUTS["oscal/poam.json"])["plan-of-action-and-milestones"]
    assert doc["system-id"]["id"] == "b70f730f-4231-51ea-b461-3a487f1a9263"   # oscal-ato-package SSP
    assert len(doc["poam-items"]) == len(PIPE.items)


def test_closed_on_time_when_fixed_before_due():
    xz = item(AUG, "FIP-1002")
    assert xz["status"] == "Closed" and xz["closure"] == "remediated"
    assert xz["closed_on"] == date(2026, 8, 3) <= xz["due"]


def test_partial_fix_keeps_item_open_and_it_goes_overdue():
    ssh = item(SEP, "FIP-1001")
    assert ssh["status"] == "Open" and ssh["overdue"] and ssh["days_overdue"] == 33
    assert ssh["assets"] == ["fip-jump-01", "fip-test-03"]          # web-01/02 fixed in August
    assert PIPE.items["FIP-1001"].assets["fip-web-01"].closed_on == date(2026, 8, 3)


def test_unscanned_asset_is_not_treated_as_fixed():
    curl = item(SEP, "FIP-1003")
    assert curl["status"] == "Open" and curl["unverified"] == ["fip-ci-runner-01"]
    gap = item(SEP, "COV-fip-ci-runner-01")
    assert gap["status"] == "Open" and gap["controls"] == ["RA-5", "CA-7"]


def test_unknown_asset_raises_inventory_finding():
    inv = item(SEP, "INV-fip-test-03")
    assert inv["status"] == "Open" and inv["controls"] == ["CM-8"]


def test_recurrence_reopens_with_new_detection_date():
    smb = item(SEP, "FIP-2002")
    assert smb["recurrences"] == 1
    assert smb["first_detected"] == date(2026, 7, 6) and smb["detected"] == date(2026, 9, 7)
    assert item(AUG, "FIP-2002")["status"] == "Closed"


def test_approved_false_positive_closes_on_approval_date():
    fp = item(SEP, "FIP-1005")
    assert fp["status"] == "Closed" and fp["closure"] == "false positive"
    assert fp["closed_on"] == date(2026, 7, 17)


def test_pending_deviation_changes_nothing():
    terrapin = item(SEP, "FIP-1006")
    assert terrapin["status"] == "Open" and terrapin["risk"] == "Moderate"
    assert "pending" in terrapin["deviation_note"]


def test_risk_adjustment_lowers_rating_and_extends_due_date():
    webp = item(SEP, "FIP-1004")
    assert webp["original_risk"] == "High" and webp["risk"] == "Moderate"
    assert webp["due"] == date(2026, 10, 4) and not webp["overdue"]


def test_operational_requirement_is_accepted_not_overdue():
    tls = item(SEP, "FIP-2001")
    assert tls["status"] == "Risk accepted (OR)" and not tls["overdue"]


def test_vendor_dependency_excused_only_while_checkins_are_current():
    vd = item(SEP, "FIP-1007")
    assert vd["status"] == "Open (vendor dependency)" and vd["risk"] == "Moderate" and not vd["overdue"]

    def stale(vds):
        vds[0]["checkins"] = ["2026-08-04"]
        vds[0].pop("mitigated_on")
    pipe, errs = rebuild(mutate_vds=stale)
    assert errs == []
    pipe.run()
    v = pipe.snapshots["2026-09"]["frozen"]["FIP-1007"]
    assert v["overdue"] and "CHECK-IN OVERDUE" in v["vd_note"] and "(OVERDUE)" in v["vd_note"]


def test_rejects_operational_requirement_for_high_risk():
    def high_or(devs):
        devs.append({"id": "DR-099", "plugin_id": "FIP-1001", "type": "OR", "status": "approved",
                     "requested_on": "2026-07-10", "approved_on": "2026-07-12", "reassess_by": "2027-01-01",
                     "rationale": "x"})
    _, errs = rebuild(mutate_deviations=high_or)
    assert any("cannot be approved for a High" in e for e in errs)


def test_rejects_risk_adjustment_that_does_not_lower_risk():
    def bad_ra(devs):
        devs[0]["adjusted_risk"] = "Critical"
    _, errs = rebuild(mutate_deviations=bad_ra)
    assert any("must lower the rating" in e for e in errs)


def test_rejects_approved_deviation_without_date():
    def no_date(devs):
        devs[1].pop("approved_on")
    _, errs = rebuild(mutate_deviations=no_date)
    assert any("without an approval date" in e for e in errs)


def test_report_headline_numbers():
    m = conmon.metrics(PIPE.snapshots["2026-09"], PIPE.inventory)
    assert (m["open_total"], m["overdue"], m["coverage_pct"]) == (10, 2, 87.5)
    report = OUTPUTS["reports/conmon-2026-09.md"]
    assert "| Overdue | 2 |" in report and "87.5%" in report
