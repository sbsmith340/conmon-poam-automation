# ConMon POA&M Automation

> Monthly continuous monitoring for a federal system, automated. Vulnerability scan exports go in; a FedRAMP-style POA&M, an OSCAL 1.1.2 POA&M, and a monthly ConMon report come out. The rules an assessor checks by hand (due dates, deviations, vendor dependencies, scan coverage, recurrences) are enforced in code and tested on every commit.

![ci](https://github.com/sbsmith340/conmon-poam-automation/actions/workflows/ci.yml/badge.svg)
![oscal](https://img.shields.io/badge/OSCAL-1.1.2-1f6feb)
![data](https://img.shields.io/badge/data-synthetic-blue)

**[September 2026 ConMon report](reports/conmon-2026-09.md)** · [POA&M (CSV)](poam/poam.csv) · [OSCAL POA&M](oscal/poam.json)

## Problem
Continuous monitoring is where authorized systems drift. Every month someone exports scan results, matches them to last month's POA&M spreadsheet by hand, works out due dates, and writes a summary for the authorizing official. The common mistakes are predictable:
- closing an item because the asset **wasn't scanned**, not because it was fixed
- losing track of which assets still have a partially fixed vulnerability
- missing that a closed weakness **came back**
- letting an approved deviation or a vendor dependency hide an item that is actually late

## What it does
For each month's scan, in order:

| Step | Rule |
|---|---|
| Open | The first detection of a weakness opens a POA&M item with a due date: Critical and High 30 days, Moderate 90, Low 180 (FedRAMP Rev 5 ConMon guidance, configurable in [`config/policy.yaml`](config/policy.yaml)). |
| Track assets | Every affected asset is tracked separately. An item closes only when **every** asset is fixed. |
| Close | An asset closes only when a later scan **reaches it** and no longer finds the weakness. |
| Coverage | An inventoried asset the scanner didn't reach becomes its own finding (RA-5, CA-7), and its open items stay open. |
| Inventory | A scanned asset that isn't in the inventory becomes a finding (CM-8). |
| Reopen | A closed weakness that reappears is reopened with a new detection date and counted as a recurrence. |
| Deviations | From [`deviations.yaml`](deviations.yaml), applied from their approval date: a **false positive** closes the item; a **risk adjustment** lowers the rating and recomputes the due date; an **operational requirement** keeps the item open as an accepted risk with a reassessment date. Pending requests change nothing. |
| Vendor dependencies | Not counted as late while vendor check-ins are current (30 days). A High vendor dependency must be mitigated to Moderate with a compensating control within 30 days, or it is flagged. |

The build **rejects** a deviation package that a reviewer would reject: an operational requirement on a High risk, a "risk adjustment" that doesn't lower the risk, an approval with no date, or a deviation for a weakness that never appeared in a scan.

## The scenario
Three monthly scans (July to September 2026) of the fictional *Field Inspection Portal*, the same system documented in [oscal-ato-package](https://github.com/sbsmith340/oscal-ato-package). The generated OSCAL POA&M points at that repo's SSP and uses the same system ID. The data is scripted so every rule above is exercised at least once:

| Case | Example in the data |
|---|---|
| Fixed on time | xz-utils backdoor (CVE-2024-3094), closed in 28 days |
| Partly fixed, now overdue | regreSSHion (CVE-2024-6387): fixed on the web servers, still on the bastion, then found on an unknown test VM |
| Not scanned, so not closed | curl (CVE-2023-38545) on a build runner that was powered off during the September scan |
| Recurrence | SMB signing not required: fixed in August, back in September |
| False positive | OpenSSL (CVE-2022-0778): version-string match on a back-ported package |
| Risk adjustment | libwebp (CVE-2023-4863): High to Moderate, because the portal never decodes WebP |
| Operational requirement | TLS 1.1 kept for one partner, limited to that partner's two IPs |
| Pending deviation | Terrapin (CVE-2023-48795): false positive requested, not yet approved |
| Vendor dependency | HTTP/2 Rapid Reset (CVE-2023-44487) on a vendor load balancer, mitigated with a compensating control |

**September result:** 10 open items, 2 overdue, 87.5% scan coverage, 1 unknown asset. See the [report](reports/conmon-2026-09.md).

## How to run it
```bash
git clone https://github.com/sbsmith340/conmon-poam-automation.git
cd conmon-poam-automation
pip install pyyaml jsonschema pytest
python tools/conmon.py            # writes poam/, oscal/, reports/
python tools/conmon.py --check    # CI mode: fail if outputs are stale or invalid
pytest -q tests                   # 17 tests
```
To run a new month, add `data/scans/YYYY-MM.csv` in the same column layout and rerun. Change due-date policy or control mappings in `config/policy.yaml`; record deviations in `deviations.yaml`.

## Framework mapping
| Control | How this supports it |
|---|---|
| CA-5 Plan of Action and Milestones | POA&M generated and kept current from scan evidence |
| CA-7 Continuous Monitoring | Monthly report with trend, coverage, and overdue items |
| RA-5 Vulnerability Monitoring and Scanning | Scan coverage measured against the inventory |
| SI-2 Flaw Remediation | Due dates by risk; on-time closure measured |
| CM-8 System Component Inventory | Unknown assets surfaced from scan results |

## Design notes
- **One item per weakness, many assets.** That matches how POA&Ms are usually reviewed and lets a partial fix show up as progress without closing the item.
- **Closure needs evidence.** "Not in this month's results" is ambiguous, so the pipeline checks whether the asset was scanned before it closes anything.
- **Deviation rules follow the FedRAMP POA&M guidance** (no operational requirements for High risks; vendor dependencies are not deviations and need monthly check-ins). FedRAMP is moving to new consolidated rules in 2026, so every timeframe lives in config rather than code.
- **Everything is generated.** The POA&M, OSCAL, and reports are rebuilt from the scans and `deviations.yaml`; CI fails if a committed output doesn't match.

## Limitations and what's next
- The scan format is a simplified, scanner-neutral CSV. Real exports from Tenable, Qualys, or Defender would need a small adapter per tool.
- Due dates for an asset that joins an already-open item inherit the item's original date. Some programs open a separate item instead; that would be a config option.
- Next: a Defender Vulnerability Management adapter using the export from [vuln-remediation-metrics](https://github.com/sbsmith340/vuln-remediation-metrics), and milestones generated per item.

## Repo layout
```
config/policy.yaml          due dates, vendor-dependency rules, category-to-control map
deviations.yaml             deviation requests and vendor dependencies (edited by people)
data/generate.py            deterministic scenario generator
data/inventory.csv          system inventory
data/scans/YYYY-MM.csv      monthly scan exports
tools/conmon.py             the pipeline
poam/poam.csv               POA&M, columns modeled on the FedRAMP POA&M template
oscal/poam.json             the same POA&M in OSCAL 1.1.2, schema-validated
reports/conmon-YYYY-MM.md   monthly ConMon reports
schemas/                    NIST OSCAL POA&M JSON schema
tests/                      lifecycle and validation tests
```

---
The system, agency, vendor, and assets are fictional. CVE identifiers are real and used only as realistic examples. NIST schema from [usnistgov/OSCAL](https://github.com/usnistgov/OSCAL). Built by [Shawn Smith](https://sbsmith340.github.io).
