"""
Generate the synthetic dataset: an asset inventory and three monthly vulnerability
scan exports for the fictional Field Inspection Portal.

  python data/generate.py

The output is fully deterministic. The scenario is scripted (not random) so that
every lifecycle case the pipeline handles appears at least once:

  closed on time, closed late, still overdue, reopened after closure, approved
  false positive, approved risk adjustment, approved operational requirement,
  pending deviation, vendor dependency with compensating control, an inventoried
  asset that was not scanned, and a scanned asset that is not in the inventory.

Hostnames use the fictional "fip" prefix; IPs come from the RFC 5737 documentation
range 192.0.2.0/24 and the RFC 1918 range 10.20.0.0/16 used only inside this dataset.
"""
from __future__ import annotations

import csv
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCANS = {"2026-07": "2026-07-06", "2026-08": "2026-08-03", "2026-09": "2026-09-07"}

INVENTORY = [
    # asset, ip, type, os_or_image, owner_role, boundary
    ("fip-lb-01", "10.20.1.10", "network-appliance", "Northwind LB 9.2 (vendor appliance)", "Network Engineer", "inside"),
    ("fip-web-01", "10.20.2.11", "virtual-machine", "Ubuntu 22.04", "System Administrator", "inside"),
    ("fip-web-02", "10.20.2.12", "virtual-machine", "Ubuntu 22.04", "System Administrator", "inside"),
    ("fip-api-01", "10.20.2.21", "virtual-machine", "Ubuntu 22.04", "System Administrator", "inside"),
    ("fip-sql-01", "10.20.3.31", "virtual-machine", "Windows Server 2022 / SQL Server 2022", "Database Administrator", "inside"),
    ("fip-jump-01", "10.20.0.5", "virtual-machine", "Ubuntu 22.04 (bastion)", "System Administrator", "inside"),
    ("fip-ci-runner-01", "10.20.5.41", "virtual-machine", "Ubuntu 22.04 (build runner)", "DevSecOps Engineer", "inside"),
    ("fip-portal:2.4", "n/a", "container-image", "fip-portal image, Debian 12 base", "DevSecOps Engineer", "inside"),
]

# One row per weakness. "where" maps each month to the assets it is detected on that month.
# Months where an asset is not scanned at all are handled by SCANNED below, not here.
FINDINGS = [
    dict(plugin="FIP-1001", cve="CVE-2024-6387", category="patch", severity="High", cvss="8.1", port="22",
         title="OpenSSH signal handler race condition (regreSSHion) remote code execution",
         solution="Upgrade OpenSSH to the vendor-patched package.",
         where={"2026-07": ["fip-web-01", "fip-web-02", "fip-jump-01"],
                "2026-08": ["fip-jump-01"],
                "2026-09": ["fip-jump-01", "fip-test-03"]}),
    dict(plugin="FIP-1002", cve="CVE-2024-3094", category="patch", severity="Critical", cvss="10.0", port="22",
         title="xz-utils / liblzma embedded backdoor",
         solution="Downgrade or upgrade xz-utils to a vendor-fixed release and rebuild the host.",
         where={"2026-07": ["fip-api-01"]}),
    dict(plugin="FIP-1003", cve="CVE-2023-38545", category="patch", severity="Critical", cvss="9.8", port="",
         title="curl SOCKS5 proxy handshake heap buffer overflow",
         solution="Upgrade curl and libcurl to the vendor-patched package.",
         where={"2026-07": ["fip-ci-runner-01"], "2026-08": ["fip-ci-runner-01"]}),
    dict(plugin="FIP-1004", cve="CVE-2023-4863", category="patch", severity="High", cvss="8.8", port="",
         title="libwebp heap buffer overflow in container image",
         solution="Rebuild the image on a base with the patched libwebp package.",
         where={"2026-07": ["fip-portal:2.4"], "2026-08": ["fip-portal:2.4"], "2026-09": ["fip-portal:2.4"]}),
    dict(plugin="FIP-1005", cve="CVE-2022-0778", category="patch", severity="High", cvss="7.5", port="1433",
         title="OpenSSL BN_mod_sqrt() infinite loop denial of service",
         solution="Apply the vendor OpenSSL update.",
         where={"2026-07": ["fip-sql-01"], "2026-08": ["fip-sql-01"], "2026-09": ["fip-sql-01"]}),
    dict(plugin="FIP-1006", cve="CVE-2023-48795", category="crypto", severity="Moderate", cvss="5.9", port="22",
         title="SSH prefix truncation attack (Terrapin)",
         solution="Enable strict key exchange or disable ChaCha20-Poly1305 and Encrypt-then-MAC modes.",
         where={"2026-07": ["fip-jump-01"], "2026-08": ["fip-jump-01"], "2026-09": ["fip-jump-01"]}),
    dict(plugin="FIP-2001", cve="", category="tls", severity="Moderate", cvss="6.5", port="443",
         title="TLS 1.0 and TLS 1.1 enabled on partner integration listener",
         solution="Disable TLS 1.0 and 1.1; require TLS 1.2 or higher.",
         where={"2026-07": ["fip-lb-01"], "2026-08": ["fip-lb-01"], "2026-09": ["fip-lb-01"]}),
    dict(plugin="FIP-1007", cve="CVE-2023-44487", category="patch", severity="High", cvss="7.5", port="443",
         title="HTTP/2 Rapid Reset denial of service",
         solution="Apply the appliance vendor's firmware fix when released.",
         where={"2026-08": ["fip-lb-01"], "2026-09": ["fip-lb-01"]}),
    dict(plugin="FIP-2002", cve="", category="smb", severity="Moderate", cvss="5.3", port="445",
         title="SMB signing not required",
         solution="Require SMB signing through Group Policy.",
         where={"2026-07": ["fip-sql-01"], "2026-09": ["fip-sql-01"]}),
    dict(plugin="FIP-2003", cve="", category="crypto", severity="Low", cvss="2.6", port="22",
         title="SSH server allows CBC mode ciphers",
         solution="Remove CBC ciphers from the sshd Ciphers list.",
         where={"2026-07": ["fip-web-01"], "2026-08": ["fip-web-01"], "2026-09": ["fip-web-01"]}),
    dict(plugin="FIP-0001", cve="", category="info", severity="Info", cvss="", port="",
         title="OS identification",
         solution="",
         where={m: ["fip-web-01", "fip-web-02", "fip-api-01", "fip-sql-01"] for m in SCANS}),
]

# Which assets the scanner reached each month. fip-ci-runner-01 was powered off during the
# September scan window; fip-test-03 is a test VM someone stood up without adding it to inventory.
INVENTORIED = [a[0] for a in INVENTORY]
SCANNED = {
    "2026-07": INVENTORIED,
    "2026-08": INVENTORIED,
    "2026-09": [a for a in INVENTORIED if a != "fip-ci-runner-01"] + ["fip-test-03"],
}
EXTRA_IPS = {"fip-test-03": "10.20.4.77"}

SCAN_COLUMNS = ["scan_date", "asset", "ip", "plugin_id", "cve", "title", "severity", "cvss",
                "category", "port", "solution"]


def main() -> None:
    ip = {a[0]: a[1] for a in INVENTORY} | EXTRA_IPS
    with open(HERE / "inventory.csv", "w", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["asset", "ip", "type", "platform", "owner_role", "boundary"])
        w.writerows(INVENTORY)
    for month, date in SCANS.items():
        rows = []
        for fd in FINDINGS:
            for asset in fd["where"].get(month, []):
                assert asset in SCANNED[month], (month, asset)
                rows.append([date, asset, ip[asset], fd["plugin"], fd["cve"], fd["title"], fd["severity"],
                             fd["cvss"], fd["category"], fd["port"], fd["solution"]])
        # a host-level "scan completed" record for every asset reached, as real scanners emit
        for asset in SCANNED[month]:
            rows.append([date, asset, ip[asset], "FIP-0000", "", "Scan completed with credentials", "Info",
                         "", "info", "", ""])
        rows.sort(key=lambda r: (r[1], r[3]))
        with open(HERE / "scans" / f"{month}.csv", "w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(SCAN_COLUMNS)
            w.writerows(rows)


if __name__ == "__main__":
    main()
