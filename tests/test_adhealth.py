import csv
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from adhealth import cli, simulate
from adhealth.checks import CRITICAL, INFO, WARNING, Thresholds, area_status, run_all
from adhealth.model import from_dict, parse_ts

NOW = simulate.DEMO_NOW


def ts(**delta):
    return (NOW - timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


def base(**over):
    """A small healthy domain; tests change one thing at a time."""
    ok = {"NTDS": "Running", "DNS": "Running", "Netlogon": "Running", "Kdc": "Running", "DFSR": "Running",
          "W32Time": "Running"}
    d = {"collectedAt": ts(), "domain": {"dnsRoot": "ad.example", "domainMode": "Windows2016Domain",
                                         "forestMode": "Windows2016Forest", "krbtgtPasswordLastSet": ts(days=30),
                                         "tombstoneLifetimeDays": 180, "recycleBinEnabled": True,
                                         "fsmo": {"PDCEmulator": "DC1.ad.example", "RIDMaster": "DC2.ad.example"}},
         "domainControllers": [
             {"name": "DC1", "site": "HQ", "isGlobalCatalog": True, "services": dict(ok), "sysvolShared": True,
              "timeOffsetSeconds": 0, "ntdsVolumeFreePercent": 60},
             {"name": "DC2", "site": "HQ", "isGlobalCatalog": True, "services": dict(ok), "sysvolShared": True,
              "timeOffsetSeconds": 1, "ntdsVolumeFreePercent": 60}],
         "replication": [{"destination": "DC1", "source": "DC2", "partition": "DC=ad", "lastSuccess": ts(minutes=5),
                          "consecutiveFailures": 0, "lastError": "0"}],
         "dhcpScopes": [], "gpos": [], "privilegedGroups": [], "accounts": {}, "subnets": ["10.0.0.0/8"],
         "noClientSite": []}
    d.update(over)
    return d


def codes(d, t=None):
    return [(f.code, f.severity, f.target) for f in run_all(from_dict(d), t)]


class Healthy(unittest.TestCase):
    def test_clean_domain_has_no_findings(self):
        self.assertEqual(codes(base()), [])


class DomainControllers(unittest.TestCase):
    def test_unreachable_dc_hides_follow_on_noise(self):
        d = base()
        d["domainControllers"][1].update(reachable=False, services={"NTDS": "Stopped"}, timeOffsetSeconds=900)
        found = codes(d)
        self.assertIn(("dc_unreachable", CRITICAL, "DC2"), found)
        self.assertNotIn("dc_service_down", [c for c, _, _ in found])
        self.assertNotIn("time_skew", [c for c, _, _ in found])
        self.assertIn(("fsmo_holder_unhealthy", CRITICAL, "DC2"), found)   # DC2 holds the RID master

    def test_time_skew_thresholds(self):
        d = base()
        d["domainControllers"][1]["timeOffsetSeconds"] = -90
        self.assertIn(("time_skew", WARNING, "DC2"), codes(d))
        d["domainControllers"][1]["timeOffsetSeconds"] = 301
        self.assertIn(("time_skew", CRITICAL, "DC2"), codes(d))

    def test_service_sysvol_and_disk(self):
        d = base()
        d["domainControllers"][0].update(services={"NTDS": "Running", "DFSR": "Stopped"}, sysvolShared=False,
                                         ntdsVolumeFreePercent=4)
        found = codes(d)
        self.assertIn(("dc_service_down", CRITICAL, "DC1"), found)
        self.assertIn(("sysvol_not_shared", CRITICAL, "DC1"), found)
        self.assertIn(("ntds_disk_low", CRITICAL, "DC1"), found)

    def test_site_without_global_catalog(self):
        d = base()
        d["domainControllers"].append({"name": "BR-DC1", "site": "Branch", "isGlobalCatalog": False})
        self.assertIn(("site_without_gc", WARNING, "Branch"), codes(d))


class Replication(unittest.TestCase):
    def test_recent_failure_is_a_warning_old_one_critical(self):
        d = base(replication=[{"destination": "DC1", "source": "DC2", "partition": "DC=ad", "lastSuccess": ts(hours=2),
                               "consecutiveFailures": 2, "lastError": "1753"}])
        self.assertIn(("repl_failing", WARNING, "DC2 → DC1"), codes(d))
        d["replication"][0]["lastSuccess"] = ts(hours=30)
        self.assertIn(("repl_failing", CRITICAL, "DC2 → DC1"), codes(d))

    def test_near_tombstone_and_partitions_grouped(self):
        d = base(replication=[
            {"destination": "DC1", "source": "DC2", "partition": "DC=ad", "lastSuccess": ts(days=95),
             "consecutiveFailures": 900, "lastError": "8524"},
            {"destination": "DC1", "source": "DC2", "partition": "CN=Configuration", "lastSuccess": ts(days=2),
             "consecutiveFailures": 40, "lastError": "8524"}])
        found = run_all(from_dict(d))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].code, "repl_near_tombstone")
        self.assertIn("2 partition(s)", found[0].detail)


class Dhcp(unittest.TestCase):
    def test_scope_usage_and_failover(self):
        d = base(dhcpScopes=[
            {"server": "DC1", "scopeId": "10.1.1.0", "name": "A", "inUse": 86, "free": 14, "failover": "Normal"},
            {"server": "DC1", "scopeId": "10.1.2.0", "name": "B", "inUse": 96, "free": 4, "failover": "PartnerDown"},
            {"server": "DC1", "scopeId": "10.1.3.0", "name": "C", "inUse": 10, "free": 90}])
        found = codes(d)
        self.assertIn(("dhcp_scope_full", WARNING, "DC1 10.1.1.0"), found)
        self.assertIn(("dhcp_scope_full", CRITICAL, "DC1 10.1.2.0"), found)
        self.assertIn(("dhcp_failover_degraded", WARNING, "DC1 10.1.2.0"), found)
        self.assertNotIn("DC1 10.1.3.0", [t for _, _, t in found])


class Gpo(unittest.TestCase):
    def test_empty_beats_unlinked(self):
        d = base(gpos=[{"name": "Empty", "links": 0, "userVersion": 0, "computerVersion": 0},
                       {"name": "Orphan", "links": 0, "userVersion": 3, "computerVersion": 0},
                       {"name": "Used", "links": 2, "userVersion": 3, "computerVersion": 1}])
        self.assertEqual(codes(d), [("gpo_empty", INFO, "Empty"), ("gpo_unlinked", INFO, "Orphan")])


class Privileged(unittest.TestCase):
    def test_stale_never_expiring_and_schema_admins(self):
        d = base(privilegedGroups=[
            {"group": "Domain Admins", "members": [
                {"sam": "adm-a", "lastLogon": ts(days=1)}, {"sam": "adm-old", "lastLogon": ts(days=120)},
                {"sam": "svc-x", "lastLogon": ts(days=1), "passwordNeverExpires": True},
                {"sam": "adm-off", "lastLogon": ts(days=300), "enabled": False},
                {"sam": "Admins-Group", "type": "group"}]},
            {"group": "Schema Admins", "members": [{"sam": "adm-a", "lastLogon": ts(days=1)}]}])
        found = codes(d)
        self.assertIn(("priv_member_stale", WARNING, "adm-old"), found)
        self.assertIn(("priv_pwd_never_expires", WARNING, "svc-x"), found)
        self.assertIn(("schema_admins_not_empty", WARNING, "Schema Admins"), found)
        self.assertNotIn("adm-off", [t for _, _, t in found])       # disabled accounts are not a risk here

    def test_krbtgt_age_threshold_is_configurable(self):
        d = base()
        d["domain"]["krbtgtPasswordLastSet"] = ts(days=200)
        self.assertIn(("krbtgt_old", WARNING, "krbtgt"), codes(d))
        self.assertEqual(codes(d, Thresholds(krbtgt_days=365)), [])


class Hygiene(unittest.TestCase):
    def test_missing_subnets_are_grouped_and_known_ones_ignored(self):
        d = base(subnets=["10.0.0.0/16"], noClientSite=[{"ip": "10.9.1.5", "count": 3}, {"ip": "10.9.1.7", "count": 2},
                                                         {"ip": "10.0.4.4", "count": 9}, {"ip": "bad"}])
        self.assertEqual(codes(d), [("subnet_missing", WARNING, "10.9.1.0/24")])

    def test_recycle_bin_levels_and_stale_counts(self):
        d = base(accounts={"staleUsers": 4, "staleComputers": 0, "staleDays": 90})
        d["domain"].update(recycleBinEnabled=False, forestMode="Windows2012R2Forest")
        self.assertEqual(sorted(c for c, _, _ in codes(d)),
                         ["old_functional_level", "recycle_bin_disabled", "stale_objects"])


class Formats(unittest.TestCase):
    def test_powershell_dates_and_bom(self):
        self.assertEqual(parse_ts("/Date(1760000000000)/").year, 2025)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.json"
            p.write_text("﻿" + json.dumps(base()), encoding="utf-8")
            from adhealth.model import load
            self.assertEqual(load(p).domain.dns_root, "ad.example")


class EndToEnd(unittest.TestCase):
    def test_demo_and_previous_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            self.assertEqual(cli.main(["demo", "--out", str(out), "--data", str(Path(tmp) / "data")]), 0)
            for name in ("report.html", "findings.csv", "health_check.md"):
                self.assertTrue((out / name).stat().st_size > 500, name)
            snap = from_dict(simulate.demo_snapshot())
            st = area_status(run_all(snap))
            self.assertEqual(st["Replication"], CRITICAL)
            self.assertEqual(st["Group Policy"], INFO)
            # second run: pretend one finding was fixed and compare
            with open(out / "findings.csv", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            with open(out / "prev.csv", "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=rows[0].keys())
                w.writeheader()
                w.writerows(rows[1:] + [dict(rows[0], code="gpo_empty", target="Gone GPO")])
            sm = cli.run(Path(tmp) / "data" / "ad_health.json", out, "t", out / "prev.csv", Thresholds())
            self.assertEqual((sm["new"], sm["resolved"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
