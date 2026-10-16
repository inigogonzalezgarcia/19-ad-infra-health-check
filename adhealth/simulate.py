"""Fictional demo estate: one domain (corp.contoso.example), six DCs in three sites, DHCP, GPOs and admin groups.

Nothing here comes from a real directory. Faults are placed on purpose so every check fires at least once.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEMO_NOW = datetime(2026, 10, 19, 6, 0, tzinfo=timezone.utc)   # Monday, before the office opens


def _ts(**delta) -> str:
    return (DEMO_NOW - timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


SVC_OK = {"NTDS": "Running", "DNS": "Running", "Netlogon": "Running", "Kdc": "Running", "DFSR": "Running",
          "W32Time": "Running"}


def _dc(name, site, gc=True, os="Windows Server 2022 Standard", **kw):
    d = {"name": f"{name}.corp.contoso.example", "site": site, "os": os, "isGlobalCatalog": gc, "reachable": True,
         "services": dict(SVC_OK), "sysvolShared": True, "timeOffsetSeconds": 0.4, "ntdsVolumeFreePercent": 61}
    d.update(kw)
    return d


def demo_snapshot() -> dict:
    dcs = [
        _dc("MAD-DC01", "Madrid", timeOffsetSeconds=0.0),
        _dc("MAD-DC02", "Madrid", ntdsVolumeFreePercent=9),                       # disk filling up with logs
        _dc("PAR-DC01", "Paris", timeOffsetSeconds=412.0),                        # clock 7 minutes ahead
        _dc("PAR-DC02", "Paris", os="Windows Server 2019 Standard",
            services={**SVC_OK, "DFSR": "Stopped"}, sysvolShared=False),           # SYSVOL not replicating
        _dc("LIS-DC01", "Lisbon", gc=False, os="Windows Server 2019 Standard"),   # the only DC in Lisbon, no GC
        _dc("LON-DC01", "London", reachable=False, services={}, sysvolShared=None, timeOffsetSeconds=None,
            ntdsVolumeFreePercent=None),                                           # powered off after a move
    ]
    # (destination, source): two DCs per hub site replicate with each other, sites through the 01 servers
    links = [("MAD-DC01", "MAD-DC02"), ("MAD-DC02", "MAD-DC01"), ("PAR-DC01", "PAR-DC02"), ("PAR-DC02", "PAR-DC01"),
             ("MAD-DC01", "PAR-DC01"), ("PAR-DC01", "MAD-DC01"), ("LIS-DC01", "MAD-DC01"), ("MAD-DC01", "LIS-DC01"),
             ("MAD-DC01", "LON-DC01"), ("PAR-DC01", "LON-DC01")]
    repl = []
    for dst, src in links:
        for part in ("DC=corp,DC=contoso,DC=example", "CN=Configuration,DC=corp,DC=contoso,DC=example"):
            link = {"destination": dst, "source": src, "partition": part, "lastSuccess": _ts(minutes=12),
                    "lastAttempt": _ts(minutes=12), "consecutiveFailures": 0, "lastError": "0"}
            if src == "LON-DC01":
                link.update(lastSuccess=_ts(days=3, hours=2), consecutiveFailures=214, lastError="1722")
            if src == "PAR-DC02" and dst == "PAR-DC01" and part.startswith("DC="):
                link.update(lastSuccess=_ts(hours=5), consecutiveFailures=3, lastError="1753")
            repl.append(link)
    # A link that has been failing for a long time and nobody noticed
    repl.append({"destination": "LIS-DC01", "source": "PAR-DC02", "partition": "DC=DomainDnsZones,DC=corp,DC=contoso,DC=example",
                 "lastSuccess": _ts(days=97), "lastAttempt": _ts(minutes=30), "consecutiveFailures": 4120,
                 "lastError": "8524"})

    dhcp = [
        {"server": "MAD-DC01", "scopeId": "10.10.20.0", "name": "MAD-Floor2-Users", "inUse": 241, "free": 9,
         "failover": "Normal"},                                                   # 96%: new joiners this week
        {"server": "MAD-DC01", "scopeId": "10.10.30.0", "name": "MAD-Floor3-Users", "inUse": 188, "free": 62,
         "failover": "Normal"},
        {"server": "MAD-DC01", "scopeId": "10.10.50.0", "name": "MAD-Guest-WiFi", "inUse": 445, "free": 61,
         "failover": "Normal"},                                                   # 88%
        {"server": "PAR-DC01", "scopeId": "10.20.20.0", "name": "PAR-Users", "inUse": 120, "free": 130,
         "failover": "CommunicationInterrupted"},
        {"server": "LIS-DC01", "scopeId": "10.30.20.0", "name": "LIS-Users", "inUse": 61, "free": 189, "failover": None},
        {"server": "MAD-DC01", "scopeId": "10.10.40.0", "name": "MAD-Printers", "inUse": 22, "free": 228,
         "failover": "Normal"},
    ]
    gpos = [
        {"name": "Default Domain Policy", "links": 1, "userVersion": 0, "computerVersion": 14},
        {"name": "Default Domain Controllers Policy", "links": 1, "userVersion": 0, "computerVersion": 9},
        {"name": "WKS - Security baseline", "links": 3, "userVersion": 2, "computerVersion": 31},
        {"name": "WKS - BitLocker", "links": 3, "userVersion": 0, "computerVersion": 6},
        {"name": "USR - Drive maps", "links": 4, "userVersion": 18, "computerVersion": 0},
        {"name": "USR - Printers Madrid", "links": 1, "userVersion": 7, "computerVersion": 0},
        {"name": "SRV - Windows Update", "links": 2, "userVersion": 0, "computerVersion": 11},
        {"name": "TEST - Edge settings (old)", "links": 0, "userVersion": 3, "computerVersion": 5},
        {"name": "New Group Policy Object", "links": 1, "userVersion": 0, "computerVersion": 0},
        {"name": "WKS - Windows 10 legacy", "links": 0, "userVersion": 0, "computerVersion": 22},
    ]

    def m(sam, days, pne=False, typ="user", enabled=True):
        return {"sam": sam, "type": typ, "enabled": enabled, "lastLogon": None if days is None else _ts(days=days),
                "passwordNeverExpires": pne}

    priv = [
        {"group": "Domain Admins", "members": [
            m("adm-jgarcia", 1), m("adm-lmartin", 2), m("adm-pdubois", 4), m("adm-asilva", 6),
            m("adm-rlopez", 140),                                                  # left the team in spring
            m("svc-backup", 0, pne=True),                                          # service account in DA
            m("adm-contractor01", None),                                           # created, never used
            m("Tier0-Admins", 0, typ="group")]},
        {"group": "Enterprise Admins", "members": [m("adm-jgarcia", 1)]},
        {"group": "Schema Admins", "members": [m("Administrator", 400, pne=True)]},
        {"group": "Administrators", "members": [m("Administrator", 400, pne=True), m("Domain Admins", 0, typ="group"),
                                                m("Enterprise Admins", 0, typ="group")]},
    ]
    return {
        "collectedAt": DEMO_NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "domain": {"dnsRoot": "corp.contoso.example", "netbios": "CONTOSO", "domainMode": "Windows2016Domain",
                   "forestMode": "Windows2012R2Forest", "krbtgtPasswordLastSet": _ts(days=1150),
                   "tombstoneLifetimeDays": 180, "recycleBinEnabled": False,
                   "fsmo": {"SchemaMaster": "MAD-DC01.corp.contoso.example",
                            "DomainNamingMaster": "MAD-DC01.corp.contoso.example",
                            "PDCEmulator": "MAD-DC01.corp.contoso.example",
                            "RIDMaster": "PAR-DC02.corp.contoso.example",
                            "InfrastructureMaster": "MAD-DC02.corp.contoso.example"}},
        "domainControllers": dcs,
        "replication": repl,
        "dhcpScopes": dhcp,
        "gpos": gpos,
        "privilegedGroups": priv,
        "accounts": {"totalUsers": 1180, "totalComputers": 1310, "staleUsers": 74, "staleComputers": 162,
                     "staleDays": 90, "passwordNeverExpires": 23},
        "subnets": ["10.10.0.0/16", "10.20.0.0/16", "10.30.0.0/16", "10.40.0.0/16"],
        "noClientSite": [{"ip": "10.50.12.34", "count": 41}, {"ip": "10.50.12.80", "count": 17},
                         {"ip": "172.16.8.20", "count": 6}, {"ip": "10.20.4.11", "count": 3}],
    }


def write_demo(folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "ad_health.json"
    path.write_text(json.dumps(demo_snapshot(), indent=1), encoding="utf-8")
    return path
