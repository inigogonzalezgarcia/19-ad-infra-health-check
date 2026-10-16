"""Snapshot of an Active Directory estate, as written by scripts/Export-ADHealth.ps1 (one JSON file)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def parse_ts(value: str | None) -> datetime | None:
    """ISO 8601 or the /Date(ms)/ format that older PowerShell versions write. None when empty."""
    if not value:
        return None
    v = str(value).strip()
    if v.startswith("/Date("):
        ms = int(v[6:].split(")")[0].split("+")[0].split("-")[0] or 0)
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    dt = datetime.fromisoformat(v)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass
class Domain:
    dns_root: str
    netbios: str
    domain_mode: str
    forest_mode: str
    krbtgt_password_last_set: datetime | None
    tombstone_days: int
    fsmo: dict[str, str]
    recycle_bin: bool


@dataclass
class DomainController:
    name: str
    site: str
    os: str
    is_gc: bool
    reachable: bool
    services: dict[str, str]
    sysvol_shared: bool | None
    time_offset_s: float | None
    ntds_free_pct: float | None


@dataclass
class ReplLink:
    destination: str
    source: str
    partition: str
    last_success: datetime | None
    last_attempt: datetime | None
    failures: int
    last_error: str


@dataclass
class DhcpScope:
    server: str
    scope_id: str
    name: str
    in_use: int
    free: int
    failover: str | None

    @property
    def used_pct(self) -> float:
        total = self.in_use + self.free
        return round(100 * self.in_use / total, 1) if total else 0.0


@dataclass
class Gpo:
    name: str
    links: int
    user_version: int
    computer_version: int
    user_enabled: bool
    computer_enabled: bool


@dataclass
class Member:
    sam: str
    type: str
    enabled: bool
    last_logon: datetime | None
    password_never_expires: bool


@dataclass
class Snapshot:
    collected_at: datetime
    domain: Domain
    dcs: list[DomainController]
    replication: list[ReplLink]
    dhcp: list[DhcpScope]
    gpos: list[Gpo]
    privileged: dict[str, list[Member]]
    accounts: dict[str, int]
    subnets: list[str]
    no_client_site: list[dict] = field(default_factory=list)


def _b(v, default=False) -> bool:
    if v is None:
        return default
    if isinstance(v, str):
        return v.strip().lower() in ("true", "yes", "1")
    return bool(v)


def from_dict(d: dict) -> Snapshot:
    dom = d.get("domain") or {}
    domain = Domain(
        dns_root=dom.get("dnsRoot", "unknown"), netbios=dom.get("netbios", ""),
        domain_mode=dom.get("domainMode", "unknown"), forest_mode=dom.get("forestMode", "unknown"),
        krbtgt_password_last_set=parse_ts(dom.get("krbtgtPasswordLastSet")),
        tombstone_days=int(dom.get("tombstoneLifetimeDays") or 180),
        fsmo={k: (v or "").split(".")[0].upper() for k, v in (dom.get("fsmo") or {}).items()},
        recycle_bin=_b(dom.get("recycleBinEnabled")),
    )
    dcs = [DomainController(
        name=x["name"].split(".")[0].upper(), site=x.get("site", ""), os=x.get("os", ""),
        is_gc=_b(x.get("isGlobalCatalog")), reachable=_b(x.get("reachable"), True),
        services=dict(x.get("services") or {}),
        sysvol_shared=None if x.get("sysvolShared") is None else _b(x.get("sysvolShared")),
        time_offset_s=None if x.get("timeOffsetSeconds") is None else float(x["timeOffsetSeconds"]),
        ntds_free_pct=None if x.get("ntdsVolumeFreePercent") is None else float(x["ntdsVolumeFreePercent"]),
    ) for x in d.get("domainControllers") or []]
    repl = [ReplLink(
        destination=x["destination"].split(".")[0].upper(), source=x["source"].split(".")[0].upper(),
        partition=x.get("partition", ""), last_success=parse_ts(x.get("lastSuccess")),
        last_attempt=parse_ts(x.get("lastAttempt")), failures=int(x.get("consecutiveFailures") or 0),
        last_error=str(x.get("lastError") or ""),
    ) for x in d.get("replication") or []]
    dhcp = [DhcpScope(x.get("server", ""), x.get("scopeId", ""), x.get("name", ""), int(x.get("inUse") or 0),
                      int(x.get("free") or 0), x.get("failover")) for x in d.get("dhcpScopes") or []]
    gpos = [Gpo(x["name"], int(x.get("links") or 0), int(x.get("userVersion") or 0), int(x.get("computerVersion") or 0),
                _b(x.get("userSettingsEnabled"), True), _b(x.get("computerSettingsEnabled"), True))
            for x in d.get("gpos") or []]
    priv = {g["group"]: [Member(m.get("sam", "?"), m.get("type", "user"), _b(m.get("enabled"), True),
                                parse_ts(m.get("lastLogon")), _b(m.get("passwordNeverExpires")))
                         for m in g.get("members") or []]
            for g in d.get("privilegedGroups") or []}
    return Snapshot(
        collected_at=parse_ts(d.get("collectedAt")) or datetime.now(timezone.utc), domain=domain, dcs=dcs,
        replication=repl, dhcp=dhcp, gpos=gpos, privileged=priv,
        accounts={k: int(v) for k, v in (d.get("accounts") or {}).items()},
        subnets=list(d.get("subnets") or []), no_client_site=list(d.get("noClientSite") or []),
    )


def load(path: Path) -> Snapshot:
    with open(path, encoding="utf-8-sig") as f:   # PowerShell 5.1 writes a BOM
        return from_dict(json.load(f))
