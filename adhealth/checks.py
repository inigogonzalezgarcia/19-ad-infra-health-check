"""The checks. Each one returns findings with a severity, the object it is about and the first thing to do."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime

from .model import Snapshot

CRITICAL, WARNING, INFO = "critical", "warning", "info"
SEV_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}
AREAS = ["Domain controllers", "Replication", "DHCP", "Group Policy", "Privileged access", "Directory hygiene"]

CORE_SERVICES = ["NTDS", "DNS", "Netlogon", "Kdc", "DFSR", "W32Time"]
PRIV_GROUPS = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"]
OLD_LEVELS = ("Windows2008", "Windows2008R2", "Windows2012", "Windows2012R2")

FIX = {
    "dc_unreachable": "Check the server is up and reachable on the network (ping, RDP, console). Until it is back, "
                      "make sure clients in that site can reach another DC.",
    "dc_service_down": "Start the service and read its event log (Directory Service, DNS Server, DFS Replication). "
                       "Do not restart NTDS on a DC that is the only one in its site during office hours.",
    "sysvol_not_shared": "Run `net share` on the DC. If SYSVOL/NETLOGON are missing, check DFSR event 4012/4614 "
                         "before any authoritative restore.",
    "time_skew": "Kerberos tolerates 5 minutes. Check `w32tm /query /status`; the PDC emulator should use an external "
                 "source and the other DCs the domain hierarchy.",
    "ntds_disk_low": "Free space on the NTDS/SYSVOL volume (old logs, crash dumps, WinSxS) or extend it. "
                     "AD stops writing below a safe threshold.",
    "fsmo_holder_unhealthy": "A role holder has a critical problem. Fix the DC first; seize the role only if the "
                             "holder will not come back.",
    "site_without_gc": "Logons in that site need a Global Catalog. Make the local DC a GC or check the WAN path.",
    "repl_failing": "Run `repadmin /showrepl <dc>` and `repadmin /replsummary`. 1722/1753 usually mean RPC or "
                    "firewall; 8453 means permissions; 8614 means the tombstone lifetime was exceeded.",
    "repl_near_tombstone": "This link is close to the tombstone lifetime. Fix replication now: after the limit the "
                           "DC has to be demoted and rebuilt.",
    "dhcp_scope_full": "Shorten the lease, extend the range or split the VLAN. Check for rogue or stale reservations.",
    "dhcp_failover_degraded": "The failover partner is not in sync. Check connectivity between the two DHCP servers "
                              "and `Get-DhcpServerv4Failover`.",
    "gpo_unlinked": "Not applied anywhere. Back it up and delete it, or link it if it was forgotten.",
    "gpo_empty": "No settings in either half. Delete it after checking nobody is building it.",
    "krbtgt_old": "Reset the krbtgt password twice, with replication in between (Microsoft's reset script does this "
                  "safely). Plan it as a change.",
    "schema_admins_not_empty": "Schema Admins should be empty except during a schema change. Remove the members.",
    "priv_member_stale": "An enabled privileged account nobody has used for a long time. Disable it and confirm with "
                         "its owner.",
    "priv_pwd_never_expires": "Privileged account with a password that never expires. Move it to a managed or "
                              "rotated password (gMSA, PAM vault) or set an expiry.",
    "priv_too_many": "Many direct members in Domain Admins. Move day-to-day work to delegated groups or "
                     "just-in-time access.",
    "recycle_bin_disabled": "Enable the AD Recycle Bin (one-way, forest level) so deleted objects can be restored "
                            "with their attributes.",
    "stale_objects": "Disable, then delete after a grace period. The export lists the counts; "
                     "`Search-ADAccount -AccountInactive` lists the objects.",
    "subnet_missing": "Clients from this range do not map to any AD site (NO_CLIENT_SITE in netlogon.log). "
                      "Create the subnet in Sites and Services and link it to the right site.",
    "old_functional_level": "Raise the domain and forest functional levels once every DC runs a supported version.",
}


@dataclass
class Finding:
    code: str
    area: str
    severity: str
    target: str
    detail: str

    @property
    def fix(self) -> str:
        return FIX.get(self.code, "")


@dataclass
class Thresholds:
    stale_days: int = 90
    krbtgt_days: int = 180
    time_warn_s: int = 60
    time_crit_s: int = 300
    disk_warn_pct: float = 15
    disk_crit_pct: float = 5
    dhcp_warn_pct: float = 85
    dhcp_crit_pct: float = 95
    repl_crit_hours: int = 24
    max_domain_admins: int = 5


def _age_days(now: datetime, ts: datetime | None) -> float | None:
    return None if ts is None else (now - ts).total_seconds() / 86400


def check_dcs(s: Snapshot, t: Thresholds) -> list[Finding]:
    out: list[Finding] = []
    for dc in s.dcs:
        if not dc.reachable:
            out.append(Finding("dc_unreachable", AREAS[0], CRITICAL, dc.name, f"{dc.name} ({dc.site}) did not answer."))
            continue                     # everything else about an unreachable DC is noise
        for svc in CORE_SERVICES:
            state = dc.services.get(svc)
            if state is not None and state.lower() != "running":
                out.append(Finding("dc_service_down", AREAS[0], CRITICAL, dc.name, f"{svc} is {state}."))
        if dc.sysvol_shared is False:
            out.append(Finding("sysvol_not_shared", AREAS[0], CRITICAL, dc.name, "SYSVOL / NETLOGON not shared."))
        if dc.time_offset_s is not None and abs(dc.time_offset_s) >= t.time_warn_s:
            sev = CRITICAL if abs(dc.time_offset_s) >= t.time_crit_s else WARNING
            out.append(Finding("time_skew", AREAS[0], sev, dc.name,
                               f"Clock {dc.time_offset_s:+.0f} s from the PDC emulator."))
        if dc.ntds_free_pct is not None and dc.ntds_free_pct < t.disk_warn_pct:
            sev = CRITICAL if dc.ntds_free_pct < t.disk_crit_pct else WARNING
            out.append(Finding("ntds_disk_low", AREAS[0], sev, dc.name, f"{dc.ntds_free_pct:.0f}% free on the NTDS volume."))
    sites = {}
    for dc in s.dcs:
        sites.setdefault(dc.site, []).append(dc)
    for site, dcs in sorted(sites.items()):
        if not any(d.is_gc for d in dcs):
            out.append(Finding("site_without_gc", AREAS[0], WARNING, site, f"No Global Catalog among {len(dcs)} DC(s)."))
    return out


def _ago(hours: float) -> str:
    return f"{hours:.0f} h ago" if hours < 48 else f"{hours / 24:.0f} days ago"


def check_replication(s: Snapshot, t: Thresholds) -> list[Finding]:
    """One finding per source → destination link; the partitions that fail are listed in the detail."""
    unreachable = {dc.name for dc in s.dcs if not dc.reachable}
    bad: dict[tuple[str, str], list] = {}
    for r in s.replication:
        if r.failures or r.last_error not in ("", "0"):
            bad.setdefault((r.source, r.destination), []).append(r)
    out: list[Finding] = []
    for (src, dst), links in sorted(bad.items()):
        ages = [_age_days(s.collected_at, r.last_success) for r in links]
        oldest = None if any(a is None for a in ages) else max(ages)
        worst = max(links, key=lambda r: r.failures)
        parts = ", ".join(r.partition.split(",")[0] for r in links)
        when = "never succeeded" if oldest is None else f"last success {_ago(oldest * 24)}"
        detail = f"{len(links)} partition(s) failing ({parts}); {when}; {worst.failures} consecutive failures, " \
                 f"error {worst.last_error or '?'}."
        if src in unreachable:
            detail += f" Source {src} is unreachable."
        if oldest is None or oldest >= s.domain.tombstone_days / 2:
            out.append(Finding("repl_near_tombstone", AREAS[1], CRITICAL, f"{src} → {dst}",
                               detail + f" Tombstone lifetime is {s.domain.tombstone_days} days."))
        else:
            sev = CRITICAL if oldest * 24 >= t.repl_crit_hours else WARNING
            out.append(Finding("repl_failing", AREAS[1], sev, f"{src} → {dst}", detail))
    return out


def check_fsmo(s: Snapshot, dc_findings: list[Finding]) -> list[Finding]:
    bad = {f.target for f in dc_findings if f.severity == CRITICAL}
    out = []
    for role, holder in sorted(s.domain.fsmo.items()):
        if holder in bad:
            out.append(Finding("fsmo_holder_unhealthy", AREAS[0], CRITICAL, holder, f"Holds {role}."))
    return out


def check_dhcp(s: Snapshot, t: Thresholds) -> list[Finding]:
    out = []
    for sc in s.dhcp:
        target = f"{sc.server} {sc.scope_id}"
        if sc.used_pct >= t.dhcp_warn_pct:
            sev = CRITICAL if sc.used_pct >= t.dhcp_crit_pct else WARNING
            out.append(Finding("dhcp_scope_full", AREAS[2], sev, target,
                               f"{sc.name}: {sc.used_pct}% used ({sc.in_use} of {sc.in_use + sc.free})."))
        if sc.failover and sc.failover.lower() != "normal":
            out.append(Finding("dhcp_failover_degraded", AREAS[2], WARNING, target, f"{sc.name}: failover {sc.failover}."))
    return out


def check_gpos(s: Snapshot) -> list[Finding]:
    out = []
    for g in s.gpos:
        if g.user_version == 0 and g.computer_version == 0:
            out.append(Finding("gpo_empty", AREAS[3], INFO, g.name, "No user or computer settings."))
        elif g.links == 0:
            out.append(Finding("gpo_unlinked", AREAS[3], INFO, g.name, "Not linked to any site, domain or OU."))
    return out


def check_privileged(s: Snapshot, t: Thresholds) -> list[Finding]:
    out = []
    seen: set[str] = set()
    for group in PRIV_GROUPS:
        members = s.privileged.get(group, [])
        if group == "Schema Admins" and members:
            out.append(Finding("schema_admins_not_empty", AREAS[4], WARNING, group,
                               f"{len(members)} member(s): {', '.join(m.sam for m in members)}."))
        if group == "Domain Admins":
            users = [m for m in members if m.type == "user"]
            if len(users) > t.max_domain_admins:
                out.append(Finding("priv_too_many", AREAS[4], INFO, group,
                                   f"{len(users)} direct user members (target {t.max_domain_admins} or fewer)."))
        for m in members:
            if m.type != "user" or not m.enabled or m.sam in seen:
                continue
            age = _age_days(s.collected_at, m.last_logon)
            if age is None or age >= t.stale_days:
                seen.add(m.sam)
                out.append(Finding("priv_member_stale", AREAS[4], WARNING, m.sam,
                                   f"In {group}; " + ("never logged on." if age is None else f"last logon {age:.0f} days ago.")))
            if m.password_never_expires and (m.sam + "#pne") not in seen:
                seen.add(m.sam + "#pne")
                out.append(Finding("priv_pwd_never_expires", AREAS[4], WARNING, m.sam, f"In {group}."))
    age = _age_days(s.collected_at, s.domain.krbtgt_password_last_set)
    if age is not None and age >= t.krbtgt_days:
        out.append(Finding("krbtgt_old", AREAS[4], WARNING, "krbtgt", f"Password last set {age:.0f} days ago."))
    return out


def check_hygiene(s: Snapshot, t: Thresholds) -> list[Finding]:
    out = []
    if not s.domain.recycle_bin:
        out.append(Finding("recycle_bin_disabled", AREAS[5], WARNING, s.domain.dns_root, "AD Recycle Bin is off."))
    if s.domain.domain_mode.startswith(OLD_LEVELS) or s.domain.forest_mode.startswith(OLD_LEVELS):
        out.append(Finding("old_functional_level", AREAS[5], INFO, s.domain.dns_root,
                           f"Domain {s.domain.domain_mode}, forest {s.domain.forest_mode}."))
    a = s.accounts
    parts = [f"{a[k]} {label}" for k, label in (("staleComputers", "computers"), ("staleUsers", "users"))
             if a.get(k)]
    if parts:
        out.append(Finding("stale_objects", AREAS[5], INFO, s.domain.dns_root,
                           f"Enabled but inactive for {a.get('staleDays', t.stale_days)}+ days: {', '.join(parts)}."))
    out.extend(check_subnets(s))
    return out


def check_subnets(s: Snapshot) -> list[Finding]:
    nets = []
    for n in s.subnets:
        try:
            nets.append(ipaddress.ip_network(n, strict=False))
        except ValueError:
            continue
    missing: dict[str, int] = {}
    for entry in s.no_client_site:
        try:
            ip = ipaddress.ip_address(entry["ip"])
        except (KeyError, ValueError):
            continue
        if any(ip in n for n in nets):
            continue                     # already fixed since the log line was written
        block = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        missing[block] = missing.get(block, 0) + int(entry.get("count") or 1)
    return [Finding("subnet_missing", AREAS[5], WARNING, block, f"{count} logon(s) from {block} with no AD site.")
            for block, count in sorted(missing.items())]


def run_all(s: Snapshot, t: Thresholds | None = None) -> list[Finding]:
    t = t or Thresholds()
    dc = check_dcs(s, t)
    findings = dc + check_fsmo(s, dc) + check_replication(s, t) + check_dhcp(s, t) + check_gpos(s) \
        + check_privileged(s, t) + check_hygiene(s, t)
    return sorted(findings, key=lambda f: (SEV_ORDER[f.severity], AREAS.index(f.area), f.target, f.code))


def area_status(findings: list[Finding]) -> dict[str, str]:
    status = {a: "ok" for a in AREAS}
    for f in findings:
        cur = status[f.area]
        if cur == "ok" or SEV_ORDER[f.severity] < SEV_ORDER[cur]:
            status[f.area] = f.severity
    return status
