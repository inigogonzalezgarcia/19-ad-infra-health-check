# Weekly AD health check · runbook

For the engineer who runs the check and the person who chairs the weekly ops or change meeting.

## When

- **Every Monday before the office opens**, so problems from the weekend are found before users find them.
- **Before and after any change on a domain controller** (patching, a new DC, a site move, a DHCP change).
- **After an incident** that touched logons, Group Policy or name resolution.

## Run it

```powershell
# on a management server with RSAT, as an account that can read AD and query the DCs
.\scripts\Export-ADHealth.ps1 -OutputPath .\ad_health.json
```

```bash
python -m adhealth report ad_health.json --previous last_week/findings.csv --out this_week
```

Keep each week's `findings.csv`: the next run uses it to list what is **new** and what was **resolved**.
If the export prints a warning, open `collectionErrors` in the JSON first: a section that could not be read
is not the same as a section with no problems.

## Read the result

1. **Fix today** (critical): a DC that does not answer, a core service stopped, SYSVOL not shared, a clock more
   than 5 minutes out, replication failing for more than 24 hours, a DHCP scope above 95 %. One owner each,
   before 09:00.
2. **Plan this week** (warning): open a ticket or a change. Privileged-account findings go to the security
   owner, not only to the infrastructure team.
3. **Housekeeping** (info): review once a month. Delete empty and unlinked GPOs only after a backup
   (`Backup-GPO`).

## Things that are easy to get wrong

- **Replication errors**: 1722 and 1753 are almost always network or firewall (RPC). 8453 is permissions.
  8524 is DNS lookup of the partner. 8614 means the tombstone lifetime was exceeded: do not force replication,
  the DC has to be demoted and rebuilt.
- **krbtgt reset**: twice, with full replication in between, as a planned change. Never two resets in a row.
- **Seizing FSMO roles**: only if the holder will never come back. A seized role holder must not be brought
  back online.
- **AD Recycle Bin**: enabling it cannot be undone. That is fine, but it is a forest change: put it through CAB.

## What the check does not do

It does not change anything, does not read passwords or security logs, and does not test backups.
A successful system-state backup and a restore test belong in the DR plan, not in this report.
