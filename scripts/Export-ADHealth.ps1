<#
.SYNOPSIS
    Collects a read-only health snapshot of one Active Directory domain into a JSON file that adhealth can read.

.DESCRIPTION
    Domain and forest facts, every domain controller (reachability, core services, SYSVOL share, clock offset,
    free space on the NTDS volume), replication metadata, DHCP scopes and failover, GPO links and versions,
    direct members of the privileged groups, inactive account counts, AD subnets and the NO_CLIENT_SITE lines
    from each DC's netlogon.log.

    Nothing is changed. Run it from a management server with RSAT (ActiveDirectory, GroupPolicy, DhcpServer)
    as an account that can read the directory, query the DCs over WMI/CIM and read \\DC\admin$\debug.
    Every section is wrapped on its own: if one part fails (for example DHCP), the rest is still exported and
    the error is written to "collectionErrors".

.EXAMPLE
    .\Export-ADHealth.ps1 -OutputPath .\ad_health.json
    .\Export-ADHealth.ps1 -Server MAD-DC01 -StaleDays 60 -SkipDhcp
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".\ad_health.json",
    [string]$Server,                       # DC to query; default: one picked by the locator
    [int]$StaleDays = 90,
    [switch]$SkipDhcp,
    [switch]$SkipNetlogonLog
)

$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory
$ad = @{}
if ($Server) { $ad.Server = $Server }
$errors = @()
function Iso($d) { if ($d) { ([datetime]$d).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") } }

# --- Domain and forest -------------------------------------------------------------------------------
$domain = Get-ADDomain @ad
$forest = Get-ADForest @ad
$krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet @ad
$dsPath = "CN=Directory Service,CN=Windows NT,CN=Services," + (Get-ADRootDSE @ad).configurationNamingContext
$tombstone = (Get-ADObject $dsPath -Properties tombstoneLifetime @ad).tombstoneLifetime
$recycle = Get-ADOptionalFeature -Filter 'Name -like "Recycle Bin Feature"' @ad

$domainInfo = [ordered]@{
    dnsRoot               = $domain.DNSRoot
    netbios               = $domain.NetBIOSName
    domainMode            = "$($domain.DomainMode)"
    forestMode            = "$($forest.ForestMode)"
    krbtgtPasswordLastSet = Iso $krbtgt.PasswordLastSet
    tombstoneLifetimeDays = if ($tombstone) { $tombstone } else { 180 }
    recycleBinEnabled     = [bool]$recycle.EnabledScopes
    fsmo                  = [ordered]@{
        SchemaMaster         = $forest.SchemaMaster
        DomainNamingMaster   = $forest.DomainNamingMaster
        PDCEmulator          = $domain.PDCEmulator
        RIDMaster            = $domain.RIDMaster
        InfrastructureMaster = $domain.InfrastructureMaster
    }
}

# --- Domain controllers --------------------------------------------------------------------------------
$pdc = $domain.PDCEmulator
$dcs = @()
foreach ($dc in Get-ADDomainController -Filter * @ad) {
    $name = $dc.HostName
    $item = [ordered]@{ name = $name; site = $dc.Site; os = $dc.OperatingSystem; isGlobalCatalog = $dc.IsGlobalCatalog
                        reachable = $true; services = [ordered]@{}; sysvolShared = $null
                        timeOffsetSeconds = $null; ntdsVolumeFreePercent = $null }
    if (-not (Test-Connection -ComputerName $name -Count 1 -Quiet)) {
        $item.reachable = $false; $dcs += $item; continue
    }
    try {
        foreach ($svc in Get-CimInstance Win32_Service -ComputerName $name `
                 -Filter "Name='NTDS' OR Name='DNS' OR Name='Netlogon' OR Name='Kdc' OR Name='DFSR' OR Name='W32Time'") {
            $item.services[$svc.Name] = "$($svc.State)"
        }
        $shares = (Get-CimInstance Win32_Share -ComputerName $name).Name
        $item.sysvolShared = ($shares -contains "SYSVOL") -and ($shares -contains "NETLOGON")
        # Volume that holds ntds.dit (read from the DC's registry through CIM)
        $reg = Invoke-CimMethod -ComputerName $name -Namespace root\default -ClassName StdRegProv -MethodName GetStringValue `
               -Arguments @{ hDefKey = [uint32]2147483650; sSubKeyName = "SYSTEM\CurrentControlSet\Services\NTDS\Parameters"; sValueName = "DSA Database file" }
        $drive = if ($reg.sValue) { $reg.sValue.Substring(0, 2) } else { "C:" }
        $disk = Get-CimInstance Win32_LogicalDisk -ComputerName $name -Filter "DeviceID='$drive'"
        if ($disk.Size) { $item.ntdsVolumeFreePercent = [math]::Round(100 * $disk.FreeSpace / $disk.Size, 1) }
    } catch { $errors += "DC ${name} (CIM): $($_.Exception.Message)" }
    try {
        # Offset against the PDC emulator, in seconds (last sample of w32tm /stripchart)
        if ($name -eq $pdc) { $item.timeOffsetSeconds = 0 }
        else {
            $out = w32tm /stripchart /computer:$name /samples:1 /dataonly 2>$null | Where-Object { $_ -match ",\s*[+-]" } |
                   Select-Object -Last 1
            if ($out -match ",\s*([+-][\d\.]+)s") { $item.timeOffsetSeconds = [double]$Matches[1] }
        }
    } catch { $errors += "DC ${name} (time): $($_.Exception.Message)" }
    $dcs += $item
}

# --- Replication -----------------------------------------------------------------------------------------
$repl = @()
try {
    foreach ($r in Get-ADReplicationPartnerMetadata -Target $domain.DNSRoot -Scope Domain -Partition * @ad) {
        $source = ($r.Partner -split ",")[1] -replace "^CN=", ""      # CN=NTDS Settings,CN=<DC>,CN=Servers,...
        $repl += [ordered]@{
            destination = $r.Server; source = $source; partition = $r.Partition
            lastSuccess = Iso $r.LastReplicationSuccess; lastAttempt = Iso $r.LastReplicationAttempt
            consecutiveFailures = $r.ConsecutiveReplicationFailures; lastError = "$($r.LastReplicationResult)"
        }
    }
} catch { $errors += "Replication: $($_.Exception.Message)" }

# --- DHCP --------------------------------------------------------------------------------------------------
$scopes = @()
if (-not $SkipDhcp) {
    try {
        Import-Module DhcpServer
        foreach ($srv in Get-DhcpServerInDC) {
            $host_ = $srv.DnsName
            try {
                $fo = @{}
                foreach ($f in Get-DhcpServerv4Failover -ComputerName $host_ -ErrorAction SilentlyContinue) {
                    foreach ($sid in $f.ScopeId) { $fo["$sid"] = "$($f.State)" }
                }
                $names = @{}
                foreach ($s in Get-DhcpServerv4Scope -ComputerName $host_) { $names["$($s.ScopeId)"] = $s.Name }
                foreach ($st in Get-DhcpServerv4ScopeStatistics -ComputerName $host_) {
                    $sid = "$($st.ScopeId)"
                    $scopes += [ordered]@{ server = $host_.Split(".")[0]; scopeId = $sid; name = $names[$sid]
                                           inUse = $st.InUse; free = $st.Free; failover = $fo[$sid] }
                }
            } catch { $errors += "DHCP ${host_}: $($_.Exception.Message)" }
        }
    } catch { $errors += "DHCP: $($_.Exception.Message)" }
}

# --- Group Policy -------------------------------------------------------------------------------------------
$gpos = @()
try {
    Import-Module GroupPolicy
    $gpArgs = @{ Domain = $domain.DNSRoot }
    if ($Server) { $gpArgs.Server = $Server }
    foreach ($g in Get-GPO -All @gpArgs) {
        [xml]$x = Get-GPOReport -Guid $g.Id -ReportType Xml @gpArgs
        $links = @($x.GPO.LinksTo).Where({ $_ -ne $null }).Count
        $gpos += [ordered]@{ name = $g.DisplayName; links = $links
                             userVersion = $g.User.DSVersion; computerVersion = $g.Computer.DSVersion
                             userSettingsEnabled = "$($g.GpoStatus)" -notmatch "UserSettingsDisabled|AllSettingsDisabled"
                             computerSettingsEnabled = "$($g.GpoStatus)" -notmatch "ComputerSettingsDisabled|AllSettingsDisabled"
                             modified = Iso $g.ModificationTime }
    }
} catch { $errors += "GPO: $($_.Exception.Message)" }

# --- Privileged groups (direct members only) --------------------------------------------------------------
$priv = @()
foreach ($grp in "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators") {
    try {
        $members = @()
        foreach ($m in Get-ADGroupMember -Identity $grp @ad) {
            $entry = [ordered]@{ sam = $m.SamAccountName; type = $m.objectClass }
            if ($m.objectClass -eq "user") {
                $u = Get-ADUser $m.distinguishedName -Properties Enabled, lastLogonTimestamp, PasswordNeverExpires @ad
                $entry.enabled = $u.Enabled
                $entry.lastLogon = if ($u.lastLogonTimestamp) { Iso ([datetime]::FromFileTimeUtc($u.lastLogonTimestamp)) }
                $entry.passwordNeverExpires = $u.PasswordNeverExpires
            }
            $members += $entry
        }
        $priv += [ordered]@{ group = $grp; members = $members }
    } catch { $errors += "Group ${grp}: $($_.Exception.Message)" }
}

# --- Account counts, subnets, NO_CLIENT_SITE ----------------------------------------------------------------
$span = New-TimeSpan -Days $StaleDays
$accounts = [ordered]@{
    staleDays    = $StaleDays
    totalUsers   = (Get-ADUser -Filter * @ad | Measure-Object).Count
    totalComputers = (Get-ADComputer -Filter * @ad | Measure-Object).Count
    staleUsers   = (Search-ADAccount -AccountInactive -UsersOnly -TimeSpan $span @ad | Where-Object Enabled | Measure-Object).Count
    staleComputers = (Search-ADAccount -AccountInactive -ComputersOnly -TimeSpan $span @ad | Where-Object Enabled | Measure-Object).Count
    passwordNeverExpires = (Get-ADUser -Filter 'PasswordNeverExpires -eq $true -and Enabled -eq $true' @ad | Measure-Object).Count
}
$subnets = @(Get-ADReplicationSubnet -Filter * @ad | ForEach-Object Name)

$noSite = @{}
if (-not $SkipNetlogonLog) {
    foreach ($dc in $dcs | Where-Object reachable) {
        $log = "\\$($dc.name)\admin$\debug\netlogon.log"
        try {
            foreach ($line in Get-Content $log -Tail 20000 | Select-String "NO_CLIENT_SITE") {
                $ip = ($line.Line.Trim() -split "\s+")[-1]
                $noSite[$ip] = 1 + [int]$noSite[$ip]
            }
        } catch { $errors += "netlogon.log on $($dc.name): $($_.Exception.Message)" }
    }
}

$result = [ordered]@{
    collectedAt       = Iso (Get-Date)
    domain            = $domainInfo
    domainControllers = $dcs
    replication       = $repl
    dhcpScopes        = $scopes
    gpos              = $gpos
    privilegedGroups  = $priv
    accounts          = $accounts
    subnets           = $subnets
    noClientSite      = @($noSite.GetEnumerator() | ForEach-Object { [ordered]@{ ip = $_.Key; count = $_.Value } })
    collectionErrors  = $errors
}
$result | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "Wrote $OutputPath ($($dcs.Count) DCs, $($repl.Count) replication links, $($scopes.Count) DHCP scopes, $($gpos.Count) GPOs)."
if ($errors) { Write-Warning "$($errors.Count) section(s) could not be read; see collectionErrors in the file." }
