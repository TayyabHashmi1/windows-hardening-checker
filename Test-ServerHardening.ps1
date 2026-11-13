<#
.SYNOPSIS
    Read-only hardening check for a Windows machine. Writes a CSV and an HTML report.

.DESCRIPTION
    Checks ten common hardening settings (firewall, SMBv1, RDP NLA, guest account, lockout,
    password length, audit policy, Defender, automatic updates, patch age) using built-in
    Windows tools. It never changes anything.

    A setting that cannot be read, for example because the session is not elevated, is
    reported as Unknown with the reason. It is never guessed as a Pass.

    Data collection is separate from the checks, so the checks can be tested with mocked
    facts (see Tests.ps1) and with the -Demo switch.

.PARAMETER Demo
    Build the report from fictional sample results. Nothing on this machine is read.

.PARAMETER PatchMaxDays
    The newest installed hotfix must be at most this many days old. Default 45.

.PARAMETER MinPasswordLength
    Required minimum password length. Default 14.

.PARAMETER OutputPath
    Folder for the report files. Created if missing.

.EXAMPLE
    .\Test-ServerHardening.ps1 -Demo

.EXAMPLE
    .\Test-ServerHardening.ps1 -OutputPath .\report
#>
[CmdletBinding()]
param(
    [switch]$Demo,
    [int]$PatchMaxDays = 45,
    [int]$MinPasswordLength = 14,
    [string]$OutputPath = (Join-Path (Get-Location) 'HardeningReport')
)

Set-StrictMode -Version 2.0

function New-CheckResult {
    param($Id, $Area, $Check, $Expected, $Actual, $Status, $Severity, $Fix)
    [pscustomobject]@{
        Id       = $Id
        Area     = $Area
        Check    = $Check
        Expected = $Expected
        Actual   = $Actual
        Status   = $Status
        Severity = $Severity
        Fix      = $Fix
    }
}

# Returns the reason a group of facts could not be read, or $null when it was read.
function Get-WhyUnknown {
    param($Facts, [string]$Key)
    if ($Facts.Unavailable.ContainsKey($Key)) { return [string]$Facts.Unavailable[$Key] }
    return $null
}

# ---- parsers (tested with sample text in Tests.ps1) ----

function ConvertFrom-NetAccounts {
    param([string[]]$Lines)
    $out = @{ LockoutThreshold = $null; MinPasswordLength = $null }
    foreach ($l in $Lines) {
        if ($l -match '^\s*Lockout threshold:\s*(.+?)\s*$') {
            $v = $Matches[1]
            if ($v -eq 'Never') { $out.LockoutThreshold = 0 } else { $out.LockoutThreshold = [int]$v }
        }
        elseif ($l -match '^\s*Minimum password length:\s*(\d+)\s*$') {
            $out.MinPasswordLength = [int]$Matches[1]
        }
    }
    $out
}

# Turns native command output into plain text lines. In Windows PowerShell 5.1, stderr lines
# arrive as error records, so read their message instead of the type name.
function ConvertTo-OutputLines {
    param($Output)
    foreach ($o in @($Output)) {
        if ($o -is [System.Management.Automation.ErrorRecord]) { [string]$o.Exception.Message }
        else { [string]$o }
    }
}

# productState from the Windows Security Center: bit 0x1000 means the product is switched on.
function Test-AvProductOn {
    param([int]$ProductState)
    return (($ProductState -band 0x1000) -ne 0)
}

function ConvertFrom-AuditPolLine {
    param([string[]]$Lines, [string]$Subcategory)
    foreach ($l in $Lines) {
        $pattern = '^\s*' + [regex]::Escape($Subcategory) + '\s{2,}(.+?)\s*$'
        if ($l -match $pattern) { return $Matches[1] }
    }
    return $null
}

# ---- checks (pure logic on a facts object) ----

function Test-HardeningFacts {
    param($Facts, [datetime]$Now, [int]$PatchMaxDays, [int]$MinPasswordLength)
    $r = New-Object System.Collections.Generic.List[object]

    # H01 firewall
    $why = Get-WhyUnknown $Facts 'Firewall'
    if ($why) { $r.Add((New-CheckResult 'H01' 'Network' 'Windows Firewall on for all profiles' 'Domain, Private and Public enabled' $why 'Unknown' 'High' 'Run elevated, or check the firewall settings by hand.')) }
    else {
        $off = @($Facts.Firewall | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
        if ($off.Count -eq 0) { $r.Add((New-CheckResult 'H01' 'Network' 'Windows Firewall on for all profiles' 'Domain, Private and Public enabled' 'All profiles enabled' 'Pass' 'High' '')) }
        else { $r.Add((New-CheckResult 'H01' 'Network' 'Windows Firewall on for all profiles' 'Domain, Private and Public enabled' ('Disabled: ' + ($off -join ', ')) 'Fail' 'High' 'Enable the firewall on every profile.')) }
    }

    # H02 SMBv1
    $why = Get-WhyUnknown $Facts 'Smb1'
    if ($why) { $r.Add((New-CheckResult 'H02' 'Network' 'SMBv1 server disabled' 'Disabled' $why 'Unknown' 'High' 'Run elevated, or check SMB settings by hand.')) }
    elseif ($Facts.Smb1Enabled) { $r.Add((New-CheckResult 'H02' 'Network' 'SMBv1 server disabled' 'Disabled' 'Enabled' 'Fail' 'High' 'Disable SMBv1 and remove the feature if nothing needs it.')) }
    else { $r.Add((New-CheckResult 'H02' 'Network' 'SMBv1 server disabled' 'Disabled' 'Disabled' 'Pass' 'High' '')) }

    # H03 RDP NLA
    $why = Get-WhyUnknown $Facts 'Rdp'
    if ($why) { $r.Add((New-CheckResult 'H03' 'Remote access' 'RDP requires Network Level Authentication' 'NLA required when RDP is on' $why 'Unknown' 'High' 'Check the Remote Desktop settings by hand.')) }
    elseif (-not $Facts.RdpEnabled) { $r.Add((New-CheckResult 'H03' 'Remote access' 'RDP requires Network Level Authentication' 'NLA required when RDP is on' 'RDP is off' 'Pass' 'High' '')) }
    elseif ($Facts.RdpNla) { $r.Add((New-CheckResult 'H03' 'Remote access' 'RDP requires Network Level Authentication' 'NLA required when RDP is on' 'RDP on, NLA required' 'Pass' 'High' '')) }
    else { $r.Add((New-CheckResult 'H03' 'Remote access' 'RDP requires Network Level Authentication' 'NLA required when RDP is on' 'RDP on, NLA not required' 'Fail' 'High' 'Require Network Level Authentication for Remote Desktop.')) }

    # H04 guest account
    $why = Get-WhyUnknown $Facts 'Guest'
    if ($why) { $r.Add((New-CheckResult 'H04' 'Accounts' 'Guest account disabled' 'Disabled' $why 'Unknown' 'Medium' 'Check local users by hand.')) }
    elseif ($Facts.GuestEnabled) { $r.Add((New-CheckResult 'H04' 'Accounts' 'Guest account disabled' 'Disabled' 'Enabled' 'Fail' 'Medium' 'Disable the Guest account.')) }
    else { $r.Add((New-CheckResult 'H04' 'Accounts' 'Guest account disabled' 'Disabled' 'Disabled' 'Pass' 'Medium' '')) }

    # H05 lockout
    $why = Get-WhyUnknown $Facts 'Lockout'
    if ($why) { $r.Add((New-CheckResult 'H05' 'Accounts' 'Account lockout threshold set' 'Greater than 0' $why 'Unknown' 'Medium' 'Check the account policy by hand.')) }
    elseif ($Facts.LockoutThreshold -gt 0) { $r.Add((New-CheckResult 'H05' 'Accounts' 'Account lockout threshold set' 'Greater than 0' ([string]$Facts.LockoutThreshold) 'Pass' 'Medium' '')) }
    else { $r.Add((New-CheckResult 'H05' 'Accounts' 'Account lockout threshold set' 'Greater than 0' 'Never lock out' 'Fail' 'Medium' 'Set an account lockout threshold.')) }

    # H06 password length
    $why = Get-WhyUnknown $Facts 'PasswordLength'
    $expected = ('At least {0}' -f $MinPasswordLength)
    if ($why) { $r.Add((New-CheckResult 'H06' 'Accounts' 'Minimum password length' $expected $why 'Unknown' 'Medium' 'Check the password policy by hand.')) }
    elseif ($Facts.MinPasswordLength -ge $MinPasswordLength) { $r.Add((New-CheckResult 'H06' 'Accounts' 'Minimum password length' $expected ([string]$Facts.MinPasswordLength) 'Pass' 'Medium' '')) }
    else { $r.Add((New-CheckResult 'H06' 'Accounts' 'Minimum password length' $expected ([string]$Facts.MinPasswordLength) 'Fail' 'Medium' ('Raise the minimum password length to {0}.' -f $MinPasswordLength))) }

    # H07 audit policy
    $why = Get-WhyUnknown $Facts 'Audit'
    if ($why) { $r.Add((New-CheckResult 'H07' 'Logging' 'Logon and account management auditing' 'Success and Failure for both' $why 'Unknown' 'Medium' 'Run elevated, or check the audit policy by hand.')) }
    else {
        $ok = ($Facts.AuditLogon -eq 'Success and Failure') -and ($Facts.AuditAccountMgmt -eq 'Success and Failure')
        $actual = ('Logon: {0}; User Account Management: {1}' -f $Facts.AuditLogon, $Facts.AuditAccountMgmt)
        if ($ok) { $r.Add((New-CheckResult 'H07' 'Logging' 'Logon and account management auditing' 'Success and Failure for both' $actual 'Pass' 'Medium' '')) }
        else { $r.Add((New-CheckResult 'H07' 'Logging' 'Logon and account management auditing' 'Success and Failure for both' $actual 'Fail' 'Medium' 'Audit success and failure for Logon and User Account Management.')) }
    }

    # H08 Defender
    $why = Get-WhyUnknown $Facts 'Defender'
    if ($why) { $r.Add((New-CheckResult 'H08' 'Protection' 'Defender real-time protection on' 'On, when Defender is the active antivirus' $why 'Unknown' 'High' 'Check the antivirus product by hand.')) }
    elseif (-not $Facts.DefenderActive) {
        $names = if ($Facts.AntivirusNames) { ' Registered antivirus: ' + $Facts.AntivirusNames + '.' } else { '' }
        $r.Add((New-CheckResult 'H08' 'Protection' 'Defender real-time protection on' 'On, when Defender is the active antivirus' ('Defender is not the active antivirus. Check the vendor product.' + $names) 'Unknown' 'High' 'Check the active antivirus product by hand.'))
    }
    elseif ($Facts.DefenderRealTime) { $r.Add((New-CheckResult 'H08' 'Protection' 'Defender real-time protection on' 'On, when Defender is the active antivirus' 'On' 'Pass' 'High' '')) }
    else { $r.Add((New-CheckResult 'H08' 'Protection' 'Defender real-time protection on' 'On, when Defender is the active antivirus' 'Off' 'Fail' 'High' 'Turn real-time protection on.')) }

    # H09 automatic updates
    $why = Get-WhyUnknown $Facts 'AutoUpdate'
    if ($why) { $r.Add((New-CheckResult 'H09' 'Patching' 'Automatic updates not disabled by policy' 'Not disabled' $why 'Unknown' 'Medium' 'Check the Windows Update policy by hand.')) }
    elseif ($Facts.NoAutoUpdate) { $r.Add((New-CheckResult 'H09' 'Patching' 'Automatic updates not disabled by policy' 'Not disabled' 'Disabled by policy' 'Fail' 'Medium' 'Remove the policy that disables automatic updates.')) }
    else { $r.Add((New-CheckResult 'H09' 'Patching' 'Automatic updates not disabled by policy' 'Not disabled' 'Not disabled' 'Pass' 'Medium' '')) }

    # H10 patch age
    $why = Get-WhyUnknown $Facts 'Hotfix'
    $expected = ('Newest hotfix within {0} days' -f $PatchMaxDays)
    if ($why) { $r.Add((New-CheckResult 'H10' 'Patching' 'Recent patch installed' $expected $why 'Unknown' 'Medium' 'Check the update history by hand.')) }
    elseif ($null -eq $Facts.LastHotfix) { $r.Add((New-CheckResult 'H10' 'Patching' 'Recent patch installed' $expected 'No hotfix dates available' 'Unknown' 'Medium' 'Check the update history by hand.')) }
    else {
        $age = [int]($Now - $Facts.LastHotfix).TotalDays
        $actual = ('Newest hotfix is {0} days old' -f $age)
        if ($age -le $PatchMaxDays) { $r.Add((New-CheckResult 'H10' 'Patching' 'Recent patch installed' $expected $actual 'Pass' 'Medium' '')) }
        else { $r.Add((New-CheckResult 'H10' 'Patching' 'Recent patch installed' $expected $actual 'Fail' 'Medium' 'Install the latest updates.')) }
    }
    $r
}

# ---- collection (read-only; each group is isolated so one failure cannot hide the rest) ----

function Get-HardeningFacts {
    $un = @{}
    $f = [ordered]@{
        Firewall = $null; Smb1Enabled = $false; RdpEnabled = $false; RdpNla = $false; GuestEnabled = $false
        LockoutThreshold = 0; MinPasswordLength = 0; AuditLogon = ''; AuditAccountMgmt = ''
        DefenderActive = $false; DefenderRealTime = $false; AntivirusNames = ''; NoAutoUpdate = $false; LastHotfix = $null
    }

    try {
        $f.Firewall = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Enabled = ([string]$_.Enabled -eq 'True') } })
    } catch { $un['Firewall'] = 'Could not read: ' + $_.Exception.Message.Trim() }

    try {
        $f.Smb1Enabled = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
    } catch { $un['Smb1'] = 'Could not read (usually needs an elevated session): ' + $_.Exception.Message.Trim() }

    try {
        $ts = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop
        $nla = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction Stop
        $f.RdpEnabled = ($ts.fDenyTSConnections -eq 0)
        $f.RdpNla = ($nla.UserAuthentication -eq 1)
    } catch { $un['Rdp'] = 'Could not read: ' + $_.Exception.Message.Trim() }

    try {
        $f.GuestEnabled = [bool](Get-LocalUser -Name 'Guest' -ErrorAction Stop).Enabled
    } catch { $un['Guest'] = 'Could not read: ' + $_.Exception.Message.Trim() }

    try {
        $lines = @(& net.exe accounts 2>&1 | ForEach-Object { [string]$_ })
        $acct = ConvertFrom-NetAccounts -Lines $lines
        if ($null -eq $acct.LockoutThreshold) { $un['Lockout'] = 'Could not read the lockout threshold from net accounts (English output expected).' } else { $f.LockoutThreshold = $acct.LockoutThreshold }
        if ($null -eq $acct.MinPasswordLength) { $un['PasswordLength'] = 'Could not read the password length from net accounts (English output expected).' } else { $f.MinPasswordLength = $acct.MinPasswordLength }
    } catch {
        $un['Lockout'] = 'Could not run net accounts: ' + $_.Exception.Message.Trim()
        $un['PasswordLength'] = $un['Lockout']
    }

    try {
        $logon = @(ConvertTo-OutputLines (& auditpol.exe /get /subcategory:"Logon" 2>&1))
        $acctMgmt = @(ConvertTo-OutputLines (& auditpol.exe /get /subcategory:"User Account Management" 2>&1))
        $a = ConvertFrom-AuditPolLine -Lines $logon -Subcategory 'Logon'
        $b = ConvertFrom-AuditPolLine -Lines $acctMgmt -Subcategory 'User Account Management'
        if ($null -eq $a -or $null -eq $b) {
            $text = (($logon + $acctMgmt) -join ' ')
            if ($text -match 'privilege|0x00000522|denied') { throw 'needs an elevated (administrator) session.' }
            throw ('auditpol did not return a setting. ' + $text.Trim())
        }
        $f.AuditLogon = $a
        $f.AuditAccountMgmt = $b
    } catch { $un['Audit'] = 'Could not read: ' + $_.Exception.Message.Trim() }

    try {
        $active = $null
        try {
            # The Security Center lists every registered antivirus. Defender counts as active only when its on bit is set.
            $products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntivirusProduct -ErrorAction Stop)
            $f.AntivirusNames = (($products | ForEach-Object { [string]$_.displayName }) -join ', ')
            $def = @($products | Where-Object { $_.displayName -eq 'Windows Defender' })
            $active = ($def.Count -gt 0 -and (Test-AvProductOn -ProductState ([int]$def[0].productState)))
        } catch { $active = $null }
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if ($null -eq $active) { $active = [bool]$mp.AMServiceEnabled -and [bool]$mp.AntivirusEnabled }
        $f.DefenderActive = $active
        $f.DefenderRealTime = [bool]$mp.RealTimeProtectionEnabled
    } catch { $un['Defender'] = 'Could not read: ' + $_.Exception.Message.Trim() }

    try {
        $au = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -ErrorAction SilentlyContinue
        $f.NoAutoUpdate = ($null -ne $au -and $au.NoAutoUpdate -eq 1)
    } catch { $un['AutoUpdate'] = 'Could not read: ' + $_.Exception.Message.Trim() }

    try {
        $hf = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($hf) { $f.LastHotfix = [datetime]$hf.InstalledOn }
    } catch { $un['Hotfix'] = 'Could not read: ' + $_.Exception.Message.Trim() }

    $f['Unavailable'] = $un
    [pscustomobject]$f
}

function Get-DemoFacts {
    param([datetime]$Now)
    [pscustomobject]@{
        Firewall         = @(
            [pscustomobject]@{ Name = 'Domain'; Enabled = $true }
            [pscustomobject]@{ Name = 'Private'; Enabled = $true }
            [pscustomobject]@{ Name = 'Public'; Enabled = $false }
        )
        Smb1Enabled      = $true
        RdpEnabled       = $true
        RdpNla           = $false
        GuestEnabled     = $false
        LockoutThreshold = 0
        MinPasswordLength = 12
        AuditLogon       = 'Success and Failure'
        AuditAccountMgmt = 'Success'
        DefenderActive   = $false
        DefenderRealTime = $false
        AntivirusNames   = 'Contoso Endpoint Protection (fictional)'
        NoAutoUpdate     = $false
        LastHotfix       = $Now.Date.AddDays(-20)
        Unavailable      = @{}
    }
}

function Export-HardeningReport {
    param($Results, [string]$OutputPath, [datetime]$Now, [bool]$IsDemo)
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $stamp = $Now.ToString('yyyyMMdd-HHmm')
    $csvPath = Join-Path $OutputPath ("hardening-{0}.csv" -f $stamp)
    $htmPath = Join-Path $OutputPath ("hardening-{0}.html" -f $stamp)
    $statusOrder = @{ Fail = 0; Unknown = 1; Pass = 2 }
    $sevOrder = @{ High = 0; Medium = 1; Low = 2 }
    $sorted = @($Results | Sort-Object @{ Expression = { $statusOrder[$_.Status] } }, @{ Expression = { $sevOrder[$_.Severity] } }, Id)
    $sorted | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $pass = @($sorted | Where-Object { $_.Status -eq 'Pass' }).Count
    $fail = @($sorted | Where-Object { $_.Status -eq 'Fail' }).Count
    $unk = @($sorted | Where-Object { $_.Status -eq 'Unknown' }).Count
    $rows = foreach ($x in $sorted) {
        $cells = @($x.Status.ToLower(), (& $enc $x.Status), (& $enc $x.Id), (& $enc $x.Area), (& $enc $x.Check), (& $enc $x.Expected), (& $enc $x.Actual), (& $enc $x.Severity), (& $enc $x.Fix))
        $tpl = '<tr><td><span class="pill {0}">{1}</span></td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td></tr>'
        $tpl -f $cells
    }
    $css = @'
body{font-family:Segoe UI,system-ui,sans-serif;margin:32px;color:#14202b;background:#f6f8fa}
h1{margin:0 0 4px}p.sub{color:#5a6b7b;margin:0 0 24px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.card{background:#fff;border:1px solid #d8e0e8;border-radius:10px;padding:14px 18px;min-width:140px}
.card b{display:block;font-size:28px}
table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #d8e0e8}
th,td{padding:9px 12px;border-bottom:1px solid #e6ecf1;text-align:left;font-size:14px;vertical-align:top}
th{background:#eef2f6}
.pill{display:inline-block;min-width:64px;text-align:center;border-radius:999px;padding:2px 10px;font-weight:600;color:#fff}
.pass{background:#1a7f4b}.fail{background:#c0392b}.unknown{background:#6b7a8a}
.note{color:#5a6b7b;font-size:13px;margin-top:16px}
'@
    $demoNote = if ($IsDemo) { ' from fictional demo data' } else { '' }
    $html = @(
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Hardening report</title><style>' + $css + '</style></head><body>'
        '<h1>Windows hardening report</h1>'
        ('<p class="sub">Generated {0}{1}. {2} checks.</p>' -f $Now.ToString('yyyy-MM-dd HH:mm'), $demoNote, $sorted.Count)
        ('<div class="cards"><div class="card"><b>{0}</b>Pass</div><div class="card"><b>{1}</b>Fail</div><div class="card"><b>{2}</b>Unknown</div></div>' -f $pass, $fail, $unk)
        '<table><thead><tr><th>Status</th><th>Id</th><th>Area</th><th>Check</th><th>Expected</th><th>Actual</th><th>Severity</th><th>Fix</th></tr></thead><tbody>'
        ($rows -join [Environment]::NewLine)
        '</tbody></table>'
        '<p class="note">Read-only check. Unknown means the setting could not be read, often because the session is not elevated. It is not a pass. This is a small baseline, not a full benchmark. No benchmark control mapping is claimed.</p>'
        '</body></html>'
    ) -join [Environment]::NewLine
    Set-Content -Path $htmPath -Value $html -Encoding UTF8
    [pscustomobject]@{ Csv = $csvPath; Html = $htmPath; Pass = $pass; Fail = $fail; Unknown = $unk }
}

function Invoke-ServerHardeningCheck {
    $now = Get-Date
    if ($Demo) { $facts = Get-DemoFacts -Now $now } else { $facts = Get-HardeningFacts }
    $results = @(Test-HardeningFacts -Facts $facts -Now $now -PatchMaxDays $PatchMaxDays -MinPasswordLength $MinPasswordLength)
    $out = Export-HardeningReport -Results $results -OutputPath $OutputPath -Now $now -IsDemo ([bool]$Demo)
    $results | Select-Object Id, Status, Severity, Check, Actual | Format-Table -AutoSize -Wrap
    Write-Host ("Pass: {0}  Fail: {1}  Unknown: {2}" -f $out.Pass, $out.Fail, $out.Unknown)
    Write-Host ("CSV : {0}" -f $out.Csv)
    Write-Host ("HTML: {0}" -f $out.Html)
}

# Run only when executed, not when dot-sourced by the tests.
if ($MyInvocation.InvocationName -ne '.') { Invoke-ServerHardeningCheck }
