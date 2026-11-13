<#
.SYNOPSIS
    Self-test for Test-ServerHardening.ps1. Uses mocked facts and sample command output.
    Needs no elevation and no extra modules. Run: .\Tests.ps1
#>
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Test-ServerHardening.ps1')

$script:pass = 0
$script:fail = 0
function Assert-True {
    param([bool]$Condition, [string]$Name)
    if ($Condition) { $script:pass++; Write-Host ("  PASS  {0}" -f $Name) }
    else { $script:fail++; Write-Host ("  FAIL  {0}" -f $Name) -ForegroundColor Red }
}

$now = [datetime]'2026-11-09 12:00'

# A facts object where every check passes. Tests override one fact at a time.
function New-GoodFacts {
    [pscustomobject]@{
        Firewall          = @(
            [pscustomobject]@{ Name = 'Domain'; Enabled = $true }
            [pscustomobject]@{ Name = 'Private'; Enabled = $true }
            [pscustomobject]@{ Name = 'Public'; Enabled = $true }
        )
        Smb1Enabled       = $false
        RdpEnabled        = $true
        RdpNla            = $true
        GuestEnabled      = $false
        LockoutThreshold  = 5
        MinPasswordLength = 14
        AuditLogon        = 'Success and Failure'
        AuditAccountMgmt  = 'Success and Failure'
        DefenderActive    = $true
        DefenderRealTime  = $true
        AntivirusNames    = 'Windows Defender'
        NoAutoUpdate      = $false
        LastHotfix        = $now.AddDays(-10)
        Unavailable       = @{}
    }
}
function Get-Result {
    param($Facts, [string]$Id)
    $all = @(Test-HardeningFacts -Facts $Facts -Now $now -PatchMaxDays 45 -MinPasswordLength 14)
    @($all | Where-Object { $_.Id -eq $Id })[0]
}
function Set-Unknown {
    param($Facts, [string]$Key)
    $Facts.Unavailable[$Key] = 'Could not read: test reason'
    $Facts
}

Write-Host 'Baseline'
$good = New-GoodFacts
$all = @(Test-HardeningFacts -Facts $good -Now $now -PatchMaxDays 45 -MinPasswordLength 14)
Assert-True ($all.Count -eq 10) 'ten checks are returned'
Assert-True (@($all | Where-Object { $_.Status -ne 'Pass' }).Count -eq 0) 'good facts pass every check'

Write-Host 'H01 firewall'
$f = New-GoodFacts; $f.Firewall[2].Enabled = $false
$x = Get-Result $f 'H01'
Assert-True ($x.Status -eq 'Fail' -and $x.Actual -like '*Public*') 'a disabled profile fails and is named'
Assert-True ((Get-Result (Set-Unknown (New-GoodFacts) 'Firewall') 'H01').Status -eq 'Unknown') 'unreadable firewall is Unknown'

Write-Host 'H02 SMBv1'
$f = New-GoodFacts; $f.Smb1Enabled = $true
Assert-True ((Get-Result $f 'H02').Status -eq 'Fail') 'SMBv1 enabled fails'
Assert-True ((Get-Result (Set-Unknown (New-GoodFacts) 'Smb1') 'H02').Status -eq 'Unknown') 'unreadable SMBv1 is Unknown'

Write-Host 'H03 RDP NLA'
$f = New-GoodFacts; $f.RdpNla = $false
Assert-True ((Get-Result $f 'H03').Status -eq 'Fail') 'RDP on without NLA fails'
$f = New-GoodFacts; $f.RdpEnabled = $false; $f.RdpNla = $false
Assert-True ((Get-Result $f 'H03').Status -eq 'Pass') 'RDP off passes'
Assert-True ((Get-Result (Set-Unknown (New-GoodFacts) 'Rdp') 'H03').Status -eq 'Unknown') 'unreadable RDP is Unknown'

Write-Host 'H04 guest'
$f = New-GoodFacts; $f.GuestEnabled = $true
Assert-True ((Get-Result $f 'H04').Status -eq 'Fail') 'enabled Guest fails'
Assert-True ((Get-Result (Set-Unknown (New-GoodFacts) 'Guest') 'H04').Status -eq 'Unknown') 'unreadable Guest is Unknown'

Write-Host 'H05 lockout'
$f = New-GoodFacts; $f.LockoutThreshold = 0
Assert-True ((Get-Result $f 'H05').Status -eq 'Fail') 'lockout never fails'
Assert-True ((Get-Result (Set-Unknown (New-GoodFacts) 'Lockout') 'H05').Status -eq 'Unknown') 'unreadable lockout is Unknown'

Write-Host 'H06 password length'
$f = New-GoodFacts; $f.MinPasswordLength = 12
Assert-True ((Get-Result $f 'H06').Status -eq 'Fail') 'length 12 fails against 14'
$f = New-GoodFacts; $f.MinPasswordLength = 20
Assert-True ((Get-Result $f 'H06').Status -eq 'Pass') 'length 20 passes'
Assert-True ((Get-Result (Set-Unknown (New-GoodFacts) 'PasswordLength') 'H06').Status -eq 'Unknown') 'unreadable length is Unknown'

Write-Host 'H07 audit policy'
$f = New-GoodFacts; $f.AuditAccountMgmt = 'Success'
Assert-True ((Get-Result $f 'H07').Status -eq 'Fail') 'success-only account management fails'
$f = New-GoodFacts; $f.AuditLogon = 'No Auditing'
Assert-True ((Get-Result $f 'H07').Status -eq 'Fail') 'no logon auditing fails'
Assert-True ((Get-Result (Set-Unknown (New-GoodFacts) 'Audit') 'H07').Status -eq 'Unknown') 'unreadable audit policy is Unknown'

Write-Host 'H08 Defender'
$f = New-GoodFacts; $f.DefenderRealTime = $false
Assert-True ((Get-Result $f 'H08').Status -eq 'Fail') 'real-time off fails'
$f = New-GoodFacts; $f.DefenderActive = $false; $f.DefenderRealTime = $false; $f.AntivirusNames = 'Contoso AV'
$x = Get-Result $f 'H08'
Assert-True ($x.Status -eq 'Unknown') 'Defender not active is Unknown, never a guessed pass or fail'
Assert-True ($x.Actual -like '*Contoso AV*') 'the registered antivirus is named in the reason'
Assert-True ((Get-Result (Set-Unknown (New-GoodFacts) 'Defender') 'H08').Status -eq 'Unknown') 'unreadable Defender is Unknown'

Write-Host 'H09 automatic updates'
$f = New-GoodFacts; $f.NoAutoUpdate = $true
Assert-True ((Get-Result $f 'H09').Status -eq 'Fail') 'updates disabled by policy fails'
Assert-True ((Get-Result (Set-Unknown (New-GoodFacts) 'AutoUpdate') 'H09').Status -eq 'Unknown') 'unreadable update policy is Unknown'

Write-Host 'H10 patch age'
$f = New-GoodFacts; $f.LastHotfix = $now.AddDays(-100)
Assert-True ((Get-Result $f 'H10').Status -eq 'Fail') 'hotfix 100 days old fails'
$f = New-GoodFacts; $f.LastHotfix = $now.AddDays(-45)
Assert-True ((Get-Result $f 'H10').Status -eq 'Pass') 'hotfix exactly 45 days old passes'
$f = New-GoodFacts; $f.LastHotfix = $null
Assert-True ((Get-Result $f 'H10').Status -eq 'Unknown') 'no hotfix date is Unknown'
Assert-True ((Get-Result (Set-Unknown (New-GoodFacts) 'Hotfix') 'H10').Status -eq 'Unknown') 'unreadable hotfix list is Unknown'

Write-Host 'Parsers'
$net = @('Force user logoff how long after time expires?:       Never', 'Minimum password age (days):                       1', 'Minimum password length:                           14', 'Lockout threshold:                                  Never', 'The command completed successfully.')
$p = ConvertFrom-NetAccounts -Lines $net
Assert-True ($p.MinPasswordLength -eq 14) 'net accounts: password length is parsed'
Assert-True ($p.LockoutThreshold -eq 0) 'net accounts: Never becomes 0'
$net2 = @('Lockout threshold:                                  5')
Assert-True ((ConvertFrom-NetAccounts -Lines $net2).LockoutThreshold -eq 5) 'net accounts: numeric lockout is parsed'
$ap = @('System audit policy', 'Category/Subcategory                      Setting', 'Logon/Logoff', '  Logon                                   Success and Failure')
Assert-True ((ConvertFrom-AuditPolLine -Lines $ap -Subcategory 'Logon') -eq 'Success and Failure') 'auditpol: setting is parsed'
Assert-True ($null -eq (ConvertFrom-AuditPolLine -Lines @('Error 0x00000522 occurred:', 'A required privilege is not held by the client.') -Subcategory 'Logon')) 'auditpol: an error text returns nothing'
Assert-True ((Test-AvProductOn -ProductState 397568) -eq $true) 'productState 0x061100 (Defender on) is on'
Assert-True ((Test-AvProductOn -ProductState 393472) -eq $false) 'productState 0x060100 (Defender off) is off'
$er = New-Object System.Management.Automation.ErrorRecord ((New-Object System.Exception 'A required privilege is not held by the client.'), 'id', 'NotSpecified', $null)
$lines = @(ConvertTo-OutputLines @('plain line', $er))
Assert-True ($lines[0] -eq 'plain line' -and $lines[1] -like 'A required privilege*') 'error records become their message, not the type name'

Write-Host 'Report'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('hard-test-' + [guid]::NewGuid().ToString('N'))
# Note: the variable must not be called $demo, which is the script's typed -Demo switch.
$demoResults = @(Test-HardeningFacts -Facts (Get-DemoFacts -Now $now) -Now $now -PatchMaxDays 45 -MinPasswordLength 14)
$r = Export-HardeningReport -Results $demoResults -OutputPath $tmp -Now $now -IsDemo $true
Assert-True ((Test-Path $r.Csv) -and (Test-Path $r.Html)) 'CSV and HTML are written'
Assert-True ((Get-Content $r.Html -Raw) -match 'fictional demo data') 'demo report is labelled as fictional'
Assert-True ($r.Pass -gt 0 -and $r.Fail -gt 0 -and $r.Unknown -gt 0) 'demo data shows pass, fail and unknown'
Assert-True (($r.Pass + $r.Fail + $r.Unknown) -eq 10) 'counts add up to ten'
Remove-Item $tmp -Recurse -Force

Write-Host ''
Write-Host ("{0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
