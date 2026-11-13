# Windows Server Hardening Checker

A read-only PowerShell script that checks ten common hardening settings on a Windows machine and writes a CSV and a self-contained HTML report. It uses only tools built into Windows, so there is nothing to install and nothing to pay for.

A setting that cannot be read, for example because the session is not elevated, is reported as **Unknown** with the reason. It is never guessed as a Pass.

## What it checks

| Id | Check | Severity |
| --- | --- | --- |
| H01 | Windows Firewall on for Domain, Private and Public profiles | High |
| H02 | SMBv1 server disabled | High |
| H03 | RDP requires Network Level Authentication (passes if RDP is off) | High |
| H04 | Guest account disabled | Medium |
| H05 | Account lockout threshold set (not 0) | Medium |
| H06 | Minimum password length at least 14 (changeable) | Medium |
| H07 | Logon and User Account Management audited for success and failure | Medium |
| H08 | Defender real-time protection on, when Defender is the active antivirus | High |
| H09 | Automatic updates not disabled by policy | Medium |
| H10 | Newest installed hotfix within 45 days (changeable) | Medium |

## Run it

```powershell
# Try it with fictional results. Reads nothing from this machine.
.\Test-ServerHardening.ps1 -Demo

# This machine (run elevated to read every setting)
.\Test-ServerHardening.ps1 -OutputPath .\report

# Change the thresholds
.\Test-ServerHardening.ps1 -MinPasswordLength 12 -PatchMaxDays 30
```

The script only reads. It never changes the registry, policy, services or firewall.

## Test it

```powershell
.\Tests.ps1
```

The tests use mocked facts and sample command output, so they need no elevation. They cover the pass, fail and Unknown path of every check, the output parsers and the report.

## Design

- **Collection is separate from the checks.** Each group of settings is read in its own try block, so one failure cannot hide the others. The checks work on a plain object and are easy to test.
- **Unknown is a real answer.** Anything that cannot be read says why.
- **Antivirus is read carefully.** Defender counts as active only when Windows Security Center shows it switched on. If another antivirus is registered, H08 is Unknown and names it, instead of a false Fail.

## What was tested

- The checks, parsers and report: 41 self-tests on mocked data, all passing.
- Demo mode: produces the sample report in this repo.
- One real run on a non-elevated Windows 11 PC. It correctly reported H07 as Unknown (needs elevation) and H08 as Unknown (another antivirus registered).

## What was not tested

- **Windows Server.** I wrote and tested this on Windows 11. Try it on a lab server before relying on it.
- **Elevated runs.** The audit policy and SMB checks need elevation to read everything. The elevated path is covered by mocks only.
- **Non-English Windows.** Lockout and password length are read from net accounts output in English.

## Limits

- This is a small baseline, not a full benchmark. No CIS or STIG control mapping is claimed. Compare the checks with the benchmark you use [VERIFY].
- Review each result before changing anything. A Fail may be a deliberate exception.

## Files

- Test-ServerHardening.ps1: the checker
- Tests.ps1: self-test
- sample-report.html: output from -Demo (fictional data)

MIT licensed.
