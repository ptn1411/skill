<#
native_hunt.ps1 — Native Windows Event Log threat hunt (no external tools).

Queries high-signal security events with Get-WinEvent and writes a JSON array.
Runs per-category with try/catch so a locked log (e.g. Security without admin)
does not abort the whole hunt.

Usage:
  powershell -ExecutionPolicy Bypass -File native_hunt.ps1 -Hours 24 -Max 200 -Out events.json
#>
param(
    [int]$Hours = 24,
    [int]$Max = 200,
    [string]$Out = "events.json"
)

$start = (Get-Date).AddHours(-$Hours)
$results = New-Object System.Collections.ArrayList

# Each rule: log name, event id(s), category, severity, description
$rules = @(
    @{ Log='Security';   Id=4625; Cat='auth';        Sev='medium'; Desc='Failed logon' },
    @{ Log='Security';   Id=4624; Cat='auth';        Sev='low';    Desc='Successful logon (review type 3/10)' },
    @{ Log='Security';   Id=4720; Cat='account';     Sev='high';   Desc='User account created' },
    @{ Log='Security';   Id=4726; Cat='account';     Sev='medium'; Desc='User account deleted' },
    @{ Log='Security';   Id=4732; Cat='account';     Sev='high';   Desc='Member added to local group' },
    @{ Log='Security';   Id=4728; Cat='account';     Sev='high';   Desc='Member added to global group' },
    @{ Log='Security';   Id=4672; Cat='privilege';   Sev='low';    Desc='Special privileges assigned' },
    @{ Log='Security';   Id=1102; Cat='defense-evasion'; Sev='high'; Desc='Audit log cleared' },
    @{ Log='Security';   Id=4698; Cat='persistence'; Sev='high';   Desc='Scheduled task created' },
    @{ Log='Security';   Id=4688; Cat='execution';   Sev='low';    Desc='New process created' },
    @{ Log='System';     Id=7045; Cat='persistence'; Sev='high';   Desc='New service installed' },
    @{ Log='System';     Id=7030; Cat='persistence'; Sev='medium'; Desc='Service marked interactive' },
    @{ Log='Microsoft-Windows-PowerShell/Operational'; Id=4104; Cat='execution'; Sev='medium'; Desc='PowerShell script block' },
    @{ Log='Microsoft-Windows-Sysmon/Operational'; Id=1;  Cat='execution'; Sev='low';    Desc='Sysmon process create' },
    @{ Log='Microsoft-Windows-Sysmon/Operational'; Id=3;  Cat='network';   Sev='low';    Desc='Sysmon network connection' },
    @{ Log='Microsoft-Windows-Sysmon/Operational'; Id=11; Cat='file';      Sev='low';    Desc='Sysmon file create' }
)

foreach ($r in $rules) {
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName=$r.Log; Id=$r.Id; StartTime=$start } -MaxEvents $Max -ErrorAction Stop
        foreach ($e in $ev) {
            $msg = ($e.Message -split "`n")[0]
            if ($msg.Length -gt 240) { $msg = $msg.Substring(0,240) }
            [void]$results.Add([PSCustomObject]@{
                time        = $e.TimeCreated.ToString('s')
                log         = $r.Log
                id          = $r.Id
                category    = $r.Cat
                severity    = $r.Sev
                description = $r.Desc
                computer    = $e.MachineName
                message     = $msg.Trim()
            })
        }
    } catch {
        # Log/permission unavailable — record as an info note, keep going.
        if ($_.Exception.Message -notmatch 'No events were found') {
            [void]$results.Add([PSCustomObject]@{
                time        = (Get-Date).ToString('s')
                log         = $r.Log
                id          = $r.Id
                category    = 'collection'
                severity    = 'info'
                description = "Could not read log ($($r.Desc))"
                computer    = $env:COMPUTERNAME
                message     = $_.Exception.Message
            })
        }
    }
}

$results | ConvertTo-Json -Depth 4 | Out-File -FilePath $Out -Encoding utf8
Write-Host "[+] Wrote $($results.Count) event(s) to $Out"
