# Remote inventory collector for Windows (PowerShell 5.1+, no Python). Piped over ssh to powershell (see lib.rs);
# run as an administrator for full results. System info is emitted as `json <key>` sections already in snapshot
# shape; docker/tailscale output is raw. Parsed by src/collect.rs.
# Manual run: Get-Content src-tauri\collectors\windows.ps1 -Raw | ssh host "powershell -NoProfile -Command -"
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

function Sec($name) { "`n@@infra@@ $name" }
function J($key, $value) { Sec "json $key"; ConvertTo-Json -InputObject $value -Compress -Depth 6 }
function Has($cmd) { [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }
# section with a native command's output, only if it succeeds
function Out($name, [scriptblock]$cmd) { $o = & $cmd 2>$null; if ($LASTEXITCODE -eq 0) { Sec $name; $o } }

Sec platform; 'windows'
$os = Get-CimInstance Win32_OperatingSystem
$cpus = @(Get-CimInstance Win32_Processor)
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$cores = [int]($cpus | Measure-Object NumberOfLogicalProcessors -Sum).Sum
J collected_at ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
J hostname ([Net.Dns]::GetHostName())
J os ("$($os.Caption) $($cv.DisplayVersion)".Trim())
J kernel ("$($os.Version).$($cv.UBR)")
J uptime ([math]::Round(((Get-Date) - $os.LastBootUpTime).TotalSeconds))
# no load average on Windows: busy cores from current CPU utilisation
J load @([math]::Round(($cpus | Measure-Object LoadPercentage -Average).Average / 100 * $cores, 2))
J cpu ([ordered]@{ model = "$($cpus[0].Name)".Trim(); count = $cores })
J memory ([ordered]@{
    total = [int64]$os.TotalVisibleMemorySize * 1024
    available = [int64]$os.FreePhysicalMemory * 1024
    swap_total = [int64](Get-CimInstance Win32_PageFileUsage | Measure-Object AllocatedBaseSize -Sum).Sum * 1MB
  })

J disks @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    [ordered]@{ mount = $_.DeviceID; fstype = $_.FileSystem; size = [int64]$_.Size; used = [int64]($_.Size - $_.FreeSpace) }
  })

$ips = @(Get-NetIPAddress | Where-Object { $_.IPAddress -notmatch '^(fe80|169\.254\.|127\.|::1$)' })
J addresses @(Get-NetAdapter | ForEach-Object {
    $i = $_.ifIndex
    [ordered]@{
      iface = $_.Name
      state = if ("$($_.Status)" -eq 'Up') { 'UP' } else { 'DOWN' }
      addrs = @($ips | Where-Object { $_.InterfaceIndex -eq $i } | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
    }
  })

$procs = @{}
Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
$tcp = @(Get-NetTCPConnection -State Listen | ForEach-Object {
    [ordered]@{ proto = 'tcp'; addr = $_.LocalAddress; port = [int]$_.LocalPort; process = "$($procs[[int]$_.OwningProcess])" }
  })
# skip ephemeral client sockets (dynamic port range)
$udp = @(Get-NetUDPEndpoint | Where-Object { $_.LocalPort -lt 49152 } | ForEach-Object {
    [ordered]@{ proto = 'udp'; addr = $_.LocalAddress; port = [int]$_.LocalPort; process = "$($procs[[int]$_.OwningProcess])" }
  })
J listeners @($tcp + $udp)

# per-user service instances get a random suffix per logon (e.g. CDPUserSvc_1a2b3c); strip it
J services @(Get-Service | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name -replace '_[0-9a-f]{4,8}$', '' } | Sort-Object -Unique)

$fw = @(Get-NetFirewallProfile)
if ($fw.Count) {
  J firewall ([ordered]@{
      kind = 'windows'
      active = [bool]($fw | Where-Object { "$($_.Enabled)" -eq 'True' })
      rules = @($fw | ForEach-Object { "$($_.Name): $(if ("$($_.Enabled)" -eq 'True') { 'on' } else { 'off' })" })
    })
}

$pending = $null; $security = $null
try {
  # offline search = results of Windows Update's last scan; fast, no network
  $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
  $searcher.Online = $false
  $found = @($searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates)
  $pending = $found.Count
  $security = @($found | Where-Object { $_.Categories | Where-Object { $_.Name -eq 'Security Updates' } }).Count
} catch {}
$reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
  (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
J updates ([ordered]@{ pending = $pending; security = $security; reboot_required = $reboot })

J smart @(Get-PhysicalDisk | ForEach-Object {
    $c = $_ | Get-StorageReliabilityCounter
    [ordered]@{
      device = "disk$($_.DeviceId)"
      model = "$($_.FriendlyName)".Trim()
      passed = switch ("$($_.HealthStatus)") { 'Healthy' { $true } 'Unhealthy' { $false } default { $null } }
      power_on_hours = $c.PowerOnHours
      temp = if ($c.Temperature) { $c.Temperature } else { $null }
    }
  })

if (Has docker) {
  Sec docker
  Out docker_version { docker version --format '{{.Server.Version}}' }
  Out docker_ps { docker ps -a --format '{{json .}}' }
  Out docker_compose { docker compose ls -a --format json }
  Out docker_volumes { docker volume ls -q }
}

if (Has tailscale) {
  Sec tailscale
  Out tailscale_status { tailscale status --json }
  Out tailscale_serve { tailscale serve status --json }
  Out tailscale_prefs { tailscale debug prefs }
}
