# Calico-Windows node bootstrap. Rendered by calico-windows-up.sh (@@ placeholders
# substituted) onto the AUTOUNATTEND CD; run once at first logon by autounattend.xml.
# Steps mirror the official guide:
#   https://docs.tigera.io/calico/latest/getting-started/kubernetes/windows-calico/operator
#
# Reboot-resilient: installing the "Containers" Windows feature requires a reboot
# before containerd can run, so the script runs in two phases across a reboot.
# autounattend launches phase 0 once from the CD; because autologon is one-shot,
# a SYSTEM scheduled task (not a logon RunOnce) re-launches C:\bootstrap.ps1 at
# the next startup for phase 1. A phase marker file drives which half runs.
$ErrorActionPreference = 'Stop'

# Persist a copy on C: so the resume task has a stable path (the CD letter can
# change across reboots, and the CD may not be first to mount).
$self = 'C:\bootstrap.ps1'
if ($PSCommandPath -and $PSCommandPath -ne $self) { Copy-Item -LiteralPath $PSCommandPath -Destination $self -Force }
Start-Transcript -Path C:\bootstrap.log -Append | Out-Null

$k8sVersion   = '@@K8S_VERSION@@'
$staticIP     = '@@STATIC_IP@@'
$prefixLen    = @@PREFIX@@
$gateway      = '@@GATEWAY@@'
$mtu          = @@MTU@@
$joinCommand  = '@@JOIN_COMMAND@@'
$cpHost       = '@@CP_HOST@@'
$cpIP         = '@@CP_IP@@'
$containerdVersion = '2.2.0'

$phaseFile = 'C:\bootstrap-phase.txt'
$phase = if (Test-Path $phaseFile) { [int](Get-Content $phaseFile) } else { 0 }
$taskName = 'calico-bootstrap-resume'
Write-Host "=== Calico-Windows bootstrap: phase=$phase k8s=$k8sVersion ip=$staticIP/$prefixLen ==="

function Set-Phase($p) { Set-Content -Path $phaseFile -Value "$p" }

function Register-Resume {
  $a = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File $self"
  $t = New-ScheduledTaskTrigger -AtStartup
  $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
  Register-ScheduledTask -TaskName $taskName -Action $a -Trigger $t -Principal $p -Force | Out-Null
}
function Unregister-Resume { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }

# Static IP on the docker "kind" bridge (no DHCP there) + DNS, then wait for the
# resolver to actually work — the virtio NIC was just re-initialized by the
# guest-tools install, so an immediate download fails with "name not resolved".
# Idempotent: safe to re-run in phase 1 (the config persists across reboots).
function Set-Networking {
  $if = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1
  if (-not $if) { $if = Get-NetAdapter -Physical | Select-Object -First 1 }
  Write-Host "Configuring $($if.Name): $staticIP/$prefixLen gw=$gateway mtu=$mtu"
  Get-NetIPAddress -InterfaceIndex $if.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
  Remove-NetRoute -InterfaceIndex $if.ifIndex -Confirm:$false -ErrorAction SilentlyContinue
  New-NetIPAddress -InterfaceIndex $if.ifIndex -IPAddress $staticIP `
    -PrefixLength $prefixLen -DefaultGateway $gateway -ErrorAction SilentlyContinue | Out-Null
  Set-DnsClientServerAddress -InterfaceIndex $if.ifIndex -ServerAddresses '8.8.8.8','1.1.1.1'
  Clear-DnsClientCache
  netsh interface ipv4 set subinterface "$($if.ifIndex)" mtu=$mtu store=persistent | Out-Null
  # The join, kubeadm-config, and the generated kubelet kubeconfig all address
  # the control-plane by hostname; the VM's DNS (public resolvers) can't resolve
  # it, so map it to the control-plane IP in the hosts file. Idempotent.
  $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
  $line = "$cpIP $cpHost"
  if (-not (Select-String -Path $hosts -SimpleMatch $line -Quiet)) { Add-Content -Path $hosts -Value "`n$line" }
  Write-Host "Waiting for DNS to come up..."
  for ($i=0; $i -lt 30; $i++) {
    if (Resolve-DnsName raw.githubusercontent.com -ErrorAction SilentlyContinue) { break }
    Start-Sleep 5
  }
}

# Retry wrapper: transient DNS/network blips shouldn't kill the whole bootstrap.
# The sig-windows scripts use `tar -xvf`; tar's verbose per-file list goes to
# stderr, which a non-interactive PowerShell host (scheduled task / redirected)
# turns into a fatal NativeCommandError under ErrorActionPreference=Stop. Strip
# the -v so tar is silent and the scripts don't self-abort mid-extract.
function Fetch($url, $out) {
  for ($i=1; $i -le 5; $i++) {
    try {
      Invoke-WebRequest $url -OutFile $out -UseBasicParsing
      if ($out -like '*.ps1') { (Get-Content $out) -replace '-xvf','-xf' | Set-Content $out }
      return
    }
    catch { Write-Host "fetch $url failed (try $i): $_"; Start-Sleep 10 }
  }
  throw "giving up on $url after 5 tries"
}

if ($phase -eq 0) {
  # --- 1. virtio guest tools (all drivers + qemu-ga) -----------------------
  $virtio = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=5" |
    ForEach-Object { $_.DeviceID } |
    Where-Object { Test-Path (Join-Path $_ 'virtio-win-guest-tools.exe') } |
    Select-Object -First 1
  if ($virtio) {
    Write-Host "Installing virtio guest tools from $virtio"
    Start-Process (Join-Path $virtio 'virtio-win-guest-tools.exe') `
      -ArgumentList '/install','/quiet','/norestart' -Wait
  } else {
    Write-Host "WARNING: virtio guest-tools CD not found; assuming drivers already present"
  }

  # --- 2. Static IP + DNS --------------------------------------------------
  Set-Networking

  # --- 3. containerd (installs the 'Containers' feature -> needs a reboot) --
  Write-Host "Installing containerd $containerdVersion"
  Fetch https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/hostprocess/Install-Containerd.ps1 C:\Install-Containerd.ps1
  & C:\Install-Containerd.ps1 -ContainerDVersion $containerdVersion -skipHypervisorSupportCheck `
    -CNIConfigPath "c:/etc/cni/net.d" -CNIBinPath "c:/opt/cni/bin"

  Register-Resume
  Set-Phase 1
  Write-Host "=== Rebooting to activate the Containers feature (phase 1 resumes via scheduled task) ==="
  Stop-Transcript | Out-Null
  Restart-Computer -Force
  return
}

# --- Phase 1 (post-reboot, runs as SYSTEM via the scheduled task) ------------
Set-Networking

Write-Host "Starting containerd"
Start-Service containerd -ErrorAction SilentlyContinue
if (-not (Get-Service containerd -ErrorAction SilentlyContinue) -or (Get-Service containerd).Status -ne 'Running') {
  # Feature is active now; re-run the installer to register + start the service.
  & C:\Install-Containerd.ps1 -ContainerDVersion $containerdVersion -skipHypervisorSupportCheck `
    -CNIConfigPath "c:/etc/cni/net.d" -CNIBinPath "c:/opt/cni/bin"
  Start-Service containerd -ErrorAction SilentlyContinue
}

# --- 4. kubelet + node prep --------------------------------------------------
Write-Host "Preparing node (kubelet $k8sVersion)"
Fetch https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/hostprocess/PrepareNode.ps1 C:\PrepareNode.ps1
& C:\PrepareNode.ps1 -KubernetesVersion $k8sVersion

# --- 5. Join the cluster -----------------------------------------------------
# The token command from `kubeadm token create` starts with "kubeadm join ...";
# on Windows we invoke the kubelet-side binary and containerd's npipe socket.
$join = $joinCommand -replace '^kubeadm join', 'c:\k\kubeadm.exe join'
if ($join -notmatch 'cri-socket') { $join += ' --cri-socket "npipe:////./pipe/containerd-containerd"' }
Write-Host "Joining: $join"
cmd.exe /c $join

Unregister-Resume
Set-Phase 2
Write-Host "=== Bootstrap complete; node should register shortly ==="
Stop-Transcript | Out-Null
