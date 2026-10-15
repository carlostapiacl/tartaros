<#
.SYNOPSIS
  One-time setup of the dedicated sandbox user for the tartaros Windows
  "sandbox-user" tier. Run once, elevated; every later run is unprivileged.

.DESCRIPTION
  install   creates a local user and group, stores the user's random password
            DPAPI-encrypted (machine scope) in a registry key that the sandbox
            group cannot read, hides the account from the logon screen, denies
            it network/batch/service/remote-desktop logon, blocks its network
            traffic with firewall rules scoped to its SID, and grants it
            inheritable read on -ProfileDir (the neutral "read everything
            except denies" model; per-run denies are added by the backend).
  uninstall reverts all of the above.
  status    prints what is in place.

  Machine-scope DPAPI is not a security boundary by itself: the registry
  key's DACL is (it denies the sandbox group before granting Users read).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File sandbox-user.ps1 install -ProfileDir C:\Users\me
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('install', 'uninstall', 'status')]
    [string]$Action,
    # The profile of the person who will run tartaros: read is granted on it.
    [string]$ProfileDir,
    [string]$UserName = 'tartaros-sbx',
    [string]$GroupName = 'tartaros-sandbox-users'
)

$ErrorActionPreference = 'Stop'
$KeyPath = 'HKLM:\SOFTWARE\tartaros\SandboxUser'
$HideKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
$FwGroup = 'tartaros sandbox user'
$DenyRights = @('SeDenyNetworkLogonRight', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight', 'SeDenyRemoteInteractiveLogonRight')

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'run this elevated (an administrator PowerShell)'
    }
}

function New-Password {
    # 32 chars from a CSPRNG, with every class SAM password policy may demand.
    $alphabet = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+-=?@_'
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $p = -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
    return "Aa1!$p"
}

function Set-Rights([string]$Sid, [bool]$Add) {
    $tmp = Join-Path $env:TEMP "tartaros-rights-$PID"
    New-Item -ItemType Directory -Force $tmp | Out-Null
    try {
        secedit /export /cfg "$tmp\cur.inf" /areas USER_RIGHTS /quiet | Out-Null
        $cur = Get-Content "$tmp\cur.inf"
        $lines = foreach ($r in $DenyRights) {
            $m = $cur | Where-Object { $_ -match "^$r\s*=" } | Select-Object -First 1
            $vals = if ($m) { ($m -split '=', 2)[1].Trim() -split ',' | Where-Object { $_ } } else { @() }
            $vals = @($vals | Where-Object { $_ -ne "*$Sid" })
            if ($Add) { $vals += "*$Sid" }
            # On removal, emit the line even when empty so secedit actually clears
            # the assignment (our SID may have been its only holder). $vals already
            # dropped only our SID, so any other holders are still listed. On add
            # the list is never empty.
            if (($vals.Count -gt 0) -or (-not $Add)) { "$r = $($vals -join ',')" }
        }
        @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]') + $lines |
            Set-Content -Encoding Unicode "$tmp\new.inf"
        secedit /configure /db "$tmp\new.sdb" /cfg "$tmp\new.inf" /areas USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit /configure failed ($LASTEXITCODE)" }
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

function Install {
    Assert-Admin
    if (-not $ProfileDir) { throw '-ProfileDir is required (the profile of the person who runs tartaros)' }
    if (-not (Test-Path $ProfileDir -PathType Container)) { throw "no such directory: $ProfileDir" }
    Add-Type -AssemblyName System.Security

    $priorProfile = (Get-ItemProperty -Path $KeyPath -Name ProfileDir -ErrorAction SilentlyContinue).ProfileDir
    $existing = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if ($existing -and -not (Test-Path $KeyPath)) {
        throw "a local user '$UserName' exists that this script did not create; refusing to adopt it"
    }
    $plain = New-Password
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
    if ($existing) {
        Set-LocalUser -Name $UserName -Password $secure -PasswordNeverExpires $true
    } else {
        New-LocalUser -Name $UserName -Password $secure -PasswordNeverExpires -UserMayNotChangePassword `
            -AccountNeverExpires -Description 'tartaros sandbox (do not use interactively)' | Out-Null
    }
    $sid = (Get-LocalUser -Name $UserName).SID.Value
    if (-not (Get-LocalGroup -Name $GroupName -ErrorAction SilentlyContinue)) {
        New-LocalGroup -Name $GroupName -Description 'tartaros sandbox identities' | Out-Null
    }
    $gsid = (Get-LocalGroup -Name $GroupName).SID.Value
    foreach ($g in @($gsid, 'S-1-5-32-545')) {
        # Users (S-1-5-32-545) carries the interactive-logon right the launch needs.
        $grp = Get-LocalGroup -SID $g
        if (-not (Get-LocalGroupMember -Group $grp -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $sid })) {
            Add-LocalGroupMember -Group $grp -Member $UserName
        }
    }

    # Who installs: only this SID (plus SYSTEM/Admins) may read the key. DPAPI
    # LocalMachine can be decrypted by any local user, so the key's DACL is the
    # real boundary; granting Builtin Users read would hand every local account
    # the sandbox password (and thus a logon as the sandbox user).
    $installer = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    # Password: DPAPI machine scope, in a key only the installer and admins can read.
    $blob = [Security.Cryptography.ProtectedData]::Protect(
        [Text.Encoding]::Unicode.GetBytes($plain), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    $plain = $null
    if (-not (Test-Path $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
    $acl = New-Object Security.AccessControl.RegistrySecurity
    $acl.SetSecurityDescriptorSddlForm("O:BAD:P(D;OICI;KA;;;$gsid)(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)(A;OICI;KR;;;$installer)")
    Set-Acl -Path $KeyPath -AclObject $acl
    Set-ItemProperty -Path $KeyPath -Name User -Value $UserName
    Set-ItemProperty -Path $KeyPath -Name Sid -Value $sid
    Set-ItemProperty -Path $KeyPath -Name GroupSid -Value $gsid
    Set-ItemProperty -Path $KeyPath -Name Blob -Value $blob -Type Binary
    Set-ItemProperty -Path $KeyPath -Name ProfileDir -Value $ProfileDir
    Set-ItemProperty -Path $KeyPath -Name Installer -Value $installer

    # Off the logon screen; no network, batch, service or RDP logon.
    if (-not (Test-Path $HideKey)) { New-Item -Path $HideKey -Force | Out-Null }
    Set-ItemProperty -Path $HideKey -Name $UserName -Value 0 -Type DWord
    Set-Rights $sid $true

    # Network off for this identity: block every outbound/inbound connection it
    # makes, scoped to its SID (the rule never touches other users).
    Get-NetFirewallRule -Group $FwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $sddl = "O:LSD:(A;;CC;;;$sid)"
    New-NetFirewallRule -DisplayName "$FwGroup (out)" -Group $FwGroup -Direction Outbound -Action Block -LocalUser $sddl -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "$FwGroup (in)" -Group $FwGroup -Direction Inbound -Action Block -LocalUser $sddl -Profile Any | Out-Null

    # Read on the runner's profile: the neutral model reads everything except
    # what the policy denies; the backend adds those denies per run. Note: this
    # grant persists between runs, not only during one. If a previous install
    # pointed at a different profile, drop that grant first.
    if ($priorProfile -and ($priorProfile -ne $ProfileDir) -and (Test-Path $priorProfile)) {
        icacls $priorProfile /remove:g "*${gsid}" /C /Q | Out-Null
    }
    icacls $ProfileDir /grant "*${gsid}:(OI)(CI)(RX)" /C /Q | Out-Null

    # Create the profile now (first logon), so runs find USERPROFILE/TEMP.
    $cred = New-Object Management.Automation.PSCredential($UserName, $secure)
    $p = Start-Process -FilePath "$env:SystemRoot\System32\whoami.exe" -Credential $cred -LoadUserProfile `
        -WindowStyle Hidden -Wait -PassThru -WorkingDirectory $env:SystemRoot
    Write-Output "installed: user $UserName ($sid), group $GroupName ($gsid), profile logon exit $($p.ExitCode)"
}

function Uninstall {
    Assert-Admin
    $gsid = (Get-ItemProperty -Path $KeyPath -Name GroupSid -ErrorAction SilentlyContinue).GroupSid
    $sid = (Get-ItemProperty -Path $KeyPath -Name Sid -ErrorAction SilentlyContinue).Sid
    $prof = (Get-ItemProperty -Path $KeyPath -Name ProfileDir -ErrorAction SilentlyContinue).ProfileDir
    Get-NetFirewallRule -Group $FwGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    if ($sid) { Set-Rights $sid $false }
    if ($prof -and $gsid -and (Test-Path $prof)) { icacls $prof /remove:g "*$gsid" /C /Q | Out-Null }
    Remove-ItemProperty -Path $HideKey -Name $UserName -ErrorAction SilentlyContinue
    if ($sid) {
        $pl = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }
        if ($pl) { $pl | Remove-CimInstance }
    }
    if (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $UserName }
    if (Get-LocalGroup -Name $GroupName -ErrorAction SilentlyContinue) { Remove-LocalGroup -Name $GroupName }
    if (Test-Path $KeyPath) { Remove-Item -Path $KeyPath -Recurse -Force }
    # Drop the now-empty parent key if nothing else lives under HKLM\SOFTWARE	artaros.
    $parent = Split-Path $KeyPath -Parent
    if ((Test-Path $parent) -and -not (Get-ChildItem $parent -ErrorAction SilentlyContinue) -and -not (Get-ItemProperty $parent -ErrorAction SilentlyContinue).PSObject.Properties.Where({ $_.Name -notlike 'PS*' })) {
        Remove-Item -Path $parent -Force -ErrorAction SilentlyContinue
    }
    Write-Output 'uninstalled'
}

function Status {
    $u = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    $k = Get-ItemProperty -Path $KeyPath -ErrorAction SilentlyContinue
    [pscustomobject]@{
        User          = if ($u) { "$($u.Name) $($u.SID) enabled=$($u.Enabled)" } else { 'missing' }
        Group         = if (Get-LocalGroup -Name $GroupName -ErrorAction SilentlyContinue) { $GroupName } else { 'missing' }
        Credential    = if ($k -and $k.Blob) { "stored ($($k.Blob.Length) bytes)" } else { 'missing' }
        ProfileDir    = if ($k) { $k.ProfileDir } else { '' }
        FirewallRules = @(Get-NetFirewallRule -Group $FwGroup -ErrorAction SilentlyContinue).Count
        Hidden        = [bool](Get-ItemProperty -Path $HideKey -Name $UserName -ErrorAction SilentlyContinue)
    } | Format-List
}

switch ($Action) {
    'install' { Install }
    'uninstall' { Uninstall }
    'status' { Status }
}
