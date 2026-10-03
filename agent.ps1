$ServerUrl = "http://127.0.0.1:5000/api/report"

Write-Host "AssetWatch: collecting system data..."

$os = Get-CimInstance -ClassName Win32_OperatingSystem

$hotfix = Get-HotFix |
    Where-Object { $_.InstalledOn } |
    Sort-Object InstalledOn -Descending |
    Select-Object -First 1

$lastHotfix = if ($hotfix) {
    ([DateTime]$hotfix.InstalledOn).ToUniversalTime().ToString("o")
} else {
    $null
}

$firewallProfiles = @{}
Get-NetFirewallProfile | ForEach-Object {
    $firewallProfiles[$_.Name] = [bool]$_.Enabled
}

try {
    $smb = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    $smbv1 = [string]$smb.State
} catch {
    $smbv1 = "Unknown"
}

try {
    $admins = @(
        Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop |
        Select-Object -ExpandProperty Name
    )
} catch {
    $admins = @("Unable to query")
}

$ports = @(
    Get-NetTCPConnection -State Listen |
    Select-Object -ExpandProperty LocalPort |
    Sort-Object -Unique
)

$payload = [ordered]@{
    hostname          = $env:COMPUTERNAME
    os_name           = $os.Caption
    os_version        = $os.Version
    last_hotfix       = $lastHotfix
    firewall_profiles = $firewallProfiles
    smbv1              = $smbv1
    local_admins       = $admins
    listening_ports    = $ports
}

$json = $payload | ConvertTo-Json -Depth 5

try {
    $response = Invoke-RestMethod `
        -Uri $ServerUrl `
        -Method Post `
        -ContentType "application/json" `
        -Body $json

    $response | ConvertTo-Json -Depth 5
} catch {
    Write-Error "Could not send report to AssetWatch: $($_.Exception.Message)"
}
