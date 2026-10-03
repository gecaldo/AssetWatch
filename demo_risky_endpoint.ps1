$ServerUrl = "http://127.0.0.1:5000/api/report"

$payload = @{
    hostname = "DEMO-RISKY-PC"
    os_name = "Windows 11 Pro"
    os_version = "10.0"
    last_hotfix = "2026-01-01T00:00:00+00:00"

    firewall_profiles = @{
        Domain = $true
        Private = $true
        Public = $false
    }

    smbv1 = "Enabled"
    local_admins = @("Administrator", "test-admin", "helpdesk-admin")
    listening_ports = @(135, 445, 3389, 9999)
}

Invoke-RestMethod `
    -Uri $ServerUrl `
    -Method Post `
    -ContentType "application/json" `
    -Body ($payload | ConvertTo-Json -Depth 5)
