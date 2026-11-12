# Lets ONLY your Ubuntu laptop reach Guardian's port. Run in PowerShell AS ADMINISTRATOR.
#     powershell -ExecutionPolicy Bypass -File scripts\open_firewall_windows.ps1 -UbuntuIp 192.168.1.9
param(
    [Parameter(Mandatory = $true)][string]$UbuntuIp,
    [int]$Port = 8000
)
$name = "Shiro Guardian API (Nemesis only)"
Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol TCP -LocalPort $Port `
    -RemoteAddress $UbuntuIp -Action Allow -Profile Any | Out-Null
Write-Host "OK: inbound TCP $Port is allowed ONLY from $UbuntuIp."
Write-Host "To remove the rule later:  Remove-NetFirewallRule -DisplayName '$name'"
