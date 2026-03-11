<#
.SYNOPSIS
    Collects Microsoft Secure Score data via MS Graph API.

.DESCRIPTION
    Authenticates to Microsoft Graph and exports Secure Score data as JSON
    for import into the M365 Security Posture tool.

.PARAMETER TenantId
    The Azure AD tenant ID.

.PARAMETER ClientId
    The app registration client ID.

.PARAMETER ClientSecret
    The app registration client secret (for app-only auth).

.PARAMETER Interactive
    Use interactive device code authentication.

.PARAMETER OutputPath
    Path for the JSON output file.

.EXAMPLE
    .\Collect-SecureScore.ps1 -TenantId "xxx" -ClientId "yyy" -ClientSecret "zzz" -OutputPath ".\secure_score.json"

.EXAMPLE
    .\Collect-SecureScore.ps1 -TenantId "xxx" -Interactive -OutputPath ".\secure_score.json"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [switch]$Interactive,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\secure_score_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
)

$ErrorActionPreference = "Stop"

function Get-GraphToken {
    if ($Interactive) {
        # Check for Microsoft.Graph module
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
            Write-Host "Installing Microsoft.Graph.Authentication module..." -ForegroundColor Yellow
            Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
        }
        Import-Module Microsoft.Graph.Authentication
        Connect-MgGraph -TenantId $TenantId -Scopes "SecurityEvents.Read.All"
        return $null  # Token is managed by the SDK
    }
    else {
        if (-not $ClientId -or -not $ClientSecret) {
            throw "ClientId and ClientSecret are required for app-only authentication."
        }

        $body = @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = "https://graph.microsoft.com/.default"
        }

        $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $body
        return $tokenResponse.access_token
    }
}

function Invoke-GraphRequest {
    param([string]$Endpoint, [string]$Token)

    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }

    if ($Interactive) {
        return Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/$Endpoint" -Method GET
    }
    else {
        return Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/$Endpoint" -Headers $headers -Method GET
    }
}

try {
    Write-Host "Authenticating..." -ForegroundColor Cyan
    $token = Get-GraphToken

    Write-Host "Fetching Secure Scores..." -ForegroundColor Cyan
    $secureScores = Invoke-GraphRequest -Endpoint "security/secureScores?`$top=1" -Token $token

    Write-Host "Fetching Secure Score Control Profiles..." -ForegroundColor Cyan
    $profiles = $null
    try {
        $profiles = Invoke-GraphRequest -Endpoint "security/secureScoreControlProfiles" -Token $token
    }
    catch {
        Write-Warning "Could not fetch control profiles: $_"
    }

    $output = @{
        secureScores    = $secureScores
        controlProfiles = $profiles
        exportDate      = (Get-Date -Format "o")
        tenantId        = $TenantId
    }

    $output | ConvertTo-Json -Depth 20 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Secure Score data saved to: $OutputPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "Import into the posture tool with:" -ForegroundColor Yellow
    Write-Host "  python -m m365_posture import secure-score `"$OutputPath`"" -ForegroundColor White
}
catch {
    Write-Error "Failed: $_"
    exit 1
}
finally {
    if ($Interactive) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}
