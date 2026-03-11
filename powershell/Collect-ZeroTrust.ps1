<#
.SYNOPSIS
    Runs Zero Trust Assessment and exports results.

.DESCRIPTION
    Installs/imports the Maester/ZeroTrustAssessment module, runs the assessment,
    and exports results for import into the posture tool.

.PARAMETER TenantId
    The Azure AD tenant ID.

.PARAMETER OutputPath
    Path for the JSON output file.

.EXAMPLE
    .\Collect-ZeroTrust.ps1 -TenantId "xxx" -OutputPath ".\zt_assessment.json"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\zerotrust_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
)

$ErrorActionPreference = "Stop"

try {
    # Try ZeroTrustAssessment module first
    $ztModule = Get-Module -ListAvailable -Name ZeroTrustAssessment
    if (-not $ztModule) {
        Write-Host "ZeroTrustAssessment module not found. Trying to install..." -ForegroundColor Yellow
        try {
            Install-Module ZeroTrustAssessment -Scope CurrentUser -Force
            $ztModule = Get-Module -ListAvailable -Name ZeroTrustAssessment
        }
        catch {
            Write-Warning "Could not install ZeroTrustAssessment. Trying Maester as alternative..."
        }
    }

    if ($ztModule) {
        Import-Module ZeroTrustAssessment
        Write-Host "Running Zero Trust Assessment..." -ForegroundColor Cyan

        # Connect to MS Graph
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
            Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
        }
        Import-Module Microsoft.Graph.Authentication
        Connect-MgGraph -TenantId $TenantId -Scopes "Directory.Read.All", "Policy.Read.All", "SecurityEvents.Read.All"

        # Run assessment
        $results = Invoke-ZeroTrustAssessment

        # Export to JSON
        $results | ConvertTo-Json -Depth 20 | Out-File -FilePath $OutputPath -Encoding UTF8
    }
    else {
        # Fallback: Use Maester
        if (-not (Get-Module -ListAvailable -Name Maester)) {
            Write-Host "Installing Maester module..." -ForegroundColor Yellow
            Install-Module Maester -Scope CurrentUser -Force
        }
        Import-Module Maester

        Write-Host "Running Maester Zero Trust Assessment..." -ForegroundColor Cyan
        Connect-Maester -TenantId $TenantId

        $results = Invoke-Maester -OutputFolder (Split-Path $OutputPath)
        if (Test-Path $results) {
            Copy-Item $results $OutputPath
        }
    }

    Write-Host ""
    Write-Host "Zero Trust Assessment complete!" -ForegroundColor Green
    Write-Host "Results: $OutputPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "Import into the posture tool with:" -ForegroundColor Yellow
    Write-Host "  python -m m365_posture import zero-trust `"$OutputPath`"" -ForegroundColor White
}
catch {
    Write-Error "Failed: $_"
    exit 1
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
