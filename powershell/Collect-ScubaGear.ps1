<#
.SYNOPSIS
    Runs ScubaGear assessment and exports results for the M365 Security Posture tool.

.DESCRIPTION
    Installs/imports ScubaGear, runs the assessment against specified M365 products,
    and converts output to a format consumable by the posture tool.

.PARAMETER TenantId
    The Azure AD tenant ID.

.PARAMETER Products
    Comma-separated list of products to assess. Default: all.
    Options: aad, exo, defender, sharepoint, onedrive, teams, powerplatform

.PARAMETER OutputPath
    Directory for ScubaGear output.

.EXAMPLE
    .\Collect-ScubaGear.ps1 -TenantId "xxx" -OutputPath ".\scuba_output"

.EXAMPLE
    .\Collect-ScubaGear.ps1 -TenantId "xxx" -Products "aad,exo,teams"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$Products = "aad,exo,defender,sharepoint,onedrive,teams,powerplatform",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\scuba_output_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

$ErrorActionPreference = "Stop"

try {
    # Check for ScubaGear
    if (-not (Get-Module -ListAvailable -Name ScubaGear)) {
        Write-Host "Installing ScubaGear module..." -ForegroundColor Yellow
        Install-Module ScubaGear -Scope CurrentUser -Force
    }
    Import-Module ScubaGear

    $productList = $Products -split "," | ForEach-Object { $_.Trim() }

    Write-Host "Running ScubaGear assessment for products: $($productList -join ', ')" -ForegroundColor Cyan
    Write-Host "Tenant: $TenantId" -ForegroundColor Cyan

    # Run ScubaGear
    $params = @{
        M365Environment = "commercial"
        OPAPath         = $OutputPath
        ProductNames    = $productList
    }

    Invoke-SCuBA @params

    # Find the JSON results
    $jsonFiles = Get-ChildItem -Path $OutputPath -Filter "*.json" -Recurse | Where-Object { $_.Name -like "*Results*" -or $_.Name -like "*ScubaResults*" }

    if ($jsonFiles) {
        $latestJson = $jsonFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        Write-Host ""
        Write-Host "ScubaGear assessment complete!" -ForegroundColor Green
        Write-Host "Results: $($latestJson.FullName)" -ForegroundColor Green
        Write-Host ""
        Write-Host "Import into the posture tool with:" -ForegroundColor Yellow
        Write-Host "  python -m m365_posture import scuba `"$($latestJson.FullName)`"" -ForegroundColor White
    }
    else {
        # Try CSV
        $csvFiles = Get-ChildItem -Path $OutputPath -Filter "*.csv" -Recurse
        if ($csvFiles) {
            $latestCsv = $csvFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            Write-Host ""
            Write-Host "ScubaGear assessment complete!" -ForegroundColor Green
            Write-Host "Results: $($latestCsv.FullName)" -ForegroundColor Green
            Write-Host ""
            Write-Host "Import into the posture tool with:" -ForegroundColor Yellow
            Write-Host "  python -m m365_posture import scuba `"$($latestCsv.FullName)`"" -ForegroundColor White
        }
        else {
            Write-Warning "No result files found in $OutputPath"
        }
    }
}
catch {
    Write-Error "Failed: $_"
    exit 1
}
