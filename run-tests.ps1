#!/usr/bin/env pwsh
# Script to run tests on Windows with proper filtering

param(
    [string]$Filter = "",
    [switch]$Verbose,
    [switch]$NoCaptue
)

$targetDir = "C:/temp/ftr-target"

Write-Host "Running ftr tests..." -ForegroundColor Green

# Build first
Write-Host "`nBuilding project..." -ForegroundColor Cyan
cargo build --target-dir $targetDir

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

# Run tests with empty filter to avoid the "2" issue
Write-Host "`nRunning tests..." -ForegroundColor Cyan
$args = @("test", "--target-dir", $targetDir, "--")

if ($Filter) {
    $args += $Filter
} else {
    # Pass empty string to avoid default filter
    $args += ""
}

if ($NoCaptue) {
    $args += "--nocapture"
}

if ($Verbose) {
    $args += "--verbose"
}

cargo @args

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nAll tests passed!" -ForegroundColor Green
} else {
    Write-Host "`nSome tests failed!" -ForegroundColor Red
    exit 1
}