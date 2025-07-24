# PowerShell script for testing ftr on Windows
# Requires Administrator privileges for raw socket access

param(
    [switch]$SkipBuild = $false
)

# Colors
$RED = "`e[31m"
$GREEN = "`e[32m"
$YELLOW = "`e[33m"
$BLUE = "`e[34m"
$NC = "`e[0m"

Write-Host "${BLUE}=== ftr Windows Test Suite ===${NC}"
Write-Host "System: $([System.Environment]::OSVersion.VersionString)"
Write-Host "Architecture: $([System.Environment]::Is64BitOperatingSystem)"
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "${RED}This script must be run as Administrator${NC}" -ForegroundColor Red
    Write-Host "Please run in an elevated PowerShell prompt"
    exit 1
}

# Check for Npcap
Write-Host "${YELLOW}Checking for Npcap installation...${NC}"
$npcapPath = "${env:ProgramFiles}\Npcap"
$winpcapPath = "${env:ProgramFiles(x86)}\WinPcap"

if (Test-Path $npcapPath) {
    Write-Host "${GREEN}✓ Npcap found${NC}"
} elseif (Test-Path $winpcapPath) {
    Write-Host "${YELLOW}WinPcap found (consider upgrading to Npcap)${NC}"
} else {
    Write-Host "${RED}✗ Npcap not found${NC}"
    Write-Host "Please install Npcap from https://npcap.com/#download"
    Write-Host "Make sure to check 'WinPcap API-compatible Mode' during installation"
    exit 1
}

# Check for Rust
Write-Host "${YELLOW}Checking for Rust installation...${NC}"
try {
    $rustVersion = rustc --version
    Write-Host "${GREEN}✓ Rust found: $rustVersion${NC}"
} catch {
    Write-Host "${RED}✗ Rust not found${NC}"
    Write-Host "Please install Rust from https://rustup.rs"
    exit 1
}

# Navigate to ftr directory
$ftrPath = Join-Path $env:USERPROFILE "ftr"
if (-not (Test-Path $ftrPath)) {
    Write-Host "${YELLOW}Cloning ftr repository...${NC}"
    git clone https://github.com/dweekly/ftr $ftrPath
}

Set-Location $ftrPath

# Update repository
Write-Host "${YELLOW}Updating ftr repository...${NC}"
git pull

# Build ftr
if (-not $SkipBuild) {
    Write-Host "${YELLOW}Building ftr...${NC}"
    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        Write-Host "${RED}Build failed${NC}"
        exit 1
    }
}

$ftrExe = ".\target\release\ftr.exe"

# Function to test ftr
function Test-Ftr {
    param(
        [string]$TestName,
        [string]$Command,
        [bool]$ExpectSuccess = $true
    )
    
    Write-Host "${YELLOW}Test: $TestName${NC}"
    Write-Host "Command: $Command"
    
    $output = $null
    $success = $false
    
    try {
        $output = Invoke-Expression $Command 2>&1
        $success = $LASTEXITCODE -eq 0
    } catch {
        $success = $false
        $output = $_.Exception.Message
    }
    
    if ($success -eq $ExpectSuccess) {
        Write-Host "${GREEN}✓ PASSED${NC}"
        if ($output) {
            Write-Host "Output:"
            $output | Select-Object -First 10 | ForEach-Object { Write-Host $_ }
        }
    } else {
        Write-Host "${RED}✗ FAILED${NC}"
        if ($output) {
            Write-Host "Error output:"
            $output | ForEach-Object { Write-Host $_ }
        }
    }
    Write-Host ""
}

# Tests
Write-Host "${BLUE}=== Basic Functionality Tests ===${NC}"

# Test 1: Basic traceroute
Test-Ftr -TestName "Basic traceroute to google.com" `
         -Command "$ftrExe google.com -m 10" `
         -ExpectSuccess $true

# Test 2: Traceroute to IP address
Test-Ftr -TestName "Traceroute to 1.1.1.1" `
         -Command "$ftrExe 1.1.1.1 -m 10" `
         -ExpectSuccess $true

# Test 3: Custom timeout
Test-Ftr -TestName "Fast timeout test" `
         -Command "$ftrExe google.com -m 5 --overall-timeout-ms 2000" `
         -ExpectSuccess $true

# Test 4: Invalid hostname
Test-Ftr -TestName "Invalid hostname (should fail)" `
         -Command "$ftrExe invalid.hostname.does.not.exist" `
         -ExpectSuccess $false

# Test 5: Local network trace
Test-Ftr -TestName "Local network trace" `
         -Command "$ftrExe 192.168.1.1 -m 5" `
         -ExpectSuccess $true

Write-Host "${BLUE}=== Performance Testing ===${NC}"

# Compare with Windows tracert
Write-Host "Windows tracert (for comparison):"
Measure-Command { tracert -h 10 google.com | Out-Null } | ForEach-Object { Write-Host "Time: $($_.TotalSeconds) seconds" }

Write-Host ""
Write-Host "ftr:"
Measure-Command { & $ftrExe google.com -m 10 | Out-Null } | ForEach-Object { Write-Host "Time: $($_.TotalSeconds) seconds" }

Write-Host ""
Write-Host "${BLUE}=== Windows-Specific Information ===${NC}"

# Network adapters
Write-Host "Network adapters:"
Get-NetAdapter | Select-Object Name, Status, LinkSpeed | Format-Table

# Firewall status
Write-Host ""
Write-Host "Windows Firewall status:"
Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table

# Check WinPcap/Npcap service
Write-Host ""
Write-Host "Packet capture service status:"
Get-Service -Name "npcap" -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-Table
Get-Service -Name "npf" -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-Table

Write-Host ""
Write-Host "${GREEN}Windows testing complete!${NC}"

Write-Host ""
Write-Host "${YELLOW}Notes for Windows:${NC}"
Write-Host "- Administrator privileges are required for raw socket access"
Write-Host "- Npcap must be installed with WinPcap compatibility mode"
Write-Host "- Windows Defender Firewall may affect ICMP operations"
Write-Host "- Some corporate networks may block ICMP traffic"