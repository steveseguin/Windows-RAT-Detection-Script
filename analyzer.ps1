# Enhanced RAT Detection Script with HTML Output
$ErrorActionPreference = 'SilentlyContinue'

# Functions for network analysis
function Test-SuspiciousPort {
    param([int]$Port)
    
    # Common RAT/backdoor ports
    $suspiciousPorts = @(
        31337,  # Back Orifice
        12345,  # NetBus
        27374,  # SubSeven
        5900,   # VNC (when not expected)
        4444,   # Metasploit default
        1080,   # SOCKS proxy
        6660..6669, # Common IRC ports (often used by botnets)
        8080,   # Alternative HTTP (suspicious for desktop apps)
        9999    # Common backdoor port
    )
    
    return $Port -in $suspiciousPorts
}

function Test-SuspiciousConnection {
    param(
        $Connection,
        $Process
    )
    
    # Initialize suspicion flags
    $flags = @()
    
    # Only proceed if we have valid connection and process info
    if ($Connection -and $Process) {
        # 1. Check if it's a non-browser process connecting to common web ports
        if (($Connection.RemotePort -in @(80, 443)) -and 
            ($Process.Name -notmatch '^(chrome|firefox|msedge|opera|brave|iexplore|wget|curl|powershell_ise)$')) {
            $flags += "Non-browser making web connections"
        }
        
        # 2. Check for suspicious ports
        if (Test-SuspiciousPort -Port $Connection.LocalPort) {
            $flags += "Suspicious local port: $($Connection.LocalPort)"
        }
        if (Test-SuspiciousPort -Port $Connection.RemotePort) {
            $flags += "Suspicious remote port: $($Connection.RemotePort)"
        }
        
        # 3. Check for direct IP connections by non-network tools
        if ($Connection.RemoteAddress -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' -and
            ($Process.Name -notmatch '^(ping|tracert|nslookup|dig|whois|netstat|ssh|telnet)$')) {
            $flags += "Direct IP connection by non-networking tool"
        }
        
        # 4. Check for unusual process locations making network connections
        if ($Process.Path -and (
            $Process.Path -like "*\Temp\*" -or
            $Process.Path -like "*\AppData\Local\Temp\*" -or
            $Process.Path -like "*\Downloads\*")) {
            $flags += "Network connection from temporary directory"
        }
        
        # 5. Check for network connections from typically non-networked system tools
        if ($Process.Name -match '^(notepad|calc|mspaint|write|wordpad)$') {
            $flags += "Unexpected network activity from system tool"
        }
    }
    
    # Return results
    return [PSCustomObject]@{
        IsSuspicious = $flags.Count -gt 0
        Flags = $flags
        Severity = switch($flags.Count) {
            0 { "Normal" }
            1 { "Low" }
            2 { "Medium" }
            default { "High" }
        }
    }
}


function Get-FileHash2 {
    param($filePath)
    if (Test-Path $filePath) {
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256
        [PSCustomObject]@{
            'File' = Split-Path $filePath -Leaf
            'Path' = $filePath
            'SHA256' = $hash.Hash
        }
    }
}

# Function to verify process legitimacy
function Test-LegitimateProcess {
    param (
        [Parameter(Mandatory=$true)]
        [System.Diagnostics.Process]$Process
    )
    
    $result = @{
        IsLegitimate = $false
        Reasons = @()
        SignatureStatus = "Unknown"
        Path = $Process.Path
        TrustLevel = "Unknown"  # New field for trust classification
    }
    
    if (-not $Process.Path) {
        $result.Reasons += "No path available"
        $result.TrustLevel = "Unknown"
        return $result
    }
    
    # Define path categories
    $systemPaths = @(
        "$env:SystemRoot\System32",
        "$env:SystemRoot\SysWOW64"
    )
    
    $programPaths = @(
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}"
    )
    
    $userProgramPaths = @(
        "$env:LocalAppData\Programs",
        "$env:LocalAppData\Discord",
        "$env:LocalAppData\Slack",
        "$env:LocalAppData\Microsoft",
        "$env:AppData\Programs"
    )
    
    # Check signature first
    try {
        $signature = Get-AuthenticodeSignature -FilePath $Process.Path
        $result.SignatureStatus = $signature.Status
        
        switch ($signature.Status) {
            'Valid' {
                $signerName = $signature.SignerCertificate.Subject
                $result.Reasons += "Valid signature from: $signerName"
                
                # Check paths after confirming valid signature
                if ($systemPaths | Where-Object { $Process.Path.StartsWith($_) }) {
                    $result.IsLegitimate = $true
                    $result.TrustLevel = "System"
                    $result.Reasons += "Running from system directory"
                }
                elseif ($programPaths | Where-Object { $Process.Path.StartsWith($_) }) {
                    $result.IsLegitimate = $true
                    $result.TrustLevel = "Program"
                    $result.Reasons += "Running from Program Files"
                }
                elseif ($userProgramPaths | Where-Object { $Process.Path.StartsWith($_) }) {
                    $result.IsLegitimate = $true
                    $result.TrustLevel = "User-Installed"
                    $result.Reasons += "Running from user programs directory"
                }
                else {
                    $result.TrustLevel = "Non-Standard"
                    $result.Reasons += "Valid signature but non-standard location"
                }
            }
            'NotSigned' {
                $result.Reasons += "No digital signature"
                $result.TrustLevel = "Unsigned"
            }
            'Invalid' {
                $result.Reasons += "Invalid signature"
                $result.TrustLevel = "Invalid"
            }
            default {
                $result.Reasons += "Signature status: $($signature.Status)"
                $result.TrustLevel = "Unknown"
            }
        }
    } catch {
        $result.Reasons += "Error checking signature: $($_.Exception.Message)"
        $result.TrustLevel = "Error"
    }
    
    return $result
}
function Get-IPInfoLink {
    param([string]$IP)
    return "https://ipleak.net/?q=$IP"
}

function Get-AbuseIPDBLink {
    param([string]$IP)
    return "https://www.abuseipdb.com/check/$IP"
}

function Test-HighRiskCountryIP {
    param([string]$IP)

    # Known high-risk IP ranges (this is a small subset for demonstration)
	$highRiskRanges = @(
		# North Korea - All known NK ranges
		@{ Start = "175.45.176.0"; End = "175.45.179.255" },    # AS131279
		@{ Start = "210.52.109.0"; End = "210.52.109.255" },    # NK NET 1
		@{ Start = "77.94.35.0"; End = "77.94.35.255" },        # NK NET 2
		
		# Known Cybercrime Hosting Ranges
		@{ Start = "91.195.240.0"; End = "91.195.241.255" },    # Known botnet C&C
		@{ Start = "185.156.73.0"; End = "185.156.73.255" },    # Malware distribution
		@{ Start = "194.28.172.0"; End = "194.28.175.255" },    # Cybercrime hosting
		@{ Start = "46.148.112.0"; End = "46.148.127.255" },    # Malicious activity
		
		# Tor Exit Nodes (Sample ranges - these change frequently)
		@{ Start = "185.220.100.240"; End = "185.220.100.255" },
		@{ Start = "185.220.101.0"; End = "185.220.101.255" },
		@{ Start = "185.220.102.0"; End = "185.220.102.255" },
		
		# Known Spam Operations
		@{ Start = "93.179.88.0"; End = "93.179.95.255" },
		@{ Start = "146.185.200.0"; End = "146.185.207.255" },
		@{ Start = "5.188.9.0"; End = "5.188.9.255" },
		
		# Credential Stuffing/Brute Force Attacks
		@{ Start = "89.248.160.0"; End = "89.248.175.255" },
		@{ Start = "93.174.88.0"; End = "93.174.95.255" },
		
		# Known Malware Command & Control
		@{ Start = "185.193.38.0"; End = "185.193.38.255" },
		@{ Start = "194.156.98.0"; End = "194.156.98.255" },
		@{ Start = "45.155.205.0"; End = "45.155.205.255" },
		
		# Cryptocurrency Mining Malware
		@{ Start = "185.150.84.0"; End = "185.150.87.255" },
		@{ Start = "194.32.78.0"; End = "194.32.78.255" },
		
		# Known Ransomware Infrastructure
		@{ Start = "92.223.89.0"; End = "92.223.89.255" },
		@{ Start = "185.159.128.0"; End = "185.159.129.255" },
		@{ Start = "185.238.0.0"; End = "185.238.1.255" },
		
		# Bulletproof Hosting (Known for malicious activity)
		@{ Start = "194.58.56.0"; End = "194.58.59.255" },
		@{ Start = "91.243.90.0"; End = "91.243.91.255" },
		@{ Start = "146.0.77.0"; End = "146.0.77.255" },
		
		# DDoS Attack Sources
		@{ Start = "193.109.69.0"; End = "193.109.69.255" },
		@{ Start = "191.101.180.0"; End = "191.101.180.255" },
		
		# Known APT Infrastructure
		@{ Start = "185.236.203.0"; End = "185.236.203.255" },
		@{ Start = "194.87.69.0"; End = "194.87.69.255" },
		@{ Start = "45.153.160.0"; End = "45.153.160.255" },
		
		# Scan/Exploit Attempt Sources
		@{ Start = "185.156.72.0"; End = "185.156.73.255" },
		@{ Start = "89.248.167.0"; End = "89.248.167.255" },
		@{ Start = "185.216.140.0"; End = "185.216.140.255" },
		
		# Phishing Hosts
		@{ Start = "92.242.40.0"; End = "92.242.47.255" },
		@{ Start = "91.217.137.0"; End = "91.217.137.255" },
		
		# Malvertising Networks
		@{ Start = "188.241.178.0"; End = "188.241.178.255" },
		@{ Start = "185.183.96.0"; End = "185.183.97.255" }
	)
    
    $ipBytes = [System.Net.IPAddress]::Parse($IP).GetAddressBytes()
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($ipBytes) }
    $ipNum = [BitConverter]::ToUInt32($ipBytes, 0)
    
    # Categories for different types of high-risk IPs
    $categories = @{
        "175.45.176.0-175.45.179.255" = "North Korean Network"
        "91.195.240.0-91.195.241.255" = "Known Botnet Command & Control"
        "185.220.100.0-185.220.102.255" = "Tor Exit Node"
        "93.179.88.0-93.179.95.255" = "Spam Operations"
        "89.248.160.0-89.248.175.255" = "Credential Stuffing/Brute Force"
        "185.193.38.0-185.193.38.255" = "Malware Command & Control"
        "185.150.84.0-185.150.87.255" = "Cryptocurrency Mining Malware"
        "92.223.89.0-92.223.89.255" = "Ransomware Infrastructure"
        "194.58.56.0-194.58.59.255" = "Bulletproof Hosting"
        "193.109.69.0-193.109.69.255" = "DDoS Attack Source"
        "185.236.203.0-185.236.203.255" = "APT Infrastructure"
        "185.156.72.0-185.156.73.255" = "Known Scan/Exploit Source"
        "92.242.40.0-92.242.47.255" = "Phishing Operations"
        "188.241.178.0-188.241.178.255" = "Malvertising Network"
    }
    
    foreach ($range in $highRiskRanges) {
        $startBytes = [System.Net.IPAddress]::Parse($range.Start).GetAddressBytes()
        $endBytes = [System.Net.IPAddress]::Parse($range.End).GetAddressBytes()
        if ([BitConverter]::IsLittleEndian) {
            [Array]::Reverse($startBytes)
            [Array]::Reverse($endBytes)
        }
        $startNum = [BitConverter]::ToUInt32($startBytes, 0)
        $endNum = [BitConverter]::ToUInt32($endBytes, 0)
        
        if ($ipNum -ge $startNum -and $ipNum -le $endNum) {
            # Find matching category
            $rangeKey = $categories.Keys | Where-Object { 
                $range.Start -ge ($_ -split '-')[0] -and 
                $range.End -le ($_ -split '-')[1]
            } | Select-Object -First 1
            
            $category = if ($rangeKey) { 
                $categories[$rangeKey] 
            } else { 
                "High Risk Range" 
            }
            
            return @{
                IsHighRisk = $true
                Category = $category
                Range = "$($range.Start)-$($range.End)"
            }
        }
    }
    
    return @{
        IsHighRisk = $false
        Category = "Normal"
        Range = ""
    }
}

function Get-SuspiciousConnections {
    param($allConnections)
    
    # Filter for truly suspicious connections
    $suspiciousConnections = $allConnections | Where-Object {
        $process = Get-Process -Id $_.PID -ErrorAction SilentlyContinue
        
        # Skip known safe processes unless they exhibit very suspicious behavior
        $knownSafeProcesses = @(
            'svchost', 'services', 'lsass', 'System', 
            'OneDrive', 'Teams', 'msedge', 'chrome', 
            'firefox', 'Discord', 'Slack', 'outlook',
            'SearchApp', 'YourPhone', 'RuntimeBroker',
            'backgroundTaskHost', 'spoolsv', 'MsMpEng',
            'NVDisplay.Container', 'Steam', 'Battle.net',
            'EpicGamesLauncher', 'spotify', 'Code'
        )
        
        # Always check these conditions regardless of process name
        $highRiskCheck = Test-HighRiskCountryIP -IP $_.RemoteIP
        $isSuspiciousPort = Test-SuspiciousPort -Port $_.RemotePort
        
        # If it's a high-risk IP or suspicious port, include it regardless of process
        if ($highRiskCheck.IsHighRisk -or $isSuspiciousPort) {
            return $true
        }
        
        # For known safe processes, only include if there are multiple serious indicators
        if ($process.Name -in $knownSafeProcesses) {
            $suspiciousFactors = 0
            
            # Count suspicious factors
            if ($_.Path -like "*\Temp\*") { $suspiciousFactors++ }
            if ($_.Path -like "*\AppData\Local\Temp\*") { $suspiciousFactors++ }
            if ($_.Path -like "*\Downloads\*") { $suspiciousFactors++ }
            if (-not $_.IsLegitimate.IsLegitimate) { $suspiciousFactors++ }
            
            # Only include if multiple suspicious factors are present
            return $suspiciousFactors -gt 1
        }
        
        # For unknown processes, include if any suspicious indicator is present
        return (
            -not $_.IsLegitimate.IsLegitimate -or
            $_.Path -like "*\Temp\*" -or
            $_.Path -like "*\AppData\Local\Temp\*" -or
            $_.Path -like "*\Downloads\*" -or
            $_.Severity -ne "Normal"
        )
    }
    
    return $suspiciousConnections
}

# Initialize HTML report
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>RAT Detection Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .section { background: white; padding: 15px; margin: 15px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h2 { color: #2c3e50; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
        .warning { color: #dc3545; }
        .info { color: #0066cc; }
        .hash-link { color: #28a745; text-decoration: none; }
        .hash-link:hover { text-decoration: underline; }
        .suspicious { background-color: #fff3cd; }
        .verified { background-color: #d4edda; }
		.section table {
			width: 100%;
			border-collapse: collapse;
			margin: 10px 0;
			white-space: nowrap;
		}

		.section td {
			padding: 8px;
			border-bottom: 1px solid #ddd;
			max-width: 300px;
			overflow: hidden;
			text-overflow: ellipsis;
			white-space: nowrap;
		}
		.system-verified { background-color: #b3e6cc; }  /* Darker green for system processes */
		.program-verified { background-color: #d4edda; } /* Standard green for program files */
		.user-verified { background-color: #e6f3ff; }   /* Light blue for user-installed apps */
    </style>
</head>
<body>
    <h1>RAT Detection Report - $(Get-Date)</h1>
"@

# Network Connections Section
$htmlReport += "<div class='section'><h2>Network Connections Overview</h2>"

# Get all established connections with better error handling
$allConnections = Get-NetTCPConnection | Where-Object {
    $_.State -eq 'Established'
} | ForEach-Object {
    try {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        
		[PSCustomObject]@{
			'Process' = if ($process) { $process.Name } else { "Unknown" }
			'PID' = $_.OwningProcess
			'LocalPort' = $_.LocalPort
			'RemoteIP' = $_.RemoteAddress
			'RemotePort' = $_.RemotePort
			'Path' = if ($process) { $process.Path } else { "Unknown" }
			'IsLegitimate' = if ($process) { Test-LegitimateProcess -Process $process } else { @{ IsLegitimate = $false; Reasons = @("No process information") } }
			'SignatureStatus' = if ($process -and $process.Path) {
				try {
					(Get-AuthenticodeSignature -FilePath $process.Path).Status
				} catch {
					"Unknown"
				}
			} else {
				"Unknown"
			}
		}
    } catch {
        Write-Warning "Error processing connection for PID $($_.OwningProcess): $_"
        # Return a minimal object for failed processing
        [PSCustomObject]@{
            'Process' = "Error"
            'PID' = $_.OwningProcess
            'LocalPort' = $_.LocalPort
            'RemoteIP' = $_.RemoteAddress
            'RemotePort' = $_.RemotePort
            'Path' = "Error processing process information"
            'IsLegitimate' = $false
        }
    }
}

# Display all connections
$htmlReport += @"
<details>
    <summary style='cursor: pointer; padding: 10px; background: #f8f9fa; border-radius: 5px; margin-bottom: 20px;'>
        All Active Connections (Click to expand)
    </summary>
    <div style='overflow-x: auto;'>
    <table style='width: 100%;'>
        <tr>
            <th>Process</th>
            <th>PID</th>
            <th>Local Port</th>
            <th>Remote IP</th>
            <th>Remote Port</th>
            <th>Path</th>
        </tr>
"@

foreach ($conn in $allConnections) {
    $rowClass = if ($conn.IsLegitimate) { "verified" } else { "suspicious" }
    $htmlReport += @"
    <tr class='$rowClass'>
        <td>$($conn.Process)</td>
        <td>$($conn.PID)</td>
        <td>$($conn.LocalPort)</td>
        <td>$($conn.RemoteIP)</td>
        <td>$($conn.RemotePort)</td>
        <td style='max-width: 300px; overflow: hidden; text-overflow: ellipsis;'>$($conn.Path)</td>
    </tr>
"@
}

$htmlReport += "</table></div></details>"

$htmlReport += "<h2>Suspicious Network Connections</h2>"

# Filter for suspicious connections
$suspiciousConnections = Get-SuspiciousConnections -allConnections $allConnections

if ($suspiciousConnections) {
    $htmlReport += "<table>
        <tr>
            <th>Process</th>
            <th>PID</th>
            <th>Local Port</th>
            <th>Remote IP</th>
            <th>Remote Port</th>
            <th>Severity</th>
            <th>Suspicious Indicators</th>
            <th>IP Information</th>
            <th>Status</th>
        </tr>"
    
    foreach ($conn in $suspiciousConnections) {
        $process = Get-Process -Id $conn.PID -ErrorAction SilentlyContinue
        $hash = if ($process -and $process.Path) {
            Get-FileHash -Path $process.Path -Algorithm SHA256 -ErrorAction SilentlyContinue
        }
        
        $processNameCell = if ($hash) {
            "<a href='https://www.virustotal.com/gui/file/$($hash.Hash)' class='hash-link' target='_blank'>$($conn.Process)</a>"
        } else {
            $conn.Process
        }
        
        $rowClass = switch($conn.IsLegitimate.TrustLevel) {
            "System" { "system-verified" }
            "Program" { "program-verified" }
            "User-Installed" { "user-verified" }
            "Non-Standard" { "suspicious" }
            "Unsigned" { "warning" }
            "Invalid" { "danger" }
            default { "suspicious" }
        }
        
        # Generate IP information links
        $ipCheck = Test-HighRiskCountryIP -IP $conn.RemoteIP
        $ipInfoLink = Get-IPInfoLink -IP $conn.RemoteIP
        $abuseIPDBLink = Get-AbuseIPDBLink -IP $conn.RemoteIP
        
        $ipRiskWarning = if ($ipCheck.IsHighRisk) {
            "<span class='warning'>⚠️ High-risk IP range<br/>Category: $($ipCheck.Category)</span><br/>"
        } else { "" }
        
        $ipLinks = @"
            $ipRiskWarning
            <a href='$ipInfoLink' class='hash-link' target='_blank'>IPLeak Info</a>
            <br/>
            <a href='$abuseIPDBLink' class='hash-link' target='_blank'>AbuseIPDB Check</a>
"@
        
        $status = switch($conn.IsLegitimate.TrustLevel) {
            "System" { "System Process" }
            "Program" { "Verified Program" }
            "User-Installed" { "Verified User App" }
            "Non-Standard" { "Valid Signature (Non-Standard Location)" }
            "Unsigned" { "Unsigned Process" }
            "Invalid" { "Invalid Signature" }
            "Unknown" { "Unknown Status" }
            default { $conn.IsLegitimate.Reasons -join "<br/>" }
        }
        
        $flags = if ($conn.Flags) { 
            $conn.Flags -join "<br/>" 
        } else { 
            "None" 
        }
        
        $htmlReport += @"
        <tr class='$rowClass'>
            <td>$processNameCell</td>
            <td>$($conn.PID)</td>
            <td>$($conn.LocalPort)</td>
            <td>$($conn.RemoteIP)</td>
            <td>$($conn.RemotePort)</td>
            <td>$($conn.Severity)</td>
            <td>$flags</td>
            <td>$ipLinks</td>
            <td>$status</td>
        </tr>
"@
    }
    $htmlReport += "</table>"
} else {
    $htmlReport += "<p class='info'>No suspicious network connections found.</p>"
}

$htmlReport += "</div>"

$htmlReport = $htmlReport -replace "</style>", @"
        .danger { background-color: #f8d7da; }
        .warning { background-color: #fff3cd; }
        .suspicious { background-color: #fff3cd; }
        .verified { background-color: #d4edda; }
        details summary:hover { background: #e9ecef; }
        details[open] summary { margin-bottom: 10px; }
    </style>
"@

# 3. Check for processes in suspicious locations
$htmlReport += "<div class='section'><h2>Processes in Suspicious Locations</h2>"
$knownApps = @("Discord", "slack", "Teams", "ollama", "Code", "WhatsApp", "Spotify")
$suspiciousLocations = Get-Process | Where-Object {
    ($_.Path -like "*\temp\*" -or 
     $_.Path -like "*\AppData\Local\Temp\*" -or
     $_.Path -like "*\programdata\*" -or
     $_.Path -like "*\Downloads\*") -and
    $_.Name -notin $knownApps
}

if ($suspiciousLocations) {
    $htmlReport += "<table><tr><th>Process</th><th>PID</th><th>Path</th><th>VirusTotal Check</th></tr>"
    foreach ($proc in ($suspiciousLocations | Sort-Object -Property Path -Unique)) {
        if ($proc.Path) {
            $hash = Get-FileHash2 $proc.Path
            $vtLink = "https://www.virustotal.com/gui/file/$($hash.SHA256)"
            $htmlReport += "<tr><td>$($proc.Name)</td><td>$($proc.Id)</td><td>$($proc.Path)</td><td><a href='$vtLink' class='hash-link' target='_blank'>Check on VirusTotal</a></td></tr>"
        }
    }
    $htmlReport += "</table>"
} else {
    $htmlReport += "<p class='info'>No processes found in suspicious locations.</p>"
}
$htmlReport += "</div>"


function Get-HiddenProcesses {
    # Array to store results
    $hiddenProcesses = @()
    
    # Get processes through different methods
    $psProcesses = @{}
    $wmiProcesses = @{}
    
    # Build process lists with error handling
    try {
        Get-Process | ForEach-Object { $psProcesses[$_.Id] = $_ }
        Get-WmiObject Win32_Process | ForEach-Object { $wmiProcesses[$_.ProcessId] = $_ }
    }
    catch {
        Write-Warning "Error gathering process information: $_"
    }
    
    # Known legitimate processes that can have discrepancies
    $legitimateProcesses = @(
        'System', 'Registry', 'Memory', 'Idle',
        'svchost', 'services', 'wininit', 'lsass', 
        'csrss', 'smss', 'winlogon', 'RuntimeBroker',
        'SearchHost', 'ShellExperienceHost', 'TextInputHost',
        'conhost', 'dllhost', 'sihost', 'fontdrvhost',
        'spoolsv', 'SearchIndexer', 'WmiPrvSE', 'dwm',
        'ctfmon', 'taskhostw', 'explorer', 'StartMenuExperienceHost',
        'ApplicationFrameHost', 'SecurityHealthService'
    )
    
    # Suspicious characteristics to check
    function Test-ProcessSuspicious {
        param($Process, $WmiProcess)
        
        # Skip checking legitimate processes unless they show highly suspicious traits
        if ($Process.ProcessName -in $legitimateProcesses) {
            return $false
        }
        
        $suspiciousTraits = @()
        
        # Check executable path discrepancy
        if ($Process.Path -and $WmiProcess.ExecutablePath -and 
            ($Process.Path -ne $WmiProcess.ExecutablePath)) {
            $suspiciousTraits += "Path mismatch"
        }
        
        # Check for suspicious locations
        if ($Process.Path -match "\\Temp\\|\\AppData\\Local\\Temp\\|\\ProgramData\\") {
            $suspiciousTraits += "Suspicious location"
        }
        
        # Check for suspicious parent process relationships
        $parentProcess = $wmiProcesses[$WmiProcess.ParentProcessId]
        if ($parentProcess) {
            $suspiciousParentRelations = @(
                # Browser spawning command shells
                @{Child = "^(cmd|powershell)\.exe$"; Parent = "^(chrome|firefox|msedge|iexplore)\.exe$"},
                # Unusual parent for system processes
                @{Child = "^svchost\.exe$"; Parent = "^(?!services|wininit).*"},
                # Office apps spawning suspicious processes
                @{Child = ".*\.exe$"; Parent = "^(WINWORD|EXCEL|POWERPNT)\.EXE$"}
            )
            
            foreach ($relation in $suspiciousParentRelations) {
                if ($Process.ProcessName -match $relation.Child -and 
                    $parentProcess.Name -match $relation.Parent) {
                    $suspiciousTraits += "Suspicious parent process: $($parentProcess.Name)"
                }
            }
        }
        
        # Check for suspicious command line arguments
        if ($WmiProcess.CommandLine -match "-hidden|-enc|-decode|powershell\.exe.*-w hidden|cmd\.exe.*/c") {
            $suspiciousTraits += "Suspicious command line arguments"
        }
        
        # Return true if any suspicious traits were found
        return $suspiciousTraits.Count -gt 0, $suspiciousTraits
    }
    
    # Check processes
    foreach ($psProcess in $psProcesses.Values) {
        $wmiProcess = $wmiProcesses[$psProcess.Id]
        
        # Skip if process doesn't exist in WMI (might be short-lived)
        if (-not $wmiProcess) { continue }
        
        $isSuspicious, $traits = Test-ProcessSuspicious -Process $psProcess -WmiProcess $wmiProcess
        
        if ($isSuspicious) {
            $hiddenProcesses += [PSCustomObject]@{
                ProcessName = $psProcess.ProcessName
                PID = $psProcess.Id
                Path = $psProcess.Path
                DiscrepancyType = $traits -join ", "
                CommandLine = $wmiProcess.CommandLine
                ParentPID = $wmiProcess.ParentProcessId
                ParentName = ($wmiProcesses[$wmiProcess.ParentProcessId]).Name
            }
        }
    }
    
    return $hiddenProcesses
}

# 4. Check for hidden processes
$htmlReport += "<div class='section'><h2>Suspicious Processes</h2>"
$suspiciousProcesses = Get-HiddenProcesses

if ($suspiciousProcesses) {
    $htmlReport += "<table><tr><th>Process</th><th>PID</th><th>Parent Process</th><th>Path</th><th>Suspicious Traits</th><th>Command Line</th><th>VirusTotal Check</th></tr>"
    foreach ($proc in $suspiciousProcesses) {
        $vtLink = ""
        if ($proc.Path -and (Test-Path $proc.Path)) {
            $hash = Get-FileHash2 $proc.Path
            $vtLink = "<a href='https://www.virustotal.com/gui/file/$($hash.SHA256)' class='hash-link' target='_blank'>Check on VirusTotal</a>"
        }
        $htmlReport += "<tr class='suspicious'>
            <td>$($proc.ProcessName)</td>
            <td>$($proc.PID)</td>
            <td>$($proc.ParentName) ($($proc.ParentPID))</td>
            <td>$($proc.Path)</td>
            <td>$($proc.DiscrepancyType)</td>
            <td>$($proc.CommandLine)</td>
            <td>$vtLink</td>
        </tr>"
    }
    $htmlReport += "</table>"
} else {
    $htmlReport += "<p class='info'>No suspicious processes found.</p>"
}
$htmlReport += "</div>"

# 5. Check for unusual file extensions masquerading as legitimate ones
$htmlReport += "<div class='section'><h2>Suspicious File Extensions</h2>"
$suspiciousExts = Get-ChildItem -Path $env:USERPROFILE\Desktop, $env:USERPROFILE\Downloads -File -Recurse |
    Where-Object { $_.Name -match '\.(exe|scr|bat|vbs|ps1)\.' -or $_.Name -match '\.txt\.exe$' }

if ($suspiciousExts) {
    $htmlReport += "<table><tr><th>File</th><th>Path</th><th>VirusTotal Check</th></tr>"
    foreach ($file in $suspiciousExts) {
        $hash = Get-FileHash2 $file.FullName
        $vtLink = "https://www.virustotal.com/gui/file/$($hash.SHA256)"
        $htmlReport += "<tr><td>$($file.Name)</td><td>$($file.FullName)</td><td><a href='$vtLink' class='hash-link' target='_blank'>Check on VirusTotal</a></td></tr>"
    }
    $htmlReport += "</table>"
} else {
    $htmlReport += "<p class='info'>No suspicious file extensions found.</p>"
}
$htmlReport += "</div>"

# Close HTML
$htmlReport += @"
</body>
</html>
"@

# Save and open report
$reportPath = "$env:USERPROFILE\Desktop\RAT_Detection_Report.html"
$htmlReport | Out-File -FilePath $reportPath -Encoding UTF8
Start-Process $reportPath
