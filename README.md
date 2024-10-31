# Windows Process & Network Security Analyzer

A PowerShell-based security analysis tool that helps detect potentially suspicious processes, network connections, and system anomalies on Windows systems.

Results are shown in a generated HTML document that auto-opens upon completion of the scan, with tools made available to do further analysis of potential threats.

## 🔍 Features

- **Process Analysis**
  - Detects hidden and potentially malicious processes
  - Identifies processes in suspicious locations
  - Analyzes process signature verification
  - Checks for process name spoofing
  - Monitors parent-child process relationships

- **Network Connection Analysis**
  - Maps connections to processes
  - Identifies connections to high-risk IP ranges
  - Detects suspicious port usage
  - Shows connection details with severity ratings
  - Links to IP reputation services (IPLeak, AbuseIPDB)

- **File System Monitoring**
  - Detects suspicious file extensions
  - Monitors common malware locations
  - Provides VirusTotal hash checking links

## 📋 Requirements

- Windows 10/11
- PowerShell 5.1 or later
- Administrator privileges

## 🚀 Quick Start

1. Download the script files to your system
2. Open PowerShell as Administrator
3. Navigate to the script directory
4. Run the main script:

```powershell
.\analyzer.ps1
```

## 📊 Understanding the Output

The script generates an HTML report with several sections:

### Network Connections
- **All Connections**: Dropdown showing all active network connections
- **Suspicious Connections**: Filtered list of potentially concerning connections
  - Green rows: Verified system/program processes
  - Yellow rows: Processes requiring attention
  - Red rows: Invalid/unsigned processes

### Process Analysis
- **Hidden Processes**: Processes with discrepancies between different system APIs
- **Suspicious Locations**: Processes running from unusual directories
- **Suspicious Extensions**: Files that might be masquerading as legitimate ones

### Color Coding
- 🟢 `system-verified`: Official Windows system process
- 🟡 `program-verified`: Verified program from standard location
- 🔵 `user-verified`: Verified user-installed application
- 🟠 `suspicious`: Process requiring investigation
- 🔴 `danger`: Invalid or suspicious signature

## 🔍 Interpreting Results

### Network Connections
- Check connections to high-risk IP ranges (marked with ⚠️)
- Review any non-browser processes making web connections
- Investigate processes with suspicious port usage
- Look for unexpected parent-child process relationships

### Processes
- Investigate any processes marked as "suspicious" or "danger"
- Check processes running from temporary directories
- Review any unsigned executables making network connections
- Validate unexpected system process behavior

## 🛡️ False Positives

Common legitimate scenarios that might trigger alerts:

1. Development tools in non-standard locations
2. Custom applications using unusual ports
3. Recently installed software in temporary locations
4. Game launchers with direct IP connections

## 🔗 Additional Resources

The tool provides direct links to:
- VirusTotal (for file hash checking)
- IPLeak.net (for IP address information)
- AbuseIPDB (for IP reputation checking)

## ⚠️ Disclaimer

This tool is for system analysis and educational purposes. It should be used as part of a broader security strategy, not as a sole security solution. Always verify findings before taking action.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or create issues for bugs and feature requests.

## 📝 License

MIT License - See LICENSE file for details
