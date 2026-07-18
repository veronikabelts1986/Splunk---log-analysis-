# Lab 03 — Splunk SIEM & Log Analysis

WATCH ME BUILD IT HERE https://canva.link/splunk-and-log-analysis

**Platform:** Splunk Enterprise (Free) · Microsoft Azure · Ubuntu 22.04 LTS  
**Domain:** Security Information & Event Management (SIEM)  
**Cert Alignment:** CompTIA Security+ · CySA+ · Splunk Core Certified User  
**Estimated Time:** 4–6 hours across multiple sessions  
**Estimated Cost:** $0 — Splunk Free licence covers everything in this lab

---

## Overview

A medium-sized organisation generates millions of log events every day — Windows Event Logs from workstations, authentication logs from Active Directory, firewall logs from network equipment. Without a SIEM, those logs sit in separate systems and nobody can search across them, correlate events, or identify patterns that indicate an attack.

This lab builds a fully functional Splunk SIEM environment across two Azure VMs connected via VNet peering. Windows Security, System, and Application event logs are forwarded from the Active Directory VM (Lab 01) to a dedicated Splunk instance, where they are indexed, searched, visualised on a dashboard, and monitored with an automated alert.

> **Why this matters for security roles:** Splunk is the most widely deployed commercial SIEM. Microsoft Sentinel and AWS Security Hub use the same core concepts — indexes, queries, dashboards, and alerts. Learning Splunk in a free lab environment gives you a directly transferable skill that appears on job descriptions for almost every SOC role.

---

## Architecture

<img width="2720" height="1600" alt="splunk_siem_lab_architecture" src="https://github.com/user-attachments/assets/64fb5a91-9ae7-45f2-ae08-e121aebf258d" />


**Trust boundary:** The Universal Forwarder communicates with Splunk exclusively over the private Azure VNet peering connection on port 9997 — this traffic never touches the public internet. The Splunk web UI is exposed on port 8000 via the VM's public IP for analyst access. Port 9997 is restricted to VirtualNetwork source in the NSG so only internal Azure VMs can send log data.

---

## Infrastructure — What Was Built

| Component | Detail |
|---|---|
| Windows AD VM | Windows Server 2025 · Standard_D2s_v3 · West Europe · Private IP 10.0.0.4 |
| Splunk Ubuntu VM | Ubuntu 22.04 LTS · Azure free tier · Private IP 172.16.0.4 |
| VNet Peering | Bidirectional peering between VNet A (10.0.0.0/16) and VNet B (172.16.0.0/16) |
| Splunk version | Splunk Enterprise (60-day trial, then free at 500 MB/day) |
| Data flow | Universal Forwarder → port 9997 → Splunk Indexer → index=windows_logs |
| Analyst access | Browser → public IP port 8000 |

---

## Career Relevance

| Role | How this lab applies |
|---|---|
| SOC Analyst Tier 1 | Monitoring dashboards for alerts, searching logs for suspicious activity, escalating findings |
| SOC Analyst Tier 2–3 | Building detection rules, correlating events across data sources, threat hunting |
| Cloud Security Engineer | Microsoft Sentinel and AWS Security Hub use the same SIEM concepts — this lab teaches the mental model |
| Incident Responder | Searching logs during an active incident, building a timeline of events, identifying scope of compromise |

---

## What This Lab Covers

| Skill | Real-world application |
|---|---|
| Deploy Splunk and configure a data input | Every Splunk deployment starts with getting data in — the Universal Forwarder is how most enterprise environments feed logs |
| Navigate the Splunk interface | Search, dashboards, alerts, reports — understanding the layout is table stakes for any SOC role |
| Write SPL searches | SPL is how you ask Splunk questions — the skill that separates analysts who find threats from those who stare at dashboards |
| Build security dashboards | Visualising security data at a glance — login failures over time, top source IPs, failed authentication by user |
| Identify failed login attempts | One of the most common security investigations — distinguishing normal user error from a brute force attack |
| Build an automated alert | Splunk fires an alert when conditions you define are met, rather than waiting for a human to notice |
| Search for account lockout events | A trail of lockout events can indicate a password spray attack in progress |

---

## Key Concepts Reference

| Term | Definition |
|---|---|
| SIEM | Security Information and Event Management — collects logs from across the environment, makes them searchable in one place, and alerts when suspicious conditions are met |
| SPL | Splunk Processing Language — the query language used to search and shape data in Splunk. Works as a pipeline: find events, then filter and visualise |
| Index | A named storage bucket in Splunk — like a database table. This lab uses `windows_logs` |
| Universal Forwarder | A lightweight agent installed on source machines. Monitors logs, compresses and encrypts data, and forwards it to Splunk over port 9997 |
| inputs.conf | Configuration file on the forwarder that defines which logs to collect |
| outputs.conf | Configuration file on the forwarder that defines where to send collected logs |
| EventCode 4624 | Successful logon |
| EventCode 4625 | Failed logon attempt |
| EventCode 4740 | Account lockout |
| EventCode 7036 | Service started or stopped |

---

## Prerequisites

- Lab 01 (Active Directory) completed — the Windows Server AD VM is the log source for this lab
- An Azure free account for the Splunk Ubuntu VM
- A free Splunk account (use a temporary email — see Step 1)
- SSH client: Terminal on macOS/Linux, or PuTTY on Windows

---

## Step 1 — Deploy the Splunk Ubuntu VM in Azure

Create a second VM in Azure specifically for Splunk — separate from the Windows AD VM.

| Setting | Value |
|---|---|
| OS | Ubuntu 22.04 LTS |
| Size | Standard_B2s (2 vCPU, 4 GB RAM minimum) |
| Region | Match your AD VM region |
| Disk | 30 GB minimum |
| Authentication | Password or SSH key |

**NSG inbound rules to configure before connecting:**

| Port | Source | Purpose |
|---|---|---|
| 22 | My IP address | SSH access for administration |
| 8000 | My IP address | Splunk web UI access from your browser |
| 9997 | VirtualNetwork | Forwarder data — internal Azure VMs only, not the public internet |

> **Important:** Set port 9997 source to VirtualNetwork, not Any or My IP. This ensures only your AD VM can send log data to Splunk — the public internet cannot reach this port.

> **Static IP:** Change the public IP assignment from Dynamic to Static in Azure portal (VM → Networking → click the Public IP → Configuration → Static). Dynamic IPs change every time the VM stops, which breaks your browser connection.

---

## Step 2 — Install Splunk Enterprise

SSH into the Ubuntu VM, then run the following commands.

**macOS/Linux:**
```bash
ssh yourusername@YOUR_SPLUNK_PUBLIC_IP
```

**Windows (PuTTY):**
- Open PuTTY → enter your VM's public IP → Port 22 → SSH → Open
- Enter your username and password when prompted
- Note: password characters do not appear on screen — this is normal Linux behaviour

**Install Splunk:**
```bash
# Download Splunk Enterprise
# If this URL returns a 404, log into splunk.com and copy the current wget command
wget -O splunk-linux-amd64.deb "https://download.splunk.com/products/splunk/releases/10.2.2/linux/splunk-10.2.2-80b90d638de6-linux-amd64.deb"

# Install the package
sudo dpkg -i splunk-linux-amd64.deb

# Start Splunk — you will be prompted to set admin credentials
sudo /opt/splunk/bin/splunk start --accept-license --run-as-root

# Enable Splunk to start automatically on VM reboot
sudo /opt/splunk/bin/splunk enable boot-start --run-as-root
```

**Verify Splunk is running:**
```bash
sudo /opt/splunk/bin/splunk status --run-as-root
# Expected output: splunkd is running (PID: XXXX)

# Confirm Splunk is listening on port 8000
sudo ss -tlnp | grep 8000
# Expected output: LISTEN 0 128 0.0.0.0:8000 users:(("splunkd",...))
```

**Open the web UI in your browser:**
```
http://YOUR_SPLUNK_PUBLIC_IP:8000
```

---

## Step 3 — Configure Splunk to Receive Data

Log into the Splunk web UI, then complete these two configuration steps before installing the forwarder.

**Create the index:**
1. Click **Settings** → **Indexes** → **New Index**
2. Index Name: `windows_logs`
3. Leave all other settings as default → **Save**

**Enable receiving on port 9997:**
1. Click **Settings** → **Forwarding and Receiving**
2. Under **Receive Data** → **Configure Receiving** → **New Receiving Port**
3. Enter `9997` → **Save**

---

## Step 4 — Install the Universal Forwarder on the Windows AD VM

Do this on your **Windows Server VM from Lab 01** — not on the Splunk Ubuntu VM.

1. On the Windows VM, download the Universal Forwarder from `splunk.com/en_us/download/universal-forwarder.html`
2. Run the Windows 64-bit installer
3. When prompted for a **Receiving Indexer**, enter your Splunk VM's **private IP** and port `9997`

> Use the private IP (`172.16.0.4`) — not the public IP. Traffic between the two VMs should stay inside the Azure VNet peering connection and never hit the public internet.

**Configure inputs.conf — what logs to collect:**

Navigate to this exact path on the Windows VM and create the file if it does not exist:
```
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

```ini
[WinEventLog://Security]
disabled = 0
start_from = oldest
current_only = 0
evt_resolve_ad_obj = 1

[WinEventLog://System]
disabled = 0

[WinEventLog://Application]
disabled = 0
```

**Configure outputs.conf — where to send logs:**

Create or edit this file at the same path:
```
C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf
```

```ini
[tcpout]
defaultGroup = splunk-indexer

[tcpout:splunk-indexer]
server = 172.16.0.4:9997
```

**Restart the forwarder to apply changes:**
```powershell
# Run in PowerShell as Administrator on the Windows AD VM
Restart-Service SplunkForwarder
Get-Service SplunkForwarder
# Status must show: Running
```

**Verify the forwarder can reach Splunk:**
```powershell
Test-NetConnection -ComputerName 172.16.0.4 -Port 9997
# TcpTestSucceeded must return: True
```

---

## Step 5 — Generate Test Log Data

This script generates realistic Windows Event Log data across all three log sources and triggers a lockout event. Run it on the **Windows AD VM** in **64-bit PowerShell ISE as Administrator**.

**Confirm 64-bit before running:**
```powershell
[Environment]::Is64BitProcess
# Must return True — if False, close ISE and reopen the non-x86 version
```

**Run the full script:**
```powershell
# ================================================
# Lab 03 Log Generator
# Run as Administrator in 64-bit PowerShell ISE
# Output saved to C:\lab3-log-output.txt
# ================================================

$logFile  = 'C:\lab3-log-output.txt'
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

function Log($message, $color = 'White') {
    Write-Host $message -ForegroundColor $color
    Add-Content -Path $logFile -Value "[$timestamp] $message"
}

if (Test-Path $logFile) { Remove-Item $logFile }
Add-Content -Path $logFile -Value "Lab 3 Log Generator - Run started at $timestamp"
Add-Content -Path $logFile -Value "================================================"

Log 'Starting log generation...' Green

# Create temporary test user
$testUser = 'labtest.user'
$testPass = ConvertTo-SecureString 'TempPass123!' -AsPlainText -Force
New-LocalUser -Name $testUser -Password $testPass -Description 'Splunk lab test account' -ErrorAction SilentlyContinue
Log "Created test user: $testUser" Gray

# Generate 15 failed logins (EventCode 4625)
Log 'Generating failed login events (4625)...' Yellow
$wrongPass = ConvertTo-SecureString 'WrongPassword!' -AsPlainText -Force
1..15 | ForEach-Object {
    $cred = New-Object System.Management.Automation.PSCredential($testUser, $wrongPass)
    Start-Process -FilePath 'cmd.exe' -Credential $cred -ArgumentList '/c exit' -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}
Log '  Generated 15 failed login attempts (EventCode 4625)' Gray

# Generate successful login (EventCode 4624)
Log 'Generating successful login event (4624)...' Yellow
$correctPass = ConvertTo-SecureString 'TempPass123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($testUser, $correctPass)
Start-Process -FilePath 'cmd.exe' -Credential $cred -ArgumentList '/c whoami' -Wait -ErrorAction SilentlyContinue
Log '  Generated successful login (EventCode 4624)' Gray

# Generate service start/stop events (EventCode 7036)
Log 'Generating service events (7036)...' Yellow
$services = @('Spooler', 'Schedule', 'Netlogon')
$services | ForEach-Object {
    Stop-Service -Name $_ -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Service -Name $_ -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Log "  Stopped and restarted service: $_" Gray
}

# Generate application log entries (EventID 1001)
Log 'Generating application log events...' Yellow
$eventSource = 'SplunkLabTest'
if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
    New-EventLog -LogName Application -Source $eventSource -ErrorAction SilentlyContinue
}
1..5 | ForEach-Object {
    Write-EventLog -LogName Application -Source $eventSource -EventId 1001 `
        -EntryType Warning -Message 'Splunk lab test event - application warning'
    Start-Sleep -Milliseconds 300
}
Log '  Generated 5 application log entries (EventID 1001)' Gray

# Trigger account lockout (EventCode 4740)
Log 'Generating account lockout event (4740)...' Yellow
$badCred = ConvertTo-SecureString 'BadPass!' -AsPlainText -Force
1..20 | ForEach-Object {
    $cred = New-Object System.Management.Automation.PSCredential($testUser, $badCred)
    Start-Process -FilePath 'cmd.exe' -Credential $cred -ArgumentList '/c exit' -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 200
}
Log '  Account lockout triggered (EventCode 4740)' Gray

# Cleanup
Start-Sleep -Seconds 3
Remove-LocalUser -Name $testUser -ErrorAction SilentlyContinue
Log "Removed test user: $testUser" Gray

# Restart forwarder to ship events
Log 'Restarting forwarder to ship events to Splunk...' Yellow
Restart-Service SplunkForwarder -ErrorAction SilentlyContinue
Log '  SplunkForwarder restarted' Gray

$sendTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Add-Content -Path $logFile -Value "Run completed at $sendTime"
Add-Content -Path $logFile -Value "Wait 60 seconds then run: index=windows_logs | head 100"

Write-Host ''
Write-Host '================================================' -ForegroundColor Green
Write-Host 'Done. Output saved to C:\lab3-log-output.txt'    -ForegroundColor Green
Write-Host 'Wait 60 seconds then search Splunk.'             -ForegroundColor Green
Write-Host '================================================' -ForegroundColor Green
```

Wait for the green completion message, then wait 60 seconds before searching Splunk.

---

## Step 6 — SPL Searches

All searches are typed into the search bar in the **Search & Reporting** app. Select a time range using the picker on the right side of the search bar.

**Confirm data is flowing:**
```splunk
index=windows_logs | head 100
```

**Failed login attempts (EventCode 4625):**
```splunk
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, Workstation_Name
| sort -count
```

**Successful logins with logon type (EventCode 4624):**
```splunk
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| stats count by Account_Name, Logon_Type
| sort -count
```
> Logon Type 2 = interactive, Type 3 = network, Type 10 = RDP, Type 5 = service account

**Account lockout events (EventCode 4740):**
```splunk
index=windows_logs sourcetype=WinEventLog:Security EventCode=4740
| table _time, Account_Name, Caller_Computer_Name
| sort -_time
```

**Top 10 failed login usernames — last 24 hours:**
```splunk
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625 earliest=-24h
| stats count as failures by Account_Name
| sort -failures
| head 10
```

**After-hours login detection:**
```splunk
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| table _time, Account_Name, Workstation_Name, Logon_Type
| sort -_time
```

**Service start/stop events (EventCode 7036):**
```splunk
index=windows_logs sourcetype=WinEventLog:System EventCode=7036
| table _time, Message
| sort -_time
```

---

## Step 7 — Build a Security Dashboard

1. Click **Dashboards** in the top navigation → **Create New Dashboard**
2. Name it: `Windows Security Overview` → **Create Dashboard**
3. Add the following panels using **Add Panel → New Search**

| Panel | Search | Visualisation |
|---|---|---|
| Failed Logins — Last 24h | `EventCode=4625` with `stats count by Account_Name` | Bar chart |
| Account Lockouts — Last 7d | `EventCode=4740` with `table` output | Events list |
| Login Activity Over Time | `EventCode=4624` with `timechart count` | Line chart |
| Top Source Machines | `EventCode=4625` with `stats count by Workstation_Name` | Column chart |

---

## Step 8 — Create an Automated Alert

**Run this search first to confirm it works:**
```splunk
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625
| stats count as failures by Account_Name
| where failures > 10
```

**Save as an alert:**
1. Click **Save As → Alert**
2. Name: `Potential Brute Force — High Failure Count`
3. Alert type: **Scheduled**
4. Run every: **15 minutes**
5. Trigger condition: **Number of Results is greater than 0**
6. Trigger actions: **Add to Triggered Alerts**
7. Click **Save**

---

## Verification Checks

| Check | Command / Action | Expected result |
|---|---|---|
| Forwarder is running | `Get-Service SplunkForwarder` on Windows VM | Status: Running |
| Port 9997 reachable | `Test-NetConnection -ComputerName 172.16.0.4 -Port 9997` | TcpTestSucceeded: True |
| Data flowing into Splunk | `index=windows_logs \| head 10` | Returns recent events |
| Failed login search works | `EventCode=4625` search | Returns 15 events from test script |
| Lockout event present | `EventCode=4740` search | Returns 1 lockout event |
| Dashboard populated | Open Windows Security Overview | All panels show data |
| Alert active | Settings → Searches, Reports, and Alerts | Alert shows as Enabled |

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `index=windows_logs` returns no results | Check `Get-Service SplunkForwarder` on Windows VM — if Stopped, run `Start-Service SplunkForwarder` |
| Forwarder service stopped after VM restart | Run `Set-Service -Name SplunkForwarder -StartupType Automatic` |
| `Test-NetConnection` to port 9997 fails | Verify NSG rule on Splunk VM allows port 9997 from VirtualNetwork source |
| Splunk web UI times out in browser | Splunk may have stopped — SSH into Ubuntu VM and run `sudo /opt/splunk/bin/splunk start --run-as-root` |
| Public IP changed after VM restart | Set public IP to Static in Azure portal: VM → Networking → click Public IP → Configuration → Static |
| PowerShell script errors on `New-LocalUser` | Script is running in x86 ISE — close and reopen 64-bit PowerShell ISE as Administrator |
| VNet peering shows Connected but ping fails | Check NSG rules on both VMs — add an inbound rule allowing VirtualNetwork traffic on both sides |
| Splunk starts with deprecation warning about root | Add `--run-as-root` flag: `sudo /opt/splunk/bin/splunk start --run-as-root` |

---

## Resources

- [Splunk Enterprise Download](https://www.splunk.com/en_us/download/splunk-enterprise.html)
- [Splunk Universal Forwarder Download](https://www.splunk.com/en_us/download/universal-forwarder.html)
- [Splunk SPL Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [Windows Security Event IDs — Microsoft Docs](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [CompTIA CySA+ Certification](https://www.comptia.org/certifications/cybersecurity-analyst)

---

*Lab 03 of an ongoing series covering enterprise IT infrastructure, cloud security, and identity management.*
