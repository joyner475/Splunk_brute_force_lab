# SOC Home Lab - Windows Event Log Monitoring with Splunk

> End-to-end lab to simulate and detect brute-force and account creation attacks using Splunk Enterprise on Ubuntu and a Windows 10 target.

### Architecture
[ Windows 10 (JOYNER) - Splunk Universal Forwarder ] ---> [ Ubuntu - Splunk Enterprise - index=wineventlog ]

### Tools Used
- Splunk Enterprise 9.x (Ubuntu Server)
- Splunk Universal Forwarder (Windows 10)
- Windows Event Logs: Security, Application
- VirtualBox

### What I Built & Fixed
1. Created custom index `wineventlog` in Splunk (`indexes.conf`)
2. Fixed `XmlWinEventLog` parsing errors - removed bad props/transforms that caused "Failed to parse XML"
3. Fixed forwarder issue `lastChanceIndex` dropping events
4. Configured inputs.conf to forward `WinEventLog:Security` and `WinEventLog:Application`
5. Validated log flow: 0 -> 1,155+ events ingested

### Key Event IDs Investigated
| Event ID | Meaning | SOC Use Case |
|---|---|---|
| 4625 | Failed Logon | Detect brute force |
| 4624 | Successful Logon | Confirm compromise after brute force |
| 4720 | User Account Created | Detect persistence / new backdoor account |
| 5379/5381 | Credential Manager | Noise filtering |

### Splunk Queries (Detection)
**1. View all Security EventCodes:**
```spl
index=wineventlog sourcetype="XmlWinEventLog:Security"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| stats count by EventCode | sort - count