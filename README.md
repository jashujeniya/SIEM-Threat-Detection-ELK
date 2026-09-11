# SIEM Threat Detection with Elastic Stack

## Overview
A controlled cybersecurity lab project demonstrating custom SIEM detection rules in Elastic Security for three attack techniques:

1. Credential Stuffing
2. DNS Tunnelling
3. PowerShell Exploitation

The project uses synthetic test events and threshold-based detection rules in an isolated Elastic Stack environment.

## Objectives
- Build and configure custom SIEM detection rules.
- Monitor authentication, DNS, and process activity.
- Test detections using controlled synthetic events.
- Generate and validate security alerts.
- Document the detection engineering workflow.

## Technology Stack
- Elasticsearch 9.1.3
- Kibana 9.1.3
- Elastic Security
- Kali Linux
- Docker / Docker Compose
- KQL
- JSON
- VirtualBox

## Architecture

Synthetic Test Events
        |
        v
Elasticsearch
        |
        v
Kibana / Elastic Security
        |
        v
Custom Detection Rules
        |
        v
Security Alerts

## Detection Rules

### Credential Stuffing
- Index pattern: `credential-*`
- Query: `event.category:authentication AND event.outcome:failure`
- Group by: `source.ip.keyword`
- Threshold: 10 events
- Severity: Medium
- Schedule: Every 5 minutes
- Additional look-back: 1 minute

### DNS Tunnelling
- Index pattern: `dns-*`
- Query: `event.category:network AND event.type:dns`
- Group by: `source.ip.keyword`
- Threshold: 10 events
- Severity: Medium
- Schedule: Every 5 minutes
- Additional look-back: 1 minute

### PowerShell Exploitation
- Index pattern: `powershell-*`
- Query: `event.category:process AND process.name:powershell.exe`
- Group by: `host.name.keyword`
- Threshold: 5 events
- Severity: Medium
- Schedule: Every 5 minutes
- Additional look-back: 1 minute

## Testing
Testing was performed with controlled synthetic events. Reserved documentation IP addresses such as `192.0.2.10` and `192.0.2.20` were used. No real credentials, real data exfiltration, or malicious PowerShell payloads were used.

All three detection rules successfully generated security alerts during testing.

## Results
| Technique | Detection | Threshold | Result |
|---|---|---:|---|
| Credential Stuffing | Repeated failed authentication | 10 | Alert generated |
| DNS Tunnelling | Repeated DNS activity | 10 | Alert generated |
| PowerShell Exploitation | Repeated PowerShell process execution | 5 | Alert generated |

## Limitations
- Synthetic events were used instead of production telemetry.
- Threshold-only detection can produce false positives.
- The rules are intended as a learning/SOC lab baseline rather than production-ready detections.

## Future Improvements
- Add EQL/event-correlation rules.
- Add richer ECS telemetry.
- Add allowlists and exception handling.
- Tune thresholds using baseline activity.
- Add automated response actions.
- Add additional ATT&CK-aligned detections.

## Evidence
Evidence screenshots are maintained separately from this repository/report and include rule configurations and successful alerts.

## Ethical Use
This project was performed in a controlled lab environment for defensive cybersecurity learning and detection engineering.

Evidence screenshots included:
- 01-powershell-exploitation-alert.jpg
- 02-dns-tunnelling-alert.jpg
- 03-credential-stuffing-alert.jpg
