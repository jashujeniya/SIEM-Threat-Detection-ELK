DNS Tunnelling Detection
Rule type: Threshold
Severity: Medium
Detection Logic
Detect repeated DNS activity originating from the same source that may indicate tunnelling-like behavior.
Index pattern: dns-*
KQL: event.category:network AND event.type:dns
Group by: source.ip.keyword
Threshold: 10
Schedule: Every 5 minutes
Additional look-back: 1 minute
Test
Controlled synthetic DNS events were generated from the documentation IP 192.0.2.20, using synthetic query names under .example.test.
Result
The rule successfully generated a Medium-severity security alert.
