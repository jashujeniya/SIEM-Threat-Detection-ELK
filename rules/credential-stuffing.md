Credential Stuffing Detection
Rule type: Threshold
Severity: Medium
Detection Logic
Detect repeated failed authentication attempts from the same source IP in a short period.
Index pattern: credential-*
KQL: event.category:authentication AND event.outcome:failure
Group by: source.ip.keyword
Threshold: 10
Schedule: Every 5 minutes
Additional look-back: 1 minute
Test
Controlled synthetic failed-authentication events were generated from the documentation IP 192.0.2.10.
Result
The rule successfully generated a Medium-severity security alert.

