# Nova Bank SOC Incident Response Procedure (Fictional)

## Incident lifecycle in SentinelX
- NEW: created by correlation or promoted by an analyst; not yet triaged.
- IN_PROGRESS: an analyst owns the case and is investigating.
- CONTAINED: the threat can no longer spread or cause further harm (accounts disabled, hosts isolated, destinations blocked).
- RESOLVED: root cause identified, eradication and recovery complete, lessons learned documented.
- FALSE_POSITIVE: the activity was confirmed benign; tune the rule if appropriate.

## Severity and response targets
- Critical: acknowledge within 15 minutes, escalate to the SOC manager and CISO immediately.
- High: acknowledge within 1 hour.
- Medium: acknowledge within 4 business hours.
- Low: review within 2 business days.

## Triage checklist
1. Read the correlation explanation and confirm the evidence events.
2. Identify affected users, hosts and data.
3. Decide whether containment is required now.
4. Assign an owner and record notes in the case.
5. Escalate critical incidents via the on-call phone bridge.

## Communication
Technical details stay within the SOC case. Executive summaries for the CISO must state business impact, current status, and decisions required, without speculation. Never paste raw credentials, API keys or personal data into tickets or chat.

## Evidence handling
Preserve logs before remediation, record hashes of collected artefacts, and note who collected what and when (chain of custody).
