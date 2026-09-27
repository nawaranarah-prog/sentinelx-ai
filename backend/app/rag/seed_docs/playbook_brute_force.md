# Playbook: Brute Force and Password Spraying

## Purpose
Guide analysts responding to SentinelX rules SX-001 (Brute Force Authentication) and SX-002 (Successful Login After Repeated Failures). Maps to MITRE ATT&CK T1110 (Brute Force), T1110.001 (Password Guessing), T1110.003 (Password Spraying) and T1078 (Valid Accounts).

## Triage
1. Identify the source address. Internal sources usually indicate a misconfigured client or a compromised internal host; external sources indicate internet-facing attack traffic against VPN, webmail or SSO.
2. Distinguish guessing from spraying. Guessing = many attempts against one account. Spraying = one or two attempts against many accounts, designed to stay below lockout thresholds.
3. Check for any successful authentication from the same source or for the targeted accounts within 30 minutes after the failures. A success converts the alert from "attempted" to "likely compromised".
4. Check the user agent. Scripted clients (python-requests, Go-http-client, curl) against interactive login portals are strong indicators of automation.

## Containment
- If a success followed the failures: disable or reset the account, revoke refresh tokens and VPN sessions, and require MFA re-registration.
- Block the source address at the perimeter (VPN concentrator, WAF) for at least 24 hours.
- For spraying, force password resets for targeted accounts that use weak or seasonal passwords.

## Evidence to preserve
VPN / identity-provider authentication logs, the full list of targeted accounts, firewall logs for the source address, and any subsequent session activity for affected accounts.

## Common false positives
Users with expired passwords cached on mobile devices, service accounts after password rotation, and authorized penetration tests. False positives rarely involve dozens of failures in minutes from an external address.
