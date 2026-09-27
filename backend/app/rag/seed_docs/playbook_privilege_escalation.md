# Playbook: Privilege Escalation and Privileged Account Misuse

## Scope
Applies to SentinelX rules SX-003 (Suspicious Privileged Login) and SX-004 (Privilege Escalation). Relevant ATT&CK techniques: T1078 (Valid Accounts), T1098.007 (Account Manipulation: Additional Local or Domain Groups) and T1548.003 (Sudo and Sudo Caching).

## Why it matters
Membership in Administrators, Domain Admins or Enterprise Admins gives near-total control over systems or the whole domain. Attackers who obtain any account typically try to add it to a privileged group or steal administrator credentials.

## Investigation steps
1. Confirm whether a change request exists for the group modification. At Nova Bank all privileged group changes require an approved ticket in the ITSM system and are executed from NB-JUMP01.
2. Determine who performed the change and from which host. Changes executed from a user workstation rather than the jump host are policy violations.
3. Self-assignment (an account adding itself to a privileged group) is almost never legitimate.
4. Review everything the elevated account did afterwards: logons to servers, credential access, security tool changes, data access.
5. For suspicious privileged logins, validate against the on-call schedule and confirm with the administrator via a trusted channel.

## Containment
Remove the unauthorized membership, reset the account password, invalidate Kerberos tickets (reset krbtgt twice if domain compromise is suspected), and isolate hosts where the elevated account executed tools.

## False positives
Emergency (break-glass) access, onboarding automation and approved maintenance windows.
