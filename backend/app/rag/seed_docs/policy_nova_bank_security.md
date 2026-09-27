# Nova Bank Information Security Policy Extract (Fictional Demo Content)

Nova Bank is a fictional organization used for SentinelX demonstrations. This policy text is synthetic.

## Access control
- Privileged administration must be performed from the jump host NB-JUMP01 using named admin accounts (prefix `adm.`).
- Privileged group changes require an approved change ticket.
- Administrator logins between 22:00 and 06:00 UTC require an on-call justification.
- Multi-factor authentication is mandatory for VPN access.

## Data classification
- Restricted: customer account data, cardholder data, payroll, SWIFT and wire-transfer records, board and M&A material.
- Confidential: internal financial reports, budgets, vendor contracts.
- Internal: procedures, templates, training material.
Restricted data may only be stored on NB-FS01 and NB-SQL01 and must never be transferred to personal or consumer cloud storage.

## Acceptable use
Sanctioned external file sharing: corporate OneDrive / SharePoint only. Consumer services such as MEGA, Dropbox and WeTransfer are prohibited.

## Critical assets
NB-DC01 (domain controller), NB-SQL01 (core banking database), NB-FS01 (file server holding Finance and HR shares), NB-VPN01 (remote access gateway).

## Monitoring
All authentication, process, file-access and network telemetry is forwarded to the SOC. Employees are informed that activity on bank systems is monitored.
