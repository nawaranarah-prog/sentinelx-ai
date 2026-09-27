# Playbook: Data Collection and Exfiltration

## Scope
Applies to SentinelX rules SX-008 (Sensitive File Access) and SX-009 (Potential Data Exfiltration). Relevant ATT&CK techniques: T1039 (Data from Network Shared Drive), T1005 (Data from Local System), T1560.001 (Archive via Utility), T1048 / T1048.002 / T1048.003 (Exfiltration Over Alternative Protocol), T1567.002 (Exfiltration to Cloud Storage).

## Typical sequence
Collection (bulk reads of sensitive shares) → staging and compression (7-Zip or RAR, often password-protected) → transfer to an external server or consumer cloud storage.

## Investigation steps
1. List the files accessed and their classification. At Nova Bank anything under `\\NB-FS01\Finance\Treasury`, `\\NB-FS01\HR\Payroll` or files marked CONFIDENTIAL/RESTRICTED is classified as Restricted.
2. Quantify the outbound volume per destination and compare with the user's normal behavior (see the SentinelX anomaly analysis).
3. Identify the destination: ownership, reputation, whether it is a sanctioned service. Nova Bank sanctions only corporate OneDrive/SharePoint for file sharing; MEGA, Dropbox and WeTransfer are blocked by policy.
4. Look for archive creation between collection and transfer.

## Containment and notification
Block the destination, suspend the account if exfiltration is confirmed, preserve proxy and firewall logs, and inform the Data Protection Officer. Customer personal data or cardholder data exposure may trigger regulatory notification (GDPR 72-hour window, PCI DSS incident procedures).

## False positives
Nightly backups to internal backup servers (NB-BKP01) are large but internal and must not be treated as exfiltration. Large video-conference uploads and approved partner transfers are other benign causes.
