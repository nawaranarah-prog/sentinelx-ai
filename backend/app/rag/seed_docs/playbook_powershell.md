# Playbook: Suspicious PowerShell and Malicious Execution

## Scope
Applies to SentinelX rules SX-005 (Suspicious PowerShell) and SX-007 (Suspicious Process Execution). Relevant ATT&CK techniques: T1059.001 (PowerShell), T1027.010 (Command Obfuscation), T1105 (Ingress Tool Transfer), T1564.003 (Hidden Window), T1562.001 (Disable or Modify Tools), T1003.001 (LSASS Memory), T1053.005 (Scheduled Task).

## Indicators of malicious PowerShell
- `-EncodedCommand` / `-enc` followed by Base64 text: decode it (UTF-16LE) and review the real command.
- Download cradles: `DownloadString`, `Invoke-WebRequest`, `Net.WebClient`, `Start-BitsTransfer`.
- `IEX` / `Invoke-Expression` executing downloaded content in memory.
- Hidden windows (`-w hidden`), `-NoProfile`, `-NonInteractive`, `-ExecutionPolicy Bypass` in combination.
- PowerShell spawned by Office applications (WINWORD.EXE, EXCEL.EXE, OUTLOOK.EXE) usually indicates a malicious macro.

## Investigation steps
1. Decode the command and identify any URL or IP contacted; search threat intelligence for it.
2. Establish the parent process chain and the document or email that started it.
3. Check for persistence created shortly afterwards (scheduled tasks, Run keys, new services).
4. Check whether other hosts executed the same command line or contacted the same address.

## Containment
Isolate the endpoint through EDR, block the remote address and domain, collect memory before rebooting, and reset credentials used on the host if credential access tools were seen.

## False positives
Software deployment tools (SCCM, Intune) and some administrative scripts legitimately use encoded commands; these run under service accounts from known management servers.
