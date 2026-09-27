# SentinelX Event Schema

| Field | Type | Description | Accepted aliases |
|---|---|---|---|
| event_id | string | Unique ID from the source system. Used for de-duplication; generated if absent. | event_id, eventid_uid, uid, record_id, recordid, event_uid, log_id, id, event.id |
| timestamp | datetime | REQUIRED. ISO 8601, 'YYYY-MM-DD HH:MM:SS', or epoch seconds/milliseconds. Stored as UTC. | timestamp, @timestamp, time, datetime, date, event_time, eventtime, ts, timecreated, _time, time_generated, timegenerated, created_at, event.created |
| event_type | enum | authentication | process | file | network | privilege | other. Inferred when missing. | event_type, eventtype, type, category, event_category, log_type, event.category, event.type, activity |
| user | string | Account name. DOMAIN\user is split; stored lower-case. | user, username, user_name, account, account_name, accountname, targetusername, user.name, userprincipalname, upn, actor, principal, subject, login, uid_name, subjectusername, src_user, user_id |
| source_ip | ip | Originating IP address (IPv4/IPv6). Invalid values are dropped with a warning. | source_ip, src_ip, srcip, src, client_ip, clientip, sourceip, source_address, src_addr, ipaddress, id.orig_h, remote_ip, remote_addr, sourceipaddress, source.ip, client.ip, callerip, ip |
| destination_ip | ip | Destination IP address. | destination_ip, dst_ip, dstip, dest_ip, destip, dst, dest, destination_address, dst_addr, id.resp_h, server_ip, destinationip, destination.ip, server.ip, target_ip |
| host | string | Hostname where the event occurred. Stored upper-case. | host, hostname, host_name, computer, computername, device, device_name, devicename, endpoint, machine, workstation, workstationname, host.name, agent.hostname, system |
| process | string | Process image name, e.g. powershell.exe. | process, process_name, processname, image, exe, newprocessname, program, process.name, process.executable, app, application |
| command | string | Full command line or script block text. | command, command_line, commandline, cmd, cmdline, scriptblocktext, process.command_line, process_command_line, query |
| action | string | What happened: login, logout, process_start, file_read, group_add, upload... | action, event_action, operation, event.action, activity_name, verb, method |
| status | enum | success | failure (synonyms such as failed, denied, ok, allowed are normalized). | status, outcome, result, event_outcome, event.outcome, auth_result, disposition, success |
| severity | enum | info | low | medium | high | critical (numeric 0-10 and syslog words accepted). | severity, level, priority, risk, log_level, event.severity, severity_level |
| bytes | integer | Bytes transferred outbound. Accepts suffixes like 1.5MB. | bytes, bytes_out, bytes_sent, sent_bytes, orig_bytes, bytes_transferred, size, network.bytes, source.bytes, out_bytes, sentbytes, data_size, transfer_bytes |
| resource | string | File path, share, URL, domain or group name the action targeted. | resource, file, file_path, filepath, filename, path, object, objectname, object_name, target, url, domain, file.path, url.full, destination.domain, share, sharename, group, group_name, targetsid_group, request |
| source | string | Log source / product name. | source, log_source, logsource, provider, product, sourcetype, source_type, channel, event.dataset, event.module, vendor |
| metadata | object | Every unmapped field is preserved in metadata; the raw original row is also stored. |  |

## Windows Security event codes understood

- 4624: {'event_type': 'authentication', 'action': 'login', 'status': 'success'}
- 4625: {'event_type': 'authentication', 'action': 'login', 'status': 'failure'}
- 4634: {'event_type': 'authentication', 'action': 'logout', 'status': 'success'}
- 4647: {'event_type': 'authentication', 'action': 'logout', 'status': 'success'}
- 4648: {'event_type': 'authentication', 'action': 'explicit_credential_login', 'status': 'success'}
- 4672: {'event_type': 'authentication', 'action': 'special_privileges_assigned', 'status': 'success', 'privileged_logon': True}
- 4740: {'event_type': 'authentication', 'action': 'account_lockout', 'status': 'failure'}
- 4688: {'event_type': 'process', 'action': 'process_start'}
- 4104: {'event_type': 'process', 'action': 'script_block', 'process': 'powershell.exe'}
- 4663: {'event_type': 'file', 'action': 'file_access'}
- 5145: {'event_type': 'file', 'action': 'share_access'}
- 5156: {'event_type': 'network', 'action': 'connection'}
- 4720: {'event_type': 'privilege', 'action': 'account_created'}
- 4728: {'event_type': 'privilege', 'action': 'group_add'}
- 4732: {'event_type': 'privilege', 'action': 'group_add'}
- 4756: {'event_type': 'privilege', 'action': 'group_add'}