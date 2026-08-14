# Event ID reference

WinLogin Forensics parses the following Windows Event IDs. Field-level
extraction is implemented in `src/parsers/evtx_parser.py`.

## Authentication & session

| Event ID | Channel | Description |
|---|---|---|
| 4624 | Security | Successful logon |
| 4625 | Security | Failed logon |
| 4634 | Security | Account logoff |
| 4647 | Security | User-initiated logoff |
| 4648 | Security | Explicit credential use |
| 4672 | Security | Special privileges assigned |
| 4778 / 4779 | Security | RDP reconnect / disconnect |
| 4800 / 4801 | Security | Workstation lock / unlock |

Contract DataFrame columns: `EventID, TimeCreated, SubjectUserName,
TargetUserName, TargetLogonId, LogonType, IpAddress, IpPort,
WorkstationName, Status, raw_xml`.

## Kerberos / NTLM

4768 TGT requested · 4769 service ticket (RC4 `0x17` = Kerberoasting) ·
4771 pre-auth failed · 4776 NTLM validation.

## Account management

4720 create · 4722 enable · 4723 password change · 4724 reset ·
4725 disable · 4726 delete · 4728 / 4732 / 4756 group add ·
4740 lockout · 4767 unlock.

## Persistence & anti-forensic

4698 scheduled task · 7045 new service · 1102 Security log cleared ·
104 System log cleared · 4616 system time changed.

## Sysmon (optional)

1 process creation · 3 network · 11 file create · 22 DNS query.

## PowerShell (optional)

4103 module logging · 4104 script block logging (obfuscation markers:
`base64`, `Invoke-Expression`, `[char]`, `-enc`).
