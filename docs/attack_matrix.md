# MITRE ATT&CK coverage (static reference)

| Rule | Technique ID | Name |
|---|---|---|
| Repeated 4625 | T1110.001 | Brute Force: Password Guessing |
| Pass-the-Hash pattern | T1550.002 | Use Alternate Auth Material |
| Kerberoasting (4769) | T1558.003 | Steal or Forge Kerberos Tickets |
| Orphaned privileged session | T1078 | Valid Accounts |
| Log clearing (1102, 104) | T1070 | Indicator Removal |

The live catalogue in `src/report/mitre_mapper.py` also covers
credential stuffing, AS-REP roasting, RDP, account creation, group
modification, scheduled tasks, services, timestomping, and PowerShell.
