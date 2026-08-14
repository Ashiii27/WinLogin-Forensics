# Ground-truth methodology

Each file in `evaluation/samples/` is a labeled mini-scenario:

| Sample | Technique | How it is labeled |
|---|---|---|
| `brute_force_t1110.json` | T1110.001 | ≥5× 4625 from one IP inside 5 minutes |
| `pass_the_hash_t1550.json` | T1550.002 | Presence of 4648 |
| `kerberoasting_t1558.json` | T1558.003 | 4769 with `TicketEncryptionType=0x17` |
| `orphaned_privileged_t1078.json` | T1078 / T1078.002 | 4624+4672 with no 4634/4647 |
| `benign_baseline.json` | — | Closed interactive sessions, no findings expected |
| `closed_session_ok.json` | — | Closed RDP session, no findings expected |

`evaluation/run_evaluation.py` predicts technique IDs with the session
correlator + rule detector, compares them to `ground_truth`, and reports
Precision / Recall / F1 as mean ± std over 8 stratified splits.
