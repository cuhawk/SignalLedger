# Observed detection and tamper metrics

Synthetic events evaluated: 1539. DuckDB query wall time: 133.3 ms.

Distributed slow-spray recall on the same labeled incidents: 0/3 with the single-source rule, 3/3 with the distributed rule.
Benign baseline false positives: 0/1452 events (0.000 alerts per 1,000 events).

| Rule | Recall | Median event-time latency | FP/1k events |
| --- | ---: | ---: | ---: |
| distributed_password_spray | 100.0% | 4200.0 s | 0.000 |
| impossible_travel | 100.0% | 900.0 s | 0.000 |
| mfa_fatigue | 100.0% | 180.0 s | 0.000 |
| password_spray | 100.0% | 420.0 s | 0.000 |
| scope_escalation | 100.0% | 0.0 s | 0.000 |
| token_replay | 100.0% | 60.0 s | 0.000 |

Signed-window tamper attempts rejected: 6/6.
Consistency tamper, truncation and rollback cases rejected: 10/10.
Consistency prefix matrix and RFC 6962 proof-vector test: passed.
