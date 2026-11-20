# Observed detection and tamper metrics

Synthetic events evaluated: 1530. DuckDB query wall time: 36.1 ms.

| Rule | TP | FP alerts | FN | Precision | Recall | Median event-time latency | FP/1k events |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| impossible_travel | 3 | 0 | 0 | 100.0% | 100.0% | 900.0 s | 0.000 |
| mfa_fatigue | 3 | 0 | 0 | 100.0% | 100.0% | 180.0 s | 0.000 |
| password_spray | 3 | 0 | 3 | 100.0% | 50.0% | 420.0 s | 0.000 |
| scope_escalation | 3 | 0 | 0 | 100.0% | 100.0% | 0.0 s | 0.000 |
| token_replay | 3 | 0 | 0 | 100.0% | 100.0% | 60.0 s | 0.000 |

Tamper attempts rejected: 6/6.
