# ML and behavioral analytics (UEBA)

Code: [`backend/ml.py`](../backend/ml.py). Evaluation: [`simulation/mlEvaluation.py`](../simulation/mlEvaluation.py). Tests: [`tests/test_ml.py`](../tests/test_ml.py).

## What it does

Rules catch what someone thought of in advance. The ML engine looks for entities whose
behaviour is unusual, without being told what an attack looks like. It needs no labels.

```
logs ─> features per (entity, 10-minute window)
     ─> Isolation Forest score + out-of-range novelty  ─> anomaly score 0..1
     ─> baseline: deviation from the entity's own past ─> z-score
     ─> DBSCAN on the anomalies                        ─> coordinated clusters
     ─> composite risk score per entity (0..100)
     ─> "ml-detected" alerts in the shared Alert model
```

An entity is a source IP or a user name. Each gets one feature row per 10-minute window
in which it appears.

## Features

19 features per row. Counts are `log1p`-scaled before modelling, ratios are left as they are.

| Feature | Catches |
|---|---|
| `events`, `login_failed`, `login_success`, `fail_ratio` | brute force, password spraying |
| `distinct_users`, `distinct_source_ips` | one IP trying many accounts, one account used from many IPs |
| `distinct_hosts` | lateral movement |
| `distinct_dest_ips`, `distinct_dest_ports`, `firewall_drops` | port and network scans |
| `http_requests`, `http_error_ratio` | web attacks such as SQL injection probing |
| `dns_queries`, `avg_dns_length` | DNS tunneling |
| `bytes_out` | data exfiltration |
| `conn_regularity` | beaconing: 1.0 when connections to one destination are evenly spaced |
| `privileged_events`, `sudo_failed`, `ids_alerts` | privilege escalation, account creation |

Time of day is deliberately not a model feature: a model trained on a few hours would flag
every other hour. Unusual activity for a given entity is handled by the baseline instead.

## Isolation Forest, and its blind spot

One forest per entity type (200 trees, `contamination = 0.01`). The raw score is
`-score_samples`, the anomaly score from the original paper (about 0.5 = normal, towards 1 = isolated).

The first evaluation showed a real problem: **a port scan of 157 ports scored no higher than
the busiest normal host**, and was not flagged. The reason is structural. A tree only splits
inside the range of values it was trained on, so a value 50 times larger than anything seen
in training lands in the same leaf as the largest training value.

The fix is a second term, **novelty**: how far a row lies beyond the largest training value on
its most extreme feature, in units of that feature's spread. The final score is

```
anomaly_score = forest + (1 - forest) * (1 - exp(-novelty / 4))
is_anomaly    = forest says outlier  OR  novelty >= 2
```

So the forest finds unusual *combinations* inside the known range, and novelty finds values
outside it. Before this change only 4 of the 11 scenarios were detected in every run; after it, all 11 are.

## Explanation

Every anomaly lists up to three features that are above the 95th percentile of the training
data, largest excess first, with the value and the typical (median) value:

> Unusual behaviour for IP 198.51.100.186: firewall drops 136 (typical 0), events 137 (typical 1),
> distinct destination ports 136 (typical 0)

If no single feature is above the 95th percentile (an unusual combination), the features above
the median are listed instead.

## Baselines (UEBA)

Per entity, a running mean and variance of every feature (Welford's algorithm, so the baseline
is updated one window at a time and never recomputed from scratch). Each new window is compared
with the baseline built from **earlier windows only**, giving a z-score and the feature
responsible. No verdict is given until an entity has 3 windows of history. The spread is floored
so that a perfectly constant history does not turn a tiny change into a huge z-score.

This answers a different question from the forest: not "is this unusual for an IP?" but
"is this unusual for *this* IP?".

## DBSCAN: coordinated activity

Anomalous rows are clustered on their scaled features (`eps = 1.2`, `min_samples = 3`). A cluster
is kept only if it spans at least 3 distinct entities; the same entity being anomalous for several
windows is persistence, not coordination.

This is what catches the `distributed_brute_force` scenario: six addresses each making 8 to 12
attempts, too few for a per-IP threshold rule, but all six look alike at the same time.

## Risk score

One score per entity, 0 to 100:

| Component | Weight | Value |
|---|---|---|
| `ml` | 0.45 | highest anomaly score among its anomalous windows |
| `baseline` | 0.20 | largest z-score against its own history, capped at z = 10 |
| `rules` | 0.25 | severity of rule-style alerts on the entity |
| `coordinated` | 0.10 | 1 if it belongs to a DBSCAN cluster |

The weights are a judgement call, not learned. They are in `RISK_WEIGHTS`.

## Model versioning

`models/registry.json` lists every version with its training time, parameters, sample counts and
feature list; each version is one `joblib` file. Training creates a new version and activates it.
An older version can be re-activated (`POST /api/ml/models/{version}/activate`), and every alert
records the version that produced it.

## Evaluation

There are no labels in production, so the evaluation uses the generator, which knows which
entities it used for attacks. For each of 10 seeds: train on 4 hours of normal-only traffic,
then score a separate hour containing all 11 attack scenarios mixed into normal traffic.

```bash
python simulation/mlEvaluation.py --seeds 10
```

| Scenario | Detected (10 runs) |
|---|---|
| brute_force | 10 |
| distributed_brute_force | 10 (clustered as coordinated in all 10) |
| port_scan | 10 |
| sql_injection | 10 |
| privilege_escalation | 10 |
| account_takeover | 10 |
| lateral_movement | 10 |
| beaconing | 10 |
| data_exfiltration | 10 |
| dns_tunneling | 10 |
| cloud_takeover | 10 |

**False-positive rate: 48 of 4,211 benign IP windows, 1.14%.** On average 7.6 of the 10
highest risk scores belong to entities involved in an attack.

Results move a little between runs because window boundaries depend on the start time: across
runs the detection count was between 106 and 110 of 110 (lateral movement and beaconing were
each missed in up to 2 runs), and the false-positive rate between 1.1% and 1.3%.

### What these numbers do not show

- **The data is synthetic.** Normal traffic is far more regular than a real network, and the
  attacks are loud. Real false-positive rates will be higher and real detection lower.
- **No false-positive rate for users.** The password-spraying scenarios touch every user account,
  so there are no uninvolved users left to measure on.
- **Typical false positives** are internal workstations that happen to be busy in one window
  (a few DNS queries plus a login), and accounts that are being guessed at by an attacker
  elsewhere, which is arguably correct.
- **Contamination trade-off** (5 seeds): 0.005 gave 2.95% false positives, 0.01 gave 3.51%,
  0.02 gave 4.65% under an earlier, stricter labelling that counted guessed-at accounts as benign.
  The detection count was the same for all three, so the lowest practical value is preferable;
  0.01 is the default.
- **Training on contaminated data.** In production the training period may contain attacks.
  A repeated attack would then look normal. Retrain on periods known to be quiet, and keep old
  versions for comparison.

## Running it

```bash
python backend/ml.py train --hours 24     # new model version from stored logs
python backend/ml.py detect --hours 1     # score recent logs, write alerts and risk scores
python backend/ml.py models               # list versions
```

The API runs detection every 60 seconds once a model exists (`ML_DETECT_INTERVAL`, 0 disables it).
Endpoints: `POST /api/ml/train`, `POST /api/ml/detect`, `GET /api/ml/models`,
`GET /api/ml/anomalies`, `GET /api/ml/entities`, `GET /api/entities/{ip|user}/{id}`.
