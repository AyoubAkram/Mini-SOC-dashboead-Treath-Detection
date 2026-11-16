"""
ML evaluation on synthetic data with known ground truth.

Trains the Isolation Forest on normal-only traffic, scores a separate dataset
that contains the attack scenarios, and reports which attacks were flagged and
the false-positive rate on entities that took no part in any attack.

    python simulation/mlEvaluation.py
    python simulation/mlEvaluation.py --contamination 0.02 --seeds 5 --json
"""

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Set

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "simulation"))

from logGenerator import LogGenerator  # noqa: E402

from backend import ingestion, ml  # noqa: E402


def to_logs(generator: LogGenerator) -> List[dict]:
    """Run generated lines through the real parsers, as ingestion would."""
    logs = []
    for source, lines in generator.by_source().items():
        entries, _ = ingestion.normalize(lines, source)
        logs += [entry.to_document() for entry in entries]
    return logs


def attack_entities(truth: List[dict]) -> Dict[str, Dict[str, Set[str]]]:
    """scenario -> {'ip': {...}, 'user': {...}} taken from the generator's ground truth."""
    result = {}
    for item in truth:
        ips = set(item.get("source_ips", []))
        if item.get("source_ip"):
            ips.add(item["source_ip"])
        users = {item["username"]} if item.get("username") else set()
        users |= set(item.get("target_users", []))  # accounts the attacker guessed at
        if item.get("created_account"):
            users.add(item["created_account"])
        result[item["scenario"]] = {"ip": ips, "user": users}
    return result


def evaluate(seed: int = 1, contamination: float = 0.01, normal: int = 800) -> dict:
    start = datetime.now(timezone.utc) - timedelta(hours=5)
    # 4 hours of normal traffic to learn from, then 1 hour containing the attacks
    training = LogGenerator(seed=seed, start=start, duration_minutes=240)
    training.generate(normal=normal * 4, scenarios=[])
    bundle = ml.train({t: ml.extract_features(to_logs(training), t) for t in ml.ENTITY_TYPES},
                      contamination=contamination)
    bundle["version"] = "evaluation"

    test = LogGenerator(seed=seed + 1000, start=start + timedelta(hours=4), duration_minutes=60)
    # same network: the people and visitors seen in training are still there
    test.workstations, test.visitors = training.workstations, training.visitors
    truth = attack_entities(test.generate(normal=normal))
    result = ml.analyse(bundle, to_logs(test))

    malicious = {t: set().union(*(s[t] for s in truth.values())) for t in ml.ENTITY_TYPES}
    flagged = {t: {r["entity"] for r in result["anomalies"] if r["entity_type"] == t}
               for t in ml.ENTITY_TYPES}
    coordinated = {e for c in result["clusters"] for e in c["entities"]}

    scenarios = {}
    for name, entities in truth.items():
        hits = {t: sorted(entities[t] & flagged[t]) for t in ml.ENTITY_TYPES}
        scenarios[name] = {"detected": bool(hits["ip"] or hits["user"]),
                           "flagged_entities": hits["ip"] + hits["user"],
                           "coordinated_cluster": bool(entities["ip"] & coordinated)}

    benign = [r for r in result["rows"] if r["entity"] not in malicious[r["entity_type"]]]
    false_positives = [r for r in benign if r["is_anomaly"]]
    by_type = {t: {"benign_windows": sum(r["entity_type"] == t for r in benign),
                   "false_positives": sum(r["entity_type"] == t for r in false_positives)}
               for t in ml.ENTITY_TYPES}
    return {
        "seed": seed, "contamination": contamination,
        "training_windows": bundle["samples"], "test_windows": len(result["rows"]),
        "scenarios": scenarios,
        "detected": sum(s["detected"] for s in scenarios.values()), "total": len(scenarios),
        "benign_windows": len(benign), "false_positives": len(false_positives),
        "by_entity_type": by_type,
        "false_positive_rate": round(len(false_positives) / len(benign), 4) if benign else 0.0,
        "false_positive_examples": [
            {"entity": r["entity"], "score": r["anomaly_score"],
             "why": [c["label"] for c in r["explanation"]]} for r in false_positives[:5]],
        "top_risk": [{"entity": r["entity"], "risk": r["risk_score"],
                      "attacker": r["entity"] in malicious[r["entity_type"]]}
                     for r in result["risk"][:10]],
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate the ML engine on synthetic attacks")
    parser.add_argument("--seeds", type=int, default=5, help="number of independent runs")
    parser.add_argument("--contamination", type=float, default=0.01)
    parser.add_argument("--json", action="store_true", help="print the raw results")
    args = parser.parse_args()

    runs = [evaluate(seed, args.contamination) for seed in range(1, args.seeds + 1)]
    if args.json:
        print(json.dumps(runs, indent=2))
        return
    names = list(runs[0]["scenarios"])
    print(f"{'scenario':26} detected in {args.seeds} runs")
    for name in names:
        hits = sum(run["scenarios"][name]["detected"] for run in runs)
        cluster = sum(run["scenarios"][name]["coordinated_cluster"] for run in runs)
        print(f"{name:26} {hits}/{args.seeds}" + (f"   (clustered as coordinated: {cluster})" if cluster else ""))
    benign = sum(run["benign_windows"] for run in runs)
    false_positives = sum(run["false_positives"] for run in runs)
    print(f"\nfalse positives: {false_positives} of {benign} benign entity windows "
          f"({100 * false_positives / benign:.2f}%)")
    for entity_type in ml.ENTITY_TYPES:
        n = sum(run["by_entity_type"][entity_type]["benign_windows"] for run in runs)
        fp = sum(run["by_entity_type"][entity_type]["false_positives"] for run in runs)
        print(f"  {entity_type:5} {fp} of {n}" + (f" ({100 * fp / n:.2f}%)" if n else ""))
    top = sum(sum(e["attacker"] for e in run["top_risk"]) for run in runs)
    print(f"attackers among the 10 highest risk scores: {top / len(runs):.1f} on average")


if __name__ == "__main__":
    main()
