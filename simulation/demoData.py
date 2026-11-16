"""
Demo data
Resets the database and loads a ready-to-show dataset: 4 hours of normal
traffic, then the last hour with every attack scenario. Trains a model on the
normal part and runs detection, so the dashboard has alerts, anomalies and
risk scores straight away.

    python simulation/demoData.py            # WARNING: deletes the stored logs first
"""

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "simulation"))

from logGenerator import LogGenerator  # noqa: E402

from backend import dataBase, ingestion, ml  # noqa: E402


def load(seed: int = 42) -> dict:
    db = dataBase.get_db()
    if db is None:
        raise SystemExit("MongoDB is not reachable")
    ingestion.clear_logs()
    for name in (dataBase.ALERTS_COLLECTION, ml.RISK_COLLECTION, ml.BASELINES_COLLECTION):
        db[name].delete_many({})

    start = datetime.now(timezone.utc) - timedelta(hours=5)
    normal = LogGenerator(seed=seed, start=start, duration_minutes=240)
    normal.generate(normal=3200, scenarios=[])
    for source, lines in normal.by_source().items():
        ingestion.ingest_batch(lines, source)
    model = ml.train_from_db(hours=24, note="demo: 4 hours of normal traffic")

    attack = LogGenerator(seed=seed + 1, start=start + timedelta(hours=4), duration_minutes=60)
    attack.workstations, attack.visitors = normal.workstations, normal.visitors
    truth = attack.generate(normal=800)
    for source, lines in attack.by_source().items():
        ingestion.ingest_batch(lines, source)
    summary = ml.detect(hours=1.2)
    return {"logs": ingestion.get_log_count(), "model": model["version"],
            "scenarios": [item["scenario"] for item in truth], "detection": summary}


def main():
    parser = argparse.ArgumentParser(description="Reset the database and load demo data")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    result = load(args.seed)
    print(f"✓ {result['logs']} logs loaded, model {result['model']} trained")
    print(f"✓ {len(result['scenarios'])} attack scenarios in the last hour")
    print(f"✓ detection: {result['detection']['anomalies']} anomalies, "
          f"{result['detection']['clusters']} coordinated clusters")


if __name__ == "__main__":
    main()
