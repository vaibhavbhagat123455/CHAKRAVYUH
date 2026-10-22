"""Command-line runner for the Member 3 scenario library."""

import argparse
import json
from pathlib import Path

from .scenario_engine import ScenarioEngine


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyse synthetic AI Chakravyuh scenarios")
    parser.add_argument("path", nargs="?", default="scenarios", help="scenario JSON file or directory")
    args = parser.parse_args()
    target = Path(args.path)
    engine = ScenarioEngine()
    if target.is_dir():
        output = engine.run_directory(target)
    else:
        scenario = engine.load(target)
        output = {scenario.scenario_id: engine.analyse(scenario).to_dict()}
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
