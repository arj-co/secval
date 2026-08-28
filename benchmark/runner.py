"""
SecVal Benchmark & Security Evaluation Runner.

Orchestrates live model or deterministic executions across security configurations,
computes empirical metrics from real run artifacts, and writes immutable manifests.
"""

from __future__ import annotations

import csv
import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.adapters.base import BaseAgentAdapter
from agents.adapters.deterministic import DeterministicAgentAdapter
from agents.runtime import AgentRunArtifact, AgentRuntime
from benchmark.factories.scenario_factory import generate_all_scenarios
from benchmark.metrics.calculator import MetricsCalculator
from security.gateway import SecValSecurityGateway


class BenchmarkRunner:
    """
    Executes scenarios through the AgentRuntime and SecVal Security Gateway.
    """

    def __init__(
        self,
        results_dir: Optional[Path] = None,
        gateway: Optional[SecValSecurityGateway] = None,
    ):
        self.repo_root = Path(__file__).resolve().parent.parent
        self.results_dir = results_dir or (self.repo_root / "benchmark" / "results")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.gateway = gateway or SecValSecurityGateway()
        self.runtime = AgentRuntime(gateway=self.gateway)
        self.metrics_calc = MetricsCalculator()

    def run_scenario(
        self,
        scenario: Dict[str, Any],
        configuration: str = "cedar_provenance",
        adapter: Optional[BaseAgentAdapter] = None,
        custom_policy: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute a single scenario run and return its serialized run artifact."""
        artifact = self.runtime.run_scenario(
            scenario=scenario,
            configuration=configuration,
            adapter=adapter,
            custom_policy_text=custom_policy,
        )
        return artifact.to_dict()

    def run_experiment(
        self,
        scenarios: Optional[List[Dict[str, Any]]] = None,
        configurations: Optional[List[str]] = None,
        adapter: Optional[BaseAgentAdapter] = None,
        repetitions: int = 1,
        experiment_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute complete comparative benchmark matrix across configurations.
        """
        exp_id = experiment_id or f"EXP-{uuid.uuid4().hex[:8].upper()}"
        active_scenarios = scenarios or generate_all_scenarios()
        active_configs = configurations or ["unprotected", "prompt_only", "cedar_only", "cedar_provenance"]
        active_adapter = adapter or DeterministicAgentAdapter()
        provider_info = active_adapter.get_provider_info()

        start_time = time.time()
        all_runs: List[Dict[str, Any]] = []

        for rep in range(1, repetitions + 1):
            for sc in active_scenarios:
                for cfg in active_configs:
                    run_dict = self.run_scenario(
                        scenario=sc,
                        configuration=cfg,
                        adapter=active_adapter,
                    )
                    run_dict["repetition"] = rep
                    all_runs.append(run_dict)

        # Compute empirical metrics
        metrics = self.metrics_calc.compute_metrics(all_runs)

        # Write immutable experiment artifacts
        manifest: Dict[str, Any] = {
            "experiment_id": exp_id,
            "timestamp": start_time,
            "git_commit": self._get_git_commit(),
            "model_id": provider_info.get("model_id", "unknown"),
            "provider": provider_info.get("provider", "unknown"),
            "execution_type": provider_info.get("execution_type", "deterministic_simulation"),
            "total_runs": len(all_runs),
            "repetitions": repetitions,
            "scenarios_count": len(active_scenarios),
            "configurations": active_configs,
            "metrics": metrics,
        }

        # Save files
        manifest_file = self.results_dir / f"{exp_id}_manifest.json"
        manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        runs_file = self.results_dir / f"{exp_id}_runs.json"
        runs_file.write_text(json.dumps(all_runs, indent=2), encoding="utf-8")

        # Also update latest pointer safely
        (self.results_dir / "latest_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        (self.results_dir / "latest_runs.json").write_text(json.dumps(all_runs, indent=2), encoding="utf-8")

        # Export CSV Summary
        csv_file = self.results_dir / f"{exp_id}_summary.csv"
        self._export_csv_summary(metrics, csv_file)

        return manifest

    def _get_git_commit(self) -> str:
        try:
            import subprocess
            res = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=str(self.repo_root),
                capture_output=True,
                text=True,
                timeout=2,
            )
            return res.stdout.strip() if res.returncode == 0 else "unknown"
        except Exception:
            return "unknown"

    def _export_csv_summary(self, metrics: Dict[str, Any], filepath: Path) -> None:
        configs = metrics.get("configurations", {})
        if not configs:
            return

        fieldnames = [
            "configuration",
            "total_runs",
            "malicious_scenarios",
            "benign_scenarios",
            "asr",
            "asr_ci_lower",
            "asr_ci_upper",
            "ltcr",
            "relative_asr_reduction",
            "false_positive_rate",
            "recall",
            "median_latency_ms",
            "p95_latency_ms",
        ]

        with open(filepath, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for cfg_name, data in configs.items():
                ci = data.get("asr_ci", [0.0, 0.0])
                writer.writerow({
                    "configuration": cfg_name,
                    "total_runs": data.get("total_runs", 0),
                    "malicious_scenarios": data.get("malicious_scenarios", 0),
                    "benign_scenarios": data.get("benign_scenarios", 0),
                    "asr": data.get("asr", 0.0),
                    "asr_ci_lower": ci[0] if len(ci) > 0 else 0.0,
                    "asr_ci_upper": ci[1] if len(ci) > 1 else 0.0,
                    "ltcr": data.get("ltcr", 0.0),
                    "relative_asr_reduction": data.get("relative_asr_reduction", 0.0),
                    "false_positive_rate": data.get("false_positive_rate", 0.0),
                    "recall": data.get("recall", 0.0),
                    "median_latency_ms": data.get("median_latency_ms", 0.0),
                    "p95_latency_ms": data.get("p95_latency_ms", 0.0),
                })


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SecVal Benchmark Runner")
    parser.add_argument("--smoke", action="store_true", help="Run 5-scenario smoke test")
    parser.add_argument("--all", action="store_true", help="Run full honest scenario suite")
    parser.add_argument("--reps", type=int, default=1, help="Repetitions per scenario")
    args = parser.parse_args()

    runner = BenchmarkRunner()
    scenarios = generate_all_scenarios()
    if args.smoke:
        scenarios = scenarios[:5]

    print(f"🚀 Running SecVal Benchmark ({len(scenarios)} scenarios, reps={args.reps})...")
    res = runner.run_experiment(scenarios=scenarios, repetitions=args.reps)
    print(f"✅ Finished! Manifest written to benchmark/results/{res['experiment_id']}_manifest.json")
