#!/usr/bin/env python3
"""Run one SABLE-HE stage inside a Slurm job (or locally with --local).

Writes, for every stage:
  outputs/<stage>/<commit12>/FINAL_STATUS.json   machine-readable status and checks
  outputs/<stage>/<commit12>/SUMMARY.md          human-readable report
  outputs/<stage>/LATEST.json                    pointer to the latest run
  results/slurm_jobs/<job_id>/report/SUMMARY.md  per-job copy
A stage PASSES only if every predeclared check passes, not merely because
the process exited with code 0.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import traceback
from pathlib import Path

ORDER = ["setup", "smoke", "pilot", "crypto", "fl", "report"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--code", required=True)
    ap.add_argument("--stage", required=True, choices=ORDER)
    ap.add_argument("--workers", type=int, default=int(os.environ.get("SLURM_CPUS_PER_TASK", os.cpu_count() or 1)))
    ap.add_argument("--mem-gb", type=float, default=None)
    ap.add_argument("--local", action="store_true", help="local test run without Slurm")
    args = ap.parse_args()

    code = Path(args.code).resolve()
    project = Path(args.project).resolve()
    sys.path.insert(0, str(code))
    sys.path.insert(0, str(code / "src"))
    os.environ.setdefault("SABLE_DATA_DIR", str(project / "data"))

    from evaluation.common import atomic_write_json, env_info, read_json

    commit = (code / "COMMIT").read_text().strip() if (code / "COMMIT").exists() else "local-" + time.strftime("%Y%m%d%H%M%S")
    out_dir = project / "outputs" / args.stage / commit[:12]
    out_dir.mkdir(parents=True, exist_ok=True)
    job_id = os.environ.get("SLURM_JOB_ID", "local")
    mem_gb = args.mem_gb
    if mem_gb is None:
        mem_mb = os.environ.get("SLURM_MEM_PER_NODE")
        mem_gb = float(mem_mb) / 1024 * 0.9 if mem_mb else 8.0
    started = time.time()
    status: dict = {"stage": args.stage, "commit": commit, "job_id": job_id, "started": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "workers": args.workers, "memory_budget_gb": mem_gb, "checks": [], "scientific_status": "FAILED"}
    atomic_write_json(out_dir / "RUN_CONFIG.json", {"args": vars(args), "commit": commit, "env": env_info()})
    print(f"[stage] {args.stage} commit={commit[:12]} job={job_id} workers={args.workers} mem_budget={mem_gb:.0f}GB", flush=True)

    try:
        if args.stage == "setup":
            status.update(run_setup(project, code, out_dir))
        elif args.stage == "report":
            from evaluation.analyze import build_report

            rep = build_report(project, commit)
            status["checks"] = rep["checks"]
            status["report_dir"] = rep["out_dir"]
        else:
            from evaluation import registry
            from evaluation.runner import run_tasks

            tasks = registry.stage_tasks(args.stage)
            manifest = hashlib.sha256(json.dumps(tasks, sort_keys=True).encode()).hexdigest()[:16]
            atomic_write_json(out_dir / "TASKS.json", {"manifest_hash": manifest, "tasks": tasks})
            results = run_tasks(tasks, out_dir, workers=args.workers, mem_gb=mem_gb)
            projection = registry.pilot_projection(results, args.workers, mem_gb) if args.stage == "pilot" else None
            status["checks"] = registry.stage_checks(args.stage, tasks, results, projection=projection)
            status["tasks_total"] = len(tasks)
            status["tasks_ok"] = sum(1 for r in results if r.get("status") == "ok")
            status["tasks_failed"] = [{"id": r["id"], "error": r.get("error")} for r in results if r.get("status") != "ok"][:50]
            status["task_seconds_total"] = sum(r.get("seconds", 0.0) for r in results)
            if projection:
                status["projection"] = projection
        status["scientific_status"] = "PASSED" if status["checks"] and all(c["passed"] for c in status["checks"]) else "FAILED"
    except Exception as exc:  # noqa: BLE001
        status["error"] = f"{type(exc).__name__}: {exc}"
        status["traceback"] = traceback.format_exc()
        status["checks"].append({"name": "stage completed without exception", "passed": False, "detail": status["error"]})
        print(status["traceback"], flush=True)
    finally:
        status["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
        status["runtime_hours"] = (time.time() - started) / 3600
        idx = ORDER.index(args.stage)
        status["next_stage"] = ORDER[idx + 1] if status["scientific_status"] == "PASSED" and idx + 1 < len(ORDER) else "fix and rerun " + args.stage
        status["out_dir"] = str(out_dir)
        atomic_write_json(out_dir / "FINAL_STATUS.json", status)
        atomic_write_json(project / "outputs" / args.stage / "LATEST.json", status)
        summary = render_summary(status)
        (out_dir / "SUMMARY.md").write_text(summary)
        job_dir = project / "results" / "slurm_jobs" / job_id / "report"
        job_dir.mkdir(parents=True, exist_ok=True)
        (job_dir / "SUMMARY.md").write_text(summary)
        print(summary, flush=True)
    return 0 if status["scientific_status"] == "PASSED" else 1


def run_setup(project: Path, code: Path, out_dir: Path) -> dict:
    from evaluation.aggregation import available_backends
    from evaluation.common import atomic_write_json, package_versions

    checks = []
    def chk(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(ok), "detail": detail})
        print(f"[setup] {'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)

    chk("python >= 3.10", sys.version_info >= (3, 10), sys.version.split()[0])
    vers = package_versions()
    missing = [k for k, v in vers.items() if str(v).startswith("unavailable")]
    chk("required packages import", not missing, f"missing: {missing}" if missing else json.dumps(vers))
    av = available_backends()
    chk("all aggregation backends available", all(v == "ok" for v in av.values()), json.dumps(av))

    from evaluation.fl import data as fdata

    for name in ("mnist", "fmnist"):
        try:
            fdata.download(name, project / "data")
            xtr, ytr, xte, yte = fdata.load(name)
            ok = xtr.shape == (60000, 1, 28, 28) and xte.shape == (10000, 1, 28, 28)
            chk(f"dataset {name}", ok, f"train {xtr.shape} test {xte.shape}")
        except Exception as exc:  # noqa: BLE001
            chk(f"dataset {name}", False, f"{type(exc).__name__}: {exc} (compute-node internet may be blocked; see docs/HPC_RUNBOOK.md)")

    t = subprocess.run([sys.executable, "-m", "pytest", "-q", "-o", "addopts=", "-p", "no:warnings", str(code / "tests")],
                       cwd=str(code), capture_output=True, text=True, timeout=3600)
    tail = (t.stdout.strip().splitlines() or [""])[-1]
    chk("package unit tests", t.returncode == 0, tail)

    res = hpc_resources()
    atomic_write_json(project / "outputs" / "setup" / "hpc_resources.json", res)
    chk("Slurm resource query", bool(res.get("partitions")), json.dumps(res.get("partitions", {}))[:300])

    req = (code / "scripts" / "hpc" / "requirements-hpc.txt").read_bytes()
    return {"checks": checks, "requirements_hash": hashlib.sha256(req).hexdigest()[:16], "packages": vers, "backends": av}


def hpc_resources() -> dict:
    try:
        out = subprocess.check_output(["sinfo", "-h", "-N", "-o", "%P|%c|%m|%l"], text=True, timeout=60)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
    parts: dict[str, dict] = {}
    for line in out.splitlines():
        try:
            p, c, m, lim = line.strip().split("|")
        except ValueError:
            continue
        p = p.rstrip("*")
        d = parts.setdefault(p, {"min_cpus": 10**9, "min_mem_mb": 10**12, "max_mem_mb": 0, "time_limit": lim, "nodes": 0})
        d["min_cpus"] = min(d["min_cpus"], int(c))
        d["min_mem_mb"] = min(d["min_mem_mb"], int(float(m)))
        d["max_mem_mb"] = max(d["max_mem_mb"], int(float(m)))
        d["nodes"] += 1
    longq = parts.get("longq", {})
    return {"partitions": parts, "longq_min_node_mem_mb": longq.get("min_mem_mb")}


def render_summary(st: dict) -> str:
    lines = [
        f"# SABLE-HE stage report: {st['stage']}",
        "",
        f"- Job ID: {st['job_id']}",
        f"- Code commit: {st['commit']}",
        f"- Stage: {st['stage']}",
        f"- Started / finished: {st.get('started')} / {st.get('finished')}",
        f"- Runtime: {st.get('runtime_hours', 0):.2f} h",
        f"- CPUs (workers) / memory budget: {st.get('workers')} / {st.get('memory_budget_gb', 0):.0f} GB",
        f"- Tasks: {st.get('tasks_ok', '-')} ok of {st.get('tasks_total', '-')}",
        f"- **Scientific status: {st['scientific_status']}**",
        f"- Next permitted stage: {st.get('next_stage')}",
        "",
        "## Pass/fail criteria",
        "",
        "| check | result | detail |",
        "|---|---|---|",
    ]
    for c in st.get("checks", []):
        detail = " ".join(str(c["detail"]).replace("|", "/").split())[:240]
        lines.append(f"| {c['name']} | {'PASS' if c['passed'] else 'FAIL'} | {detail} |")
    if st.get("projection"):
        lines += ["", "## Projected full-stage cost (from pilot timings)", ""]
        for s, p in st["projection"].items():
            lines.append(f"- {s}: {p['tasks']} tasks, {p['cpu_hours']:.1f} CPU-hours, about {p['projected_wall_hours']:.1f} h wall")
    if st.get("tasks_failed"):
        lines += ["", "## Failed tasks (first 50)", ""]
        lines += [f"- {f['id']}: {f['error']}" for f in st["tasks_failed"]]
    if st.get("error"):
        lines += ["", "## Stage error", "", "```", st.get("traceback", st["error"]), "```"]
    lines += ["", f"Outputs: {st.get('out_dir')}", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
