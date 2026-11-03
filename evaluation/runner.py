"""Resumable, memory-aware parallel task runner.

Each task runs in its own spawned process (so memory is returned after every
task and a crash or timeout cannot take down the others).  The worker writes
its own result file atomically; the parent only schedules, enforces timeouts
and records crashes.  Re-running a stage skips tasks that already have an
"ok" result, so a TIMEOUT or node failure loses only the tasks in flight.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import time
import traceback
from pathlib import Path
from typing import Any

from evaluation.common import atomic_write_json, read_json

THREAD_VARS = ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS")


def resolve(kind: str):
    if kind == "fl_run":
        from evaluation.fl.run import run_fl

        return run_fl
    if kind == "reference_crosscheck":
        from evaluation.crypto.reference import crosscheck

        return crosscheck
    from evaluation.crypto.tasks import TASKS

    return TASKS[kind]


def _worker(task: dict[str, Any], out_path: str, attempt: int) -> None:
    for v in THREAD_VARS:
        os.environ[v] = "1"
    import warnings

    warnings.simplefilter("ignore")
    record: dict[str, Any] = {"id": task["id"], "family": task["family"], "kind": task["kind"], "cfg": task["cfg"],
                              "attempt": attempt, "pid": os.getpid(), "started": time.time()}
    t0 = time.perf_counter()
    try:
        record["result"] = resolve(task["kind"])(task["cfg"])
        record["status"] = "ok"
    except Exception as exc:  # noqa: BLE001
        record["status"] = "error"
        record["error"] = f"{type(exc).__name__}: {exc}"
        record["traceback"] = traceback.format_exc()
    record["seconds"] = time.perf_counter() - t0
    atomic_write_json(out_path, record)


def load_results(task_dir: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if task_dir.exists():
        for f in task_dir.glob("*.json"):
            try:
                rec = read_json(f)
                out[rec["id"]] = rec
            except Exception:  # noqa: BLE001  (partial or corrupt file: treat as missing)
                continue
    return out


def run_tasks(tasks: list[dict[str, Any]], out_dir: Path, *, workers: int, mem_gb: float,
              max_attempts: int = 2, progress_every: float = 60.0, log=print) -> list[dict[str, Any]]:
    task_dir = out_dir / "tasks"
    task_dir.mkdir(parents=True, exist_ok=True)
    existing = load_results(task_dir)
    pending = []
    for t in tasks:
        prev = existing.get(t["id"])
        if prev and prev.get("status") == "ok":
            continue
        attempt = int(prev.get("attempt", 0)) + 1 if prev else 1
        if prev and attempt > max_attempts:
            continue
        pending.append((t, attempt))
    # longest/biggest first to shorten the tail
    pending.sort(key=lambda ta: (-ta[0]["mem_gb"], -ta[0]["timeout_s"]))
    total = len(tasks)
    log(f"[runner] {total} tasks, {total - len(pending)} already done, {len(pending)} to run; "
        f"workers={workers} memory budget={mem_gb:.0f} GB")
    for v in THREAD_VARS:
        os.environ[v] = "1"
    ctx = mp.get_context("spawn")
    running: dict[str, tuple[Any, dict[str, Any], float, int]] = {}
    used_mem = 0.0
    t_start = time.time()
    last_progress = 0.0
    finished = 0
    cpu_s_done = 0.0
    while pending or running:
        launched = True
        while launched and pending and len(running) < workers:
            launched = False
            for i, (t, attempt) in enumerate(pending):
                need = min(t["mem_gb"], mem_gb)  # a task larger than the budget runs alone
                if used_mem + need <= mem_gb or not running:
                    p = ctx.Process(target=_worker, args=(t, str(task_dir / f"{t['id']}.json"), attempt), daemon=False)
                    p.start()
                    running[t["id"]] = (p, t, time.time(), attempt)
                    used_mem += need
                    pending.pop(i)
                    launched = True
                    break
        time.sleep(0.5)
        for tid in list(running):
            p, t, started, attempt = running[tid]
            timed_out = time.time() - started > t["timeout_s"]
            if p.is_alive() and not timed_out:
                continue
            if p.is_alive():
                p.terminate()
                p.join(10)
            else:
                p.join()
            used_mem -= min(t["mem_gb"], mem_gb)
            del running[tid]
            finished += 1
            cpu_s_done += time.time() - started
            path = task_dir / f"{tid}.json"
            if timed_out or not path.exists():
                if timed_out:
                    reason = f"timeout after {t['timeout_s']} s"
                elif p.exitcode in (-9, 137):
                    reason = f"killed by signal 9 (exit {p.exitcode}): most likely out of memory"
                else:
                    reason = f"worker process died with exit code {p.exitcode} (see the job .err log)"
                atomic_write_json(path, {"id": tid, "family": t["family"], "kind": t["kind"], "cfg": t["cfg"], "attempt": attempt,
                                         "status": "error", "error": reason, "seconds": time.time() - started})
                log(f"[runner] {tid} failed: {reason}")
        if time.time() - last_progress > progress_every:
            last_progress = time.time()
            done_now = total - len(pending) - len(running)
            el = time.time() - t_start
            rate = finished / el if el > 0 and finished else 0.0
            eta = (len(pending) + len(running)) / rate / 3600 if rate else float("nan")
            prog = {"total": total, "done": done_now, "running": len(running), "pending": len(pending),
                    "elapsed_h": el / 3600, "cpu_hours_done": cpu_s_done / 3600,
                    "eta_h_by_task_count": eta,
                    "note": "heaviest tasks run first, so the task-count ETA overestimates early in a stage",
                    "updated": time.strftime("%Y-%m-%d %H:%M:%S")}
            atomic_write_json(out_dir / "PROGRESS.json", prog)
            log(f"[runner] {done_now}/{total} done, {len(running)} running, ETA {eta:.2f} h")
    results = load_results(task_dir)
    return [results[t["id"]] for t in tasks if t["id"] in results]
