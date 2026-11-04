#!/usr/bin/env python3
"""Submit the next approved SABLE-HE stage to Slurm (HPC command (b)).

Stages run strictly in order:
  setup -> smoke -> pilot -> crypto -> fl -> report
A stage is submitted only if its prerequisites PASSED (smoke/pilot must have
passed on the same commit), and only one sable job may be queued at a time.

  python3 ~/sable-he/code/current/scripts/hpc/submit_hpc.py --project ~/sable-he --next           # dry run
  python3 ~/sable-he/code/current/scripts/hpc/submit_hpc.py --project ~/sable-he --next --submit  # submit
  python3 ~/sable-he/code/current/scripts/hpc/submit_hpc.py --project ~/sable-he --status         # overview
  python3 ~/sable-he/code/current/scripts/hpc/submit_hpc.py --project ~/sable-he --chain --submit # queue all remaining stages

Standard library only; runs on Python 3.6+.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

ORDER = ["setup", "smoke", "pilot", "crypto", "fl", "report"]
PREREQ = {"setup": [], "smoke": ["setup"], "pilot": ["smoke"], "crypto": ["pilot"], "fl": ["pilot"], "report": ["crypto", "fl"]}
SPEC = {
    "setup": {"partition": "longq", "cpus": 5, "mem": "32G", "time": "06:00:00"},
    "smoke": {"partition": "shortq", "cpus": 5, "mem": "24G", "time": "01:00:00"},
    "pilot": {"partition": "longq", "cpus": 40, "mem": "auto", "time": "1-00:00:00"},
    "crypto": {"partition": "longq", "cpus": 40, "mem": "auto", "time": "auto"},
    "fl": {"partition": "longq", "cpus": 40, "mem": "auto", "time": "auto"},
    "report": {"partition": "shortq", "cpus": 5, "mem": "16G", "time": "01:00:00"},
}
DEFAULT_EMAIL = "tariq.qayyum@uaeu.ac.ae"
# time limits used by --chain, which submits before the pilot projection exists
CHAIN_TIME = {"crypto": "1-12:00:00", "fl": "4-00:00:00"}
# --chain dependencies: every later stage needs the pilot to exit 0 (= scientifically PASSED);
# fl and report also wait for the stage before them to end, whatever its result, so jobs run one at a time
CHAIN_DEPS = {"smoke": [], "pilot": [("afterok", "smoke")], "crypto": [("afterok", "pilot")],
              "fl": [("afterok", "pilot"), ("afterany", "crypto")], "report": [("afterok", "pilot"), ("afterany", "fl")]}


def read_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return None


def code_commit(code):
    with open(os.path.join(code, "COMMIT")) as fh:
        return fh.read().strip()


def requirements_hash(code):
    with open(os.path.join(code, "scripts", "hpc", "requirements-hpc.txt"), "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()[:16]


def stage_status(project, stage, commit, code):
    """Return the latest FINAL_STATUS for this stage that applies to the given commit."""
    if stage == "setup":
        st = read_json(os.path.join(project, "outputs", "setup", "LATEST.json"))
        if st and st.get("requirements_hash") != requirements_hash(code):
            return {"scientific_status": "STALE", "detail": "requirements changed since setup"}
        return st
    return read_json(os.path.join(project, "outputs", stage, commit[:12], "FINAL_STATUS.json"))


def queued_jobs():
    try:
        out = subprocess.check_output(["squeue", "-h", "-u", os.environ.get("USER", ""), "-o", "%i %j %T"]).decode()
    except Exception:  # noqa: BLE001
        return []
    return [line.split() for line in out.splitlines() if " sable-" in " " + line]


def auto_mem(project):
    res = read_json(os.path.join(project, "outputs", "setup", "hpc_resources.json")) or {}
    mb = res.get("longq_min_node_mem_mb")
    if mb:
        # 200G covers the largest tasks (about 30 GB) with 40 workers and schedules faster than a near-full node
        return "%dG" % max(32, min(200, int(mb * 0.85 / 1024)))
    return "160G"


def auto_time(project, stage, commit):
    st = read_json(os.path.join(project, "outputs", "pilot", commit[:12], "FINAL_STATUS.json")) or {}
    proj = (st.get("projection") or {}).get(stage)
    if not proj:
        return "6-00:00:00"
    hours = min(240.0, max(12.0, proj["projected_wall_hours"] * 1.5 + 2))
    d, h = divmod(int(hours + 0.999), 24)
    return "%d-%02d:00:00" % (d, h)


def sbatch_text(project, code, commit, stage, part, cpus, mem, wall, email, extra=""):
    setup_line = 'bash "$CODE/scripts/hpc/setup_env.sh" "$PROJECT"' if stage == "setup" else 'echo "using $VENV"'
    return """#!/bin/bash
#SBATCH --job-name=sable-{stage}
#SBATCH --partition={part}
#SBATCH --cpus-per-task={cpus}
#SBATCH --mem={mem}
#SBATCH --time={wall}
#SBATCH --output={project}/logs/%x_%j.out
#SBATCH --error={project}/logs/%x_%j.err
#SBATCH --mail-type=BEGIN,END,FAIL
#SBATCH --mail-user={email}

set -euo pipefail
# Start from a clean Python environment.  Slurm copies the submitting shell's variables into the job,
# and a conda env, a Python module or PYTHONPATH from another project can make the venv load another numpy.
echo "inherited: PYTHONPATH=${{PYTHONPATH:-}} PYTHONHOME=${{PYTHONHOME:-}} CONDA_PREFIX=${{CONDA_PREFIX:-}} VIRTUAL_ENV=${{VIRTUAL_ENV:-}} LD_LIBRARY_PATH=${{LD_LIBRARY_PATH:-}} LD_PRELOAD=${{LD_PRELOAD:-}}"
unset PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE PYTHONSAFEPATH CONDA_PREFIX CONDA_DEFAULT_ENV CONDA_PYTHON_EXE VIRTUAL_ENV LD_PRELOAD
export PYTHONNOUSERSITE=1 LD_LIBRARY_PATH=
PROJECT={project}
CODE={code}
VENV=$PROJECT/work/venv
export SABLE_PROJECT=$PROJECT SABLE_DATA_DIR=$PROJECT/data PYTHONUNBUFFERED=1
export OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
echo "job $SLURM_JOB_ID stage={stage} commit={commit} host=$(hostname) cpus=$SLURM_CPUS_PER_TASK mem=${{SLURM_MEM_PER_NODE:-?}}MB"
cd "$CODE"
{setup_line}
"$VENV/bin/python" "$CODE/scripts/hpc/run_stage.py" --project "$PROJECT" --code "$CODE" --stage {stage}{extra}
""".format(stage=stage, part=part, cpus=cpus, mem=mem, wall=wall, project=project, code=code, commit=commit,
           email=email, setup_line=setup_line, extra=extra)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", default=os.path.expanduser("~/sable-he"))
    ap.add_argument("--stage", choices=ORDER)
    ap.add_argument("--next", action="store_true", help="pick the next stage that has not passed")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--submit", action="store_true", help="actually call sbatch (default: dry run)")
    ap.add_argument("--partition")
    ap.add_argument("--cpus", type=int)
    ap.add_argument("--mem")
    ap.add_argument("--time")
    ap.add_argument("--email", default=DEFAULT_EMAIL)
    ap.add_argument("--force", action="store_true", help="ignore prerequisite and queue checks")
    ap.add_argument("--reuse-from", default=None,
                    help="copy finished pilot/crypto/fl results of this earlier commit instead of rerunning them")
    ap.add_argument("--rerun-families", default="",
                    help="with --reuse-from: comma-separated task families to rerun anyway (e.g. attack2)")
    ap.add_argument("--chain", action="store_true",
                    help="queue every remaining stage (smoke..report) at once, linked by Slurm dependencies")
    args = ap.parse_args()

    project = os.path.abspath(os.path.expanduser(args.project))
    code = os.path.realpath(os.path.join(project, "code", "current"))
    commit = code_commit(code)
    statuses = {s: stage_status(project, s, commit, code) for s in ORDER}

    if args.status or not (args.stage or args.next or args.chain):
        print("project:", project)
        print("code commit:", commit)
        for s in ORDER:
            st = statuses[s] or {}
            print("  %-7s %-10s %s" % (s, st.get("scientific_status", "-"), st.get("job_id", "")))
        jobs = queued_jobs()
        print("queued sable jobs:", jobs or "none")
        if not (args.stage or args.next or args.chain):
            return 0

    if args.chain:
        return submit_chain(project, code, commit, statuses, args)

    stage = args.stage
    if args.next:
        stage = next((s for s in ORDER if (statuses[s] or {}).get("scientific_status") != "PASSED"), None)
        if stage is None:
            print("all stages PASSED for commit", commit[:12])
            return 0
        if stage == "fl" and (statuses["crypto"] or {}).get("scientific_status") != "PASSED":
            stage = "crypto"
    if not args.force:
        bad = [p for p in PREREQ[stage] if (statuses[p] or {}).get("scientific_status") != "PASSED"]
        if stage == "fl":
            bad = [p for p in ["pilot"] if (statuses[p] or {}).get("scientific_status") != "PASSED"]
        if bad:
            print("REFUSED: prerequisite stage(s) not PASSED for this commit:", bad)
            print("read outputs/<stage>/<commit>/SUMMARY.md, fix, update the code with command (a), then resubmit")
            return 2
        jobs = queued_jobs()
        if jobs:
            print("REFUSED: a sable job is already queued or running (sequential policy):", jobs)
            return 3

    spec = dict(SPEC[stage])
    part = args.partition or spec["partition"]
    cpus = args.cpus or spec["cpus"]
    mem = args.mem or (auto_mem(project) if spec["mem"] == "auto" else spec["mem"])
    wall = args.time or (auto_time(project, stage, commit) if spec["time"] == "auto" else spec["time"])
    text = sbatch_text(project, code, commit, stage, part, cpus, mem, wall, args.email)
    sb_dir = os.path.join(project, "configs", "sbatch")
    os.makedirs(sb_dir, exist_ok=True)
    path = os.path.join(sb_dir, "%s_%s_%s.sbatch" % (stage, commit[:12], time.strftime("%Y%m%d-%H%M%S")))
    with open(path, "w") as fh:
        fh.write(text)
    print("stage=%s partition=%s cpus=%s mem=%s time=%s commit=%s" % (stage, part, cpus, mem, wall, commit[:12]))
    print("sbatch file:", path)
    if not args.submit:
        print("(dry run; add --submit to queue it)")
        return 0
    job_id = sbatch(project, path, stage, commit, part, cpus, mem, wall, [])
    print("\nmonitor:")
    print("  squeue -j %s" % job_id)
    print("  tail -F %s/logs/sable-%s_%s.out" % (project, stage, job_id))
    print("  cat %s/outputs/%s/%s/PROGRESS.json" % (project, stage, commit[:12]))
    print("  sacct -j %s --format=JobID,JobName,State,ExitCode,Elapsed,AllocCPUS,MaxRSS,Reason" % job_id)
    return 0


def sbatch(project, path, stage, commit, part, cpus, mem, wall, deps):
    cmd = ["sbatch"]
    if deps:
        cmd += ["--dependency=" + ",".join("%s:%s" % d for d in deps), "--kill-on-invalid-dep=yes"]
    out = subprocess.check_output(cmd + [path]).decode().strip()
    print(out)
    job_id = out.split()[-1]
    with open(os.path.join(project, "LAST_JOB_ID"), "w") as fh:
        fh.write(job_id + "\n")
    with open(os.path.join(project, "configs", "jobs.jsonl"), "a") as fh:
        fh.write(json.dumps({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "job_id": job_id, "stage": stage, "commit": commit,
                             "partition": part, "cpus": cpus, "mem": mem, "time_limit": wall,
                             "dependency": ",".join("%s:%s" % d for d in deps)}) + "\n")
    return job_id


def submit_chain(project, code, commit, statuses, args):
    if (statuses["setup"] or {}).get("scientific_status") != "PASSED":
        print("REFUSED: setup has not PASSED; submit it first with --next --submit")
        return 2
    jobs = queued_jobs()
    if jobs and not args.force:
        print("REFUSED: a sable job is already queued or running:", jobs)
        return 3
    todo = [s for s in ORDER[1:] if (statuses[s] or {}).get("scientific_status") != "PASSED"]
    if not todo:
        print("all stages PASSED for commit", commit[:12])
        return 0
    sb_dir = os.path.join(project, "configs", "sbatch")
    os.makedirs(sb_dir, exist_ok=True)
    ids = {}
    print("chain for commit %s: %s" % (commit[:12], " -> ".join(todo)))
    for stage in todo:
        spec = dict(SPEC[stage])
        part = spec["partition"] if not args.partition or spec["cpus"] < 40 else args.partition
        cpus = spec["cpus"]
        mem = args.mem if (args.mem and spec["mem"] == "auto") else (auto_mem(project) if spec["mem"] == "auto" else spec["mem"])
        if spec["time"] == "auto":
            wall = auto_time(project, stage, commit) if (statuses["pilot"] or {}).get("scientific_status") == "PASSED" else CHAIN_TIME[stage]
        else:
            wall = spec["time"]
        deps = [(kind, ids[s]) for kind, s in CHAIN_DEPS[stage] if s in ids]
        path = os.path.join(sb_dir, "%s_%s_%s.sbatch" % (stage, commit[:12], time.strftime("%Y%m%d-%H%M%S")))
        extra = ""
        if args.reuse_from and stage in ("pilot", "crypto", "fl"):
            extra = " --reuse-from %s" % args.reuse_from[:12]
            if args.rerun_families:
                extra += " --rerun-families %s" % args.rerun_families
        with open(path, "w") as fh:
            fh.write(sbatch_text(project, code, commit, stage, part, cpus, mem, wall, args.email, extra))
        print("  %-7s partition=%s cpus=%s mem=%s time=%s after=%s%s" % (stage, part, cpus, mem, wall,
                                                                          ",".join("%s:%s" % d for d in deps) or "-", extra))
        if args.submit:
            ids[stage] = sbatch(project, path, stage, commit, part, cpus, mem, wall, deps)
        else:
            ids[stage] = "<%s>" % stage
    if not args.submit:
        print("(dry run; add --submit to queue the chain)")
        return 0
    print("\nIf a gating stage fails, Slurm cancels the stages that depend on it (--kill-on-invalid-dep).")
    print("monitor:  squeue -u $USER   |   python3 %s/code/current/scripts/hpc/submit_hpc.py --project %s --status" % (project, project))
    print("progress: cat %s/outputs/<stage>/%s/PROGRESS.json" % (project, commit[:12]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
