# HPC runbook (UAEU Slurm)

Everything runs from a pinned GitHub commit through two commands.  Project
folder on the HPC: `~/sable-he` (change `--project` if you prefer another).

## The two commands

**(a) Get or update the code** (downloads an immutable snapshot of the commit;
no git needed):

```bash
curl -fsSL https://raw.githubusercontent.com/rtqayyum/sable-he-research/experiments-v1/scripts/hpc/bootstrap_hpc.py \
  | python3 - --project ~/sable-he --ref experiments-v1
```

**(b) Submit the next approved stage** (first without `--submit` to see the plan):

```bash
python3 ~/sable-he/code/current/scripts/hpc/submit_hpc.py --project ~/sable-he --next --submit
```

**(b′) Or queue every remaining stage at once** (smoke → pilot → crypto → fl → report):

```bash
python3 ~/sable-he/code/current/scripts/hpc/submit_hpc.py --project ~/sable-he --chain --submit
```

The chain uses Slurm dependencies.  Each stage starts only after the one
before it ends, so jobs still run one at a time.  Every stage after the pilot
needs the pilot to exit 0, which happens only when its checks PASS; if a
gating stage fails, Slurm cancels the stages that depend on it.  Each job also
re-checks its prerequisite on start.  The report runs after fl whatever fl's
result, so tables are built from whatever finished.

`--status` prints every stage's state.  The script refuses a stage whose
prerequisite has not PASSED on the same commit, and refuses to queue while
another `sable-*` job is pending or running.

## Stages

| Stage | Partition / CPUs | Time | What it does | Passes when |
|---|---|---|---|---|
| setup | longq / 5 | 6 h | uv-managed Python 3.11 venv in `work/venv`, pinned packages, MNIST + Fashion-MNIST download, unit tests, `sinfo` resource scan | packages import, all 7 backends load, both datasets have 60k/10k images, tests pass |
| smoke | shortq / 5 | 1 h | 22 tiny tasks covering every task type | all tasks ok, attacks work, SABLE FedAvg equals plaintext, plain MNIST LR ≥ 0.5 after 2 rounds |
| pilot | longq / 40 | 24 h | 55 of the most expensive tasks, 10 FL rounds | all checks pass, MNIST LR ≥ 0.8, projected crypto and FL stages each fit in 9 days |
| crypto | longq / 40 | auto (from pilot; 36 h with --chain) | 1,014 tasks: attacks, correctness, SHE and aggregation benchmarks, parameter tables | all tasks ok and science checks pass |
| fl | longq / 40 | auto (from pilot; 4 days with --chain) | 1,224 FL runs: accuracy study (plain/SABLE/CKKS × 2 datasets × 3 models × 3 partitions × K ∈ {10, 50, 100, 200} × 5 seeds, 100 rounds) and cost/scaling study (8 methods × 3 models × K ∈ {10, 50, 100, 200, 500, 1000}) | all tasks ok and SABLE accuracy within 0.01 of plaintext |
| report | shortq / 5 | 1 h | CSV tables, PDF/PNG figures and `REPORT.md` in `results/<commit>/` | tables and figures built |

Memory for 40-CPU stages is set from the setup stage's `sinfo` scan (85% of
the smallest longq node, at most 200G); override with `--mem`.  Time for
crypto/fl is 1.5× the pilot projection plus 2 h (12 h to 10 days).

## Monitoring

```bash
squeue -u $USER
sacct -j JOB_ID --format=JobID,JobName,State,ExitCode,Elapsed,AllocCPUS,MaxRSS,Reason
tail -F ~/sable-he/logs/sable-<stage>_<JOB_ID>.out
cat ~/sable-he/outputs/<stage>/<commit12>/PROGRESS.json     # done / running / ETA
cat ~/sable-he/outputs/<stage>/<commit12>/SUMMARY.md        # after the job ends
```

A `COMPLETED 0:0` Slurm state is not a scientific pass.  Read `SUMMARY.md`:
the stage passes only if every check in its table passes.

## Resuming

Every task writes its own result file.  If a job hits `TIMEOUT` or the node
fails, submit the same stage again (`--stage <name> --submit`): finished tasks
are skipped and failed ones are retried once.  A new commit starts a fresh
output folder, so results from different code are never mixed.

## If compute nodes have no internet

The setup stage needs PyPI and the MNIST mirrors.  If it fails on downloads,
run the same steps on the login node, then resubmit setup:

```bash
cd ~/sable-he/code/current
bash scripts/hpc/setup_env.sh ~/sable-he
SABLE_DATA_DIR=~/sable-he/data ~/sable-he/work/venv/bin/python -c \
  "import sys; sys.path[:0]=['.','src']; from evaluation.fl.data import download; download('mnist'); download('fmnist')"
```

## Layout

```
~/sable-he/
  code_versions/<sha>/   immutable snapshots (jobs run these)
  code/current           symlink to the latest snapshot
  work/venv              Python environment
  data/                  mnist.npz, fmnist.npz
  outputs/<stage>/<commit12>/   tasks/*.json, TASKS.json, PROGRESS.json, FINAL_STATUS.json, SUMMARY.md
  results/<commit12>/    paper tables and figures
  results/slurm_jobs/<job_id>/report/SUMMARY.md
  logs/                  Slurm stdout/stderr
  configs/               sbatch files, jobs.jsonl, code_history.jsonl
  LAST_JOB_ID
```

## SABLE replica count

SABLE's replica count R is chosen per run from the plurality bound so that a
decoded coordinate fails with probability at most 1e-12.  The summed noise of
K uploads makes one replica correct with probability (1−η)^K, so R grows with
the number of clients:

| row | K = 10 | 50 | 100 | 200 | 500 | 1000 |
|---|---|---|---|---|---|---|
| main (n = 65,536, η = 0.003) | 13 | 21 | 29 | 47 | 143 | 755 |
| low-noise (n = 131,072, η = 0.001) | 11 | 13 | 17 | 23 | 41 | 79 |

## Rerunning part of a stage after a code fix

A new commit normally starts every stage from scratch.  When a fix touches
only some task families, copy the finished results of the earlier commit and
rerun the rest:

```bash
python3 ~/sable-he/code/current/scripts/hpc/submit_hpc.py --project ~/sable-he --chain --submit \
  --reuse-from <old-commit-12> --rerun-families attack2
```

A task id is a hash of its configuration, so a copied result is for the same
experiment.  Copied records keep their numbers and gain `reused_from_commit`,
and `REPORT.md` lists how many results came from each commit.  Failed tasks
are never copied.  List every family whose code changed in
`--rerun-families`.
