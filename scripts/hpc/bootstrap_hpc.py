#!/usr/bin/env python3
"""Download an immutable snapshot of the repository at a pinned commit.

HPC command (a).  Works without git: it resolves the branch to a commit
through the GitHub API, downloads that commit's tarball, unpacks it into
<project>/code_versions/<sha>/ and points <project>/code/current at it.
Queued jobs always run their own pinned snapshot, never a mutable folder.

Usage (first time, or to update):
  curl -fsSL https://raw.githubusercontent.com/rtqayyum/sable-he-research/experiments-v1/scripts/hpc/bootstrap_hpc.py \
    | python3 - --project ~/sable-he --ref experiments-v1

Standard library only; runs on Python 3.6+.
"""

import argparse
import io
import json
import os
import re
import shutil
import sys
import tarfile
import time
import urllib.request

DIRS = ["work", "data", "outputs", "results", "logs", "code_versions", "configs", "code"]


def fetch(url, binary=False, tries=4):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sable-he-bootstrap"})
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read()
            return data if binary else data.decode("utf-8")
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(3 * (i + 1))
    raise RuntimeError("download failed for %s: %s" % (url, last))


def resolve(repo, ref):
    if re.fullmatch(r"[0-9a-f]{40}", ref):
        return ref
    info = json.loads(fetch("https://api.github.com/repos/%s/commits/%s" % (repo, ref)))
    return info["sha"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", default=os.path.expanduser("~/sable-he"))
    ap.add_argument("--repo", default="rtqayyum/sable-he-research")
    ap.add_argument("--ref", default="experiments-v1", help="branch, tag or full commit hash")
    args = ap.parse_args()

    project = os.path.abspath(os.path.expanduser(args.project))
    for d in DIRS:
        os.makedirs(os.path.join(project, d), exist_ok=True)

    sha = resolve(args.repo, args.ref)
    target = os.path.join(project, "code_versions", sha)
    if os.path.exists(os.path.join(target, "COMMIT")):
        print("snapshot already present:", target)
    else:
        print("downloading %s@%s ..." % (args.repo, sha[:12]))
        blob = fetch("https://codeload.github.com/%s/tar.gz/%s" % (args.repo, sha), binary=True)
        tmp = target + ".partial"
        if os.path.exists(tmp):
            shutil.rmtree(tmp)
        os.makedirs(tmp)
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            members = tf.getmembers()
            root = members[0].name.split("/")[0]
            for m in members:
                if m.name == root:
                    continue
                rel = m.name[len(root) + 1:]
                if not rel or rel.startswith("/") or ".." in rel.split("/"):
                    continue
                m.name = rel
                tf.extract(m, tmp)
        with open(os.path.join(tmp, "COMMIT"), "w") as fh:
            fh.write(sha + "\n")
        os.rename(tmp, target)
        print("unpacked into", target)

    link = os.path.join(project, "code", "current")
    tmp_link = link + ".new"
    if os.path.lexists(tmp_link):
        os.remove(tmp_link)
    os.symlink(target, tmp_link)
    os.replace(tmp_link, link)
    with open(os.path.join(project, "configs", "code_history.jsonl"), "a") as fh:
        fh.write(json.dumps({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "ref": args.ref, "commit": sha}) + "\n")
    print("current code ->", sha)
    print("next: python3 %s/code/current/scripts/hpc/submit_hpc.py --project %s --next" % (project, project))


if __name__ == "__main__":
    sys.exit(main())
