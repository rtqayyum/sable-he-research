"""Turn stage outputs into paper tables (CSV) and figures (PDF + PNG).

Figures are static print figures, so they follow the dataviz rules for
print: fixed categorical slot per method (colour follows the entity), one
axis per chart, thin marks, direct labels where colour contrast is low, and
every figure has a matching CSV table.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Callable

import numpy as np

# fixed slots (validated light-mode palette); plaintext is a neutral reference
METHOD_COLOR = {"plain": "#52514e", "sable": "#2a78d6", "lwe": "#eb6834", "secagg": "#1baf7a",
                "ckks": "#eda100", "bfv": "#e87ba4", "paillier": "#008300"}
METHOD_LABEL = {"plain": "Plaintext FedAvg", "sable": "SABLE-HE (sparse LPN)", "lwe": "LWE-KAHE", "secagg": "SecAgg+",
                "ckks": "CKKS", "bfv": "BFV", "paillier": "Paillier-3072"}
MARKERS = {"plain": "o", "sable": "s", "lwe": "^", "secagg": "D", "ckks": "v", "bfv": "P", "paillier": "X"}
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"


def _load_stage(project: Path, stage: str, commit: str) -> tuple[list[dict[str, Any]], str]:
    d = project / "outputs" / stage / commit[:12] / "tasks"
    used = commit[:12]
    if not d.exists():
        latest = project / "outputs" / stage / "LATEST.json"
        if latest.exists():
            st = json.loads(latest.read_text())
            d = Path(st["out_dir"]) / "tasks"
            used = st["commit"][:12]
    if not d.exists():
        return [], "missing"
    out = []
    for f in sorted(d.glob("*.json")):
        try:
            r = json.loads(f.read_text())
        except Exception:  # noqa: BLE001
            continue
        if r.get("status") == "ok":
            out.append(r)
    return out, used


def _style() -> Any:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({
        "font.size": 8, "axes.titlesize": 8.5, "axes.labelsize": 8, "legend.fontsize": 7, "xtick.labelsize": 7, "ytick.labelsize": 7,
        "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED, "text.color": INK,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.spines.top": False, "axes.spines.right": False,
        "lines.linewidth": 1.6, "lines.markersize": 4, "savefig.dpi": 300, "figure.dpi": 120, "pdf.fonttype": 42,
        "legend.frameon": False,
    })
    return plt


def _save(fig: Any, out: Path, name: str, written: list[str]) -> None:
    for ext in ("pdf", "png"):
        fig.savefig(out / f"{name}.{ext}", bbox_inches="tight")
    written.append(f"{name}.pdf")
    import matplotlib.pyplot as plt

    plt.close(fig)


def _csv(df: Any, out: Path, name: str, written: list[str]) -> None:
    df.to_csv(out / f"{name}.csv", index=False)
    written.append(f"{name}.csv")


def _fmt_bytes(b: float) -> str:
    for unit, s in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if b >= s:
            return f"{b / s:.1f} {unit}"
    return f"{b:.0f} B"


# --------------------------------------------------------------------------- crypto sections


def crypto_section(rows: list[dict[str, Any]], out: Path, written: list[str], notes: list[str]) -> None:
    import pandas as pd

    plt = _style()
    fam = lambda f: [r for r in rows if r["family"] == f]  # noqa: E731

    # parameter table
    pt = fam("params")
    if pt:
        res = pt[0]["result"]
        cand = pd.DataFrame([{k: v for k, v in c.items() if k not in ("sparse_screen", "sizes", "blockers")} |
                             {"blockers": "; ".join(c["blockers"]),
                              "expansion_key_GB": c["sizes"]["expansion_key_b_columns_bytes"] / 1e9,
                              "compaction_key_b_GB": c["sizes"].get("compaction_key_b_bytes", 0) / 1e9,
                              "fresh_ct_seeded_KB": c["sizes"]["fresh_ciphertext_seeded_bytes"] / 1e3,
                              "expanded_ct_GB": c["sizes"]["expanded_ciphertext_bytes"] / 1e9} for c in res["candidates"]])
        _csv(cand, out, "table_parameter_candidates", written)
        fl = pd.DataFrame([{"name": r["name"], "d": r["d"], "rounds_per_key": r["rounds_per_key"], "samples_per_key": r["samples_per_key"],
                            "min_bits": r["screen"]["min_bits"], "sample_margin": r["screen"]["sample_threshold_margin"],
                            "verdict": r["screen"]["verdict"], "upload_MB": r["upload_bytes"] / 1e6,
                            "failure_bound_K100": r["failure_bound_K100"], "failure_bound_K500": r["failure_bound_K500"]}
                           for r in res["fl_params"]])
        _csv(fl, out, "table_fl_parameter_screens", written)
        rejected = cand[cand["k"] <= 2]["name"].tolist()
        notes.append(f"Parameter rows with k<=2 rejected by sparse-specific screens: {', '.join(rejected)}.")

    # reference presets broken
    rp = fam("ref_presets")
    if rp:
        df = pd.DataFrame([r["result"] | {"seed": r["cfg"]["seed"]} for r in rp])
        g = df.groupby(["preset", "n", "k", "eta", "q"]).agg(success_rate=("success", "mean"), predicted=("predicted_success", "first"),
                                                           seconds=("seconds", "median")).reset_index()
        _csv(g, out, "table_reference_presets_attack", written)
        broken = int((g["success_rate"] > 0).sum())
        notes.append(f"Known-plaintext attack recovered the evaluation secret for {broken} of {len(g)} reference presets.")

    # 2-sparse attack heatmaps
    a2 = fam("attack2")
    if a2:
        df = pd.DataFrame([{**r["cfg"], **{k: r["result"][k] for k in ("fraction_correct", "exact", "seconds", "peak_rss_gb")}} for r in a2])
        g = df.groupby(["n", "ratio", "eta"]).agg(exact_rate=("exact", "mean"), mean_fraction=("fraction_correct", "mean"),
                                                seconds=("seconds", "median")).reset_index()
        _csv(g, out, "table_attack_two_sparse", written)
        etas = sorted(g["eta"].unique())
        fig, axes = plt.subplots(1, len(etas), figsize=(1.75 * len(etas) + 0.6, 2.2), sharey=True)
        axes = np.atleast_1d(axes)
        ns, ratios = sorted(g["n"].unique()), sorted(g["ratio"].unique())
        for ax, eta in zip(axes, etas):
            M = np.full((len(ns), len(ratios)), np.nan)
            for _, row in g[g["eta"] == eta].iterrows():
                M[ns.index(row["n"]), ratios.index(row["ratio"])] = row["exact_rate"]
            im = ax.imshow(M, cmap="Blues", vmin=0, vmax=1, aspect="auto", origin="lower")
            for i in range(len(ns)):
                for j in range(len(ratios)):
                    if not np.isnan(M[i, j]):
                        ax.text(j, i, f"{M[i, j]:.0%}" if M[i, j] < 1 else "100", ha="center", va="center", fontsize=5.5,
                                color="white" if M[i, j] > 0.6 else INK)
            ax.set_xticks(range(len(ratios)), [str(r) for r in ratios])
            ax.set_title(f"noise rate {eta}")
            ax.set_xlabel("samples / n")
            ax.grid(False)
        axes[0].set_yticks(range(len(ns)), [f"2^{int(math.log2(n))}" for n in ns])
        axes[0].set_ylabel("secret dimension n")
        fig.colorbar(im, ax=axes, shrink=0.8, label="exact recovery rate")
        _save(fig, out, "fig_attack_two_sparse", written)
        big = g[(g["eta"] <= 0.003) & (g["ratio"] >= 10)]
        if len(big):
            notes.append(f"2-sparse LPN: exact recovery in {big['exact_rate'].mean():.0%} of configurations with eta<=0.003 and m>=10n "
                         f"(largest n={int(big['n'].max())}, median {big['seconds'].median():.0f} s).")

    # known-plaintext attack vs prediction
    kp = fam("attack_kp")
    if kp:
        df = pd.DataFrame([{**r["cfg"], **r["result"]} for r in kp])
        g = df.groupby(["n", "eta"]).agg(success_rate=("success", "mean"), predicted=("predicted_success", "first"),
                                        seconds=("seconds", "median"), runs=("success", "size")).reset_index()
        g["eta_times_N"] = g["eta"] * (g["n"] + 1)
        _csv(g, out, "table_attack_known_plaintext", written)
        fig, ax = plt.subplots(figsize=(3.4, 2.3))
        x = np.logspace(-4, 1.5, 200)
        ax.plot(x, np.exp(-x), color=MUTED, linewidth=1.2, linestyle="--", label="predicted (1-eta)^(n+1)")
        gg = g[g["eta"] > 0]
        ax.scatter(gg["eta_times_N"], gg["success_rate"], s=16, color=METHOD_COLOR["sable"], edgecolor="white", linewidth=0.6,
                   zorder=3, label="measured")
        ax.set_xscale("log")
        ax.set_xlabel("eta x (n+1)")
        ax.set_ylabel("key-recovery success rate")
        ax.set_ylim(-0.03, 1.03)
        ax.legend(loc="lower left")
        _save(fig, out, "fig_attack_known_plaintext", written)

    # aggregation correctness
    ca = fam("corr_agg")
    if ca:
        df = pd.DataFrame([{**r["cfg"], **{k: r["result"][k] for k in ("coord_failure_rate", "failure_bound", "p_replica_correct_empirical",
                                                                       "p_replica_correct_theory", "upload_bytes_per_scalar")}} for r in ca])
        _csv(df.sort_values(["eta", "R", "K"]), out, "table_aggregation_correctness", written)
        etas = sorted(df["eta"].unique())
        fig, axes = plt.subplots(1, len(etas), figsize=(2.3 * len(etas), 2.3), sharey=True)
        axes = np.atleast_1d(axes)
        Rs = sorted(df["R"].unique())
        cols = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
        floor = 1e-7
        for ax, eta in zip(axes, etas):
            for R, c in zip(Rs, cols):
                s = df[(df["eta"] == eta) & (df["R"] == R)].sort_values("K")
                ax.plot(s["K"], np.maximum(s["coord_failure_rate"], floor), marker="o", color=c, label=f"R={R}")
                ax.plot(s["K"], np.clip(s["failure_bound"], floor, 1), color=c, linestyle=":", linewidth=1.0)
            ax.set_xscale("log")
            ax.set_yscale("log")
            ax.set_title(f"noise rate {eta}")
            ax.set_xlabel("clients K")
        axes[0].set_ylabel("coordinate failure rate (floor 1e-7)")
        axes[-1].legend(loc="lower right", ncol=1)
        _save(fig, out, "fig_aggregation_failures", written)

    # SHE correctness
    cs = fam("corr_she")
    if cs:
        df = pd.DataFrame([{**r["cfg"], "p_replica_correct": r["result"]["p_replica_correct"],
                            **{f"bound_R{k}": v for k, v in r["result"]["plurality_bound"].items()}} for r in cs])
        _csv(df.sort_values(["op", "n", "k", "eta"]), out, "table_she_correctness", written)

    # SHE benchmarks
    bs = fam("bench_she")
    if bs:
        df = pd.DataFrame([{**{k: r["cfg"][k] for k in ("n", "k")}, **{k: v for k, v in r["result"].items() if not isinstance(v, dict)},
                            **{f"size_{k}": v for k, v in r["result"]["key_sizes"].items()}} for r in bs])
        _csv(df.sort_values(["k", "n"]), out, "table_she_benchmarks", written)
        fig, axes = plt.subplots(1, 2, figsize=(6.8, 2.4))
        ks = sorted(df["k"].unique())
        cols = ["#2a78d6", "#eb6834", "#1baf7a"]
        for k, c in zip(ks, cols):
            s = df[df["k"] == k].sort_values("n")
            axes[0].plot(s["n"], s["mul_s"], marker="o", color=c, label=f"k={k}")
            axes[1].plot(s["n"], s["product_bytes"] / 1e9, marker="o", color=c, label=f"k={k}")
        for ax in axes:
            ax.set_xscale("log", base=2)
            ax.set_yscale("log")
            ax.set_xlabel("secret dimension n")
        axes[0].set_ylabel("multiply time per replica (s)")
        axes[1].set_ylabel("product ciphertext per replica (GB)")
        axes[0].legend()
        _save(fig, out, "fig_she_cost", written)

    # aggregation primitive benchmark
    ba = fam("bench_agg")
    if ba:
        df = pd.DataFrame([{"method": r["cfg"]["method"], "label": r["cfg"].get("label", r["cfg"]["method"]), "d": r["cfg"]["d"],
                            "K": r["cfg"]["K"], "post_quantum": r["result"]["backend"]["post_quantum"],
                            "key_model": r["result"]["backend"]["key_model"], "extrapolated": r["result"]["extrapolated"],
                            **{k: r["result"].get(k) for k in ("upload_bytes_client", "client_encrypt_s", "server_aggregate_s", "decrypt_s",
                                                                "coord_failures", "max_abs_err_vs_quantized")}} for r in ba])
        df["upload_vs_plain"] = df.apply(lambda x: x["upload_bytes_client"] / (4 * x["d"]), axis=1)
        _csv(df.sort_values(["d", "K", "label"]), out, "table_aggregation_primitives", written)
        sub = df[(df["K"] == 100) & (df["d"] == 101770)]
        if len(sub):
            _bar_methods(plt, sub, "upload_bytes_client", "bytes per client per round", out, "fig_upload_per_client", written)


def _bar_methods(plt: Any, sub: Any, col: str, ylabel: str, out: Path, name: str, written: list[str]) -> None:
    order = [m for m in ["plain", "secagg", "lwe", "bfv", "ckks", "sable", "paillier"] if m in set(sub["method"])]
    sub = sub.drop_duplicates("method").set_index("method").loc[order]
    fig, ax = plt.subplots(figsize=(3.4, 2.4))
    x = np.arange(len(order))
    vals = sub[col].astype(float).values
    ax.bar(x, vals, width=0.62, color=[METHOD_COLOR[m] for m in order], edgecolor="white", linewidth=1.0)
    for xi, v in zip(x, vals):
        ax.text(xi, v * 1.15, _fmt_bytes(v) if "bytes" in col else f"{v:.2g}", ha="center", va="bottom", fontsize=6, color=INK)
    ax.set_yscale("log")
    ax.set_xticks(x, [METHOD_LABEL[m].replace(" (sparse LPN)", "") for m in order], rotation=30, ha="right")
    ax.set_ylabel(ylabel)
    ax.grid(axis="x", visible=False)
    _save(fig, out, name, written)


# --------------------------------------------------------------------------- FL sections


def fl_section(rows: list[dict[str, Any]], out: Path, written: list[str], notes: list[str]) -> None:
    import pandas as pd

    plt = _style()
    runs = [r for r in rows if r["family"] in ("fl_acc", "fl_cost", "fl")]
    if not runs:
        return
    flat = pd.DataFrame([{**{k: r["cfg"][k] for k in ("dataset", "model", "partition", "clients", "seed", "method", "rounds", "crypto")},
                          "family": r["family"], "d": r["result"]["d"],
                          **{k: r["result"][k] for k in ("final_test_acc", "best_test_acc", "total_coord_failures",
                                                          "mean_upload_bytes_client", "mean_client_encrypt_s", "mean_server_aggregate_s",
                                                          "mean_decrypt_s", "mean_client_train_s", "wall_s")}} for r in runs])
    _csv(flat, out, "table_fl_runs", written)
    acc = flat[flat["family"].isin(["fl_acc", "fl"])]
    if len(acc):
        g = acc.groupby(["dataset", "model", "partition", "clients", "method"]).agg(
            acc_mean=("final_test_acc", "mean"), acc_std=("final_test_acc", "std"), seeds=("seed", "nunique"),
            sable_failures=("total_coord_failures", "sum")).reset_index()
        piv = g.pivot_table(index=["dataset", "model", "partition", "clients"], columns="method", values="acc_mean").reset_index()
        if "plain" in piv and "sable" in piv:
            piv["gap_sable_minus_plain"] = piv["sable"] - piv["plain"]
            notes.append(f"FL accuracy: SABLE minus plaintext final accuracy, mean {piv['gap_sable_minus_plain'].mean():+.4f}, "
                         f"max |gap| {piv['gap_sable_minus_plain'].abs().max():.4f} over {len(piv)} configurations.")
        _csv(g, out, "table_fl_accuracy", written)
        _csv(piv, out, "table_fl_accuracy_wide", written)
        # accuracy curves: K=100, seed-averaged
        hist = []
        for r in runs:
            if r["family"] not in ("fl_acc", "fl"):
                continue
            for h in r["result"]["history"]:
                if "test_acc" in h:
                    hist.append({**{k: r["cfg"][k] for k in ("dataset", "model", "partition", "clients", "seed", "method")},
                                 "round": h["round"], "test_acc": h["test_acc"]})
        H = pd.DataFrame(hist)
        _csv(H, out, "table_fl_curves", written)
        Kmax = int(H["clients"].max())
        panels = [(ds, part) for ds in sorted(H["dataset"].unique()) for part in ("iid", "dir0.1") if part in set(H["partition"])]
        models = [m for m in ("lr", "mlp", "cnn") if m in set(H["model"])]
        if panels and models:
            fig, axes = plt.subplots(len(models), len(panels), figsize=(1.9 * len(panels) + 0.3, 1.6 * len(models) + 0.3),
                                     sharex=True, squeeze=False)
            for i, model in enumerate(models):
                for j, (ds, part) in enumerate(panels):
                    ax = axes[i, j]
                    for m in ("plain", "ckks", "sable"):
                        s = H[(H["dataset"] == ds) & (H["partition"] == part) & (H["model"] == model) & (H["clients"] == Kmax) & (H["method"] == m)]
                        if len(s):
                            c = s.groupby("round")["test_acc"].mean()
                            ax.plot(c.index, c.values, color=METHOD_COLOR[m], label=METHOD_LABEL[m],
                                    linestyle="--" if m == "plain" else "-", linewidth=1.2 if m == "plain" else 1.6)
                    if i == 0:
                        ax.set_title(f"{ds.upper()} {part}")
                    if j == 0:
                        ax.set_ylabel(f"{model.upper()} test acc")
                    if i == len(models) - 1:
                        ax.set_xlabel("round")
            handles, labels = {}, []
            for ax in axes.ravel():
                for h, lab in zip(*ax.get_legend_handles_labels()):
                    handles.setdefault(lab, h)
            if handles:
                fig.legend(list(handles.values()), list(handles.keys()), loc="upper center", ncol=len(handles),
                           bbox_to_anchor=(0.5, 1.04))
            _save(fig, out, "fig_fl_accuracy_curves", written)
    cost = flat[flat["family"] == "fl_cost"]
    if len(cost):
        g = cost.groupby(["model", "clients", "method", "d"]).agg(
            upload_bytes=("mean_upload_bytes_client", "mean"), client_encrypt_s=("mean_client_encrypt_s", "mean"),
            server_aggregate_s=("mean_server_aggregate_s", "mean"), decrypt_s=("mean_decrypt_s", "mean"),
            client_train_s=("mean_client_train_s", "mean"), final_acc=("final_test_acc", "mean")).reset_index()
        g["upload_vs_plain"] = g["upload_bytes"] / (4 * g["d"])
        _csv(g, out, "table_fl_cost", written)
        sub = g[(g["clients"] == g["clients"].max()) & (g["model"] == ("mlp" if "mlp" in set(g["model"]) else g["model"].iloc[0]))]
        if len(sub):
            _bar_methods(plt, sub.rename(columns={"upload_bytes": "upload_bytes_client"}), "upload_bytes_client",
                         "bytes per client per round", out, "fig_fl_upload", written)
            s2 = sub.copy()
            s2["crypto_s"] = s2["client_encrypt_s"].fillna(0)
            _bar_methods(plt, s2[s2["method"] != "plain"], "crypto_s", "client encrypt time per round (s)", out,
                         "fig_fl_client_time", written)
        for m in ("sable", "lwe", "ckks"):
            row = g[(g["method"] == m) & (g["model"] == "mlp")]
            if len(row):
                notes.append(f"FL cost (MLP, d={int(row['d'].iloc[0])}): {METHOD_LABEL[m]} uploads {row['upload_vs_plain'].mean():.1f}x the plaintext update.")


def build_report(project: Path, commit: str) -> dict[str, Any]:
    out = project / "results" / commit[:12]
    out.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    notes: list[str] = []
    checks = []
    sources = {}
    for stage, fn in (("crypto", crypto_section), ("fl", fl_section)):
        rows, used = _load_stage(project, stage, commit)
        sources[stage] = {"commit": used, "tasks_ok": len(rows)}
        if not rows:
            checks.append({"name": f"{stage} results present", "passed": False, "detail": "no task results found"})
            continue
        try:
            fn(rows, out, written, notes)
            checks.append({"name": f"{stage} tables and figures built", "passed": True, "detail": f"{len(rows)} task results from {used}"})
        except Exception as exc:  # noqa: BLE001
            import traceback

            checks.append({"name": f"{stage} tables and figures built", "passed": False, "detail": f"{type(exc).__name__}: {exc}"})
            (out / f"error_{stage}.txt").write_text(traceback.format_exc())
    lines = ["# SABLE-HE experiment results", "", f"Code commit: {commit}", "",
             "## Sources", ""] + [f"- {k}: {v['tasks_ok']} task results (commit {v['commit']})" for k, v in sources.items()]
    lines += ["", "## Key findings (computed from the tables)", ""] + [f"- {n}" for n in notes]
    lines += ["", "## Files", ""] + [f"- {w}" for w in written] + [""]
    (out / "REPORT.md").write_text("\n".join(lines))
    return {"checks": checks, "out_dir": str(out), "written": written, "notes": notes}
