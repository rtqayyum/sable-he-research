"""Paper figures from a results folder (the CSV tables written by the report stage).

    python -m evaluation.paper_figures <results-dir> [<out-dir>]

Figures are sized for IEEE two-column papers (single column 3.5 in, double
7.16 in).  Each method has a fixed colour and marker everywhere; colour is
never the only cue (markers, line styles and direct labels carry identity).
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

from evaluation.analyze import METHOD_COLOR, METHOD_LABEL, MARKERS, INK, MUTED, GRID

ONE_COL, TWO_COL = 3.5, 7.16
ORDER = ["plain", "secagg", "lwe", "bfv", "ckks", "sable_ln", "sable", "paillier"]
SHORT = {"plain": "Plaintext", "secagg": "SecAgg+", "lwe": "LWE-KAHE", "bfv": "BFV", "ckks": "CKKS",
         "sable_ln": "SABLE-HE (low noise)", "sable": "SABLE-HE", "paillier": "Paillier-3072"}
R_COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300"]


def _plt():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({
        "font.size": 7.5, "axes.titlesize": 8, "axes.labelsize": 7.5, "legend.fontsize": 6.8, "xtick.labelsize": 6.8,
        "ytick.labelsize": 6.8, "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED,
        "text.color": INK, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5, "axes.spines.top": False,
        "axes.spines.right": False, "lines.linewidth": 1.4, "lines.markersize": 3.6, "savefig.dpi": 300, "pdf.fonttype": 42,
        "legend.frameon": False, "axes.titlepad": 4,
    })
    return plt


def _save(fig, out: Path, name: str, written: list[str]) -> None:
    for ext in ("pdf", "png"):
        fig.savefig(out / f"{name}.{ext}", bbox_inches="tight", pad_inches=0.02)
    written.append(name)
    import matplotlib.pyplot as plt

    plt.close(fig)


def _pow2(n: int) -> str:
    return f"$2^{{{int(np.log2(n))}}}$"


# --------------------------------------------------------------------------- crypto


def fig_two_sparse(res: Path, out: Path, written: list[str]) -> None:
    plt = _plt()
    t = pd.read_csv(res / "table_attack_two_sparse.csv")
    ns, ratios = sorted(t["n"].unique()), sorted(t["ratio"].unique())
    agg = t.groupby(["n", "ratio"])["exact_rate"].mean().unstack()
    fig, (a, b) = plt.subplots(1, 2, figsize=(TWO_COL, 2.1), gridspec_kw={"width_ratios": [1.0, 1.15], "wspace": 0.32})
    M = agg.reindex(index=ns, columns=ratios).values
    a.imshow(np.nan_to_num(M, nan=0.0), cmap="Blues", vmin=0, vmax=1.25, aspect="auto", origin="lower")
    for i in range(len(ns)):
        for j in range(len(ratios)):
            v = M[i, j]
            txt, col = ("–", MUTED) if np.isnan(v) else (f"{v:.0%}", "white" if v > 0.6 else INK)
            a.text(j, i, txt, ha="center", va="center", fontsize=6.3, color=col)
    a.set_xticks(range(len(ratios)), [str(r) for r in ratios])
    a.set_yticks(range(len(ns)), [_pow2(n) for n in ns])
    a.set_xlabel("public samples $m$ / $n$")
    a.set_ylabel("secret dimension $n$")
    a.set_title("(a) exact secret recovery (all $\\eta$, 3 seeds)")
    a.grid(False)
    ok = t[t["exact_rate"] > 0]
    etas = sorted(ok["eta"].unique())
    for c, e in zip(R_COLORS, etas):
        s = ok[ok["eta"] == e]
        b.scatter(s["n"] * s["ratio"], s["seconds"], s=12, color=c, edgecolor="white", linewidth=0.4,
                  marker="osD^"[etas.index(e) % 4], label=f"$\\eta$ = {e:g}", zorder=3)
    b.set_xscale("log")
    b.set_yscale("log")
    b.set_xlabel("public samples $m$")
    b.set_ylabel("attack time (s, one core)")
    b.set_title("(b) time of successful attacks")
    b.legend(loc="upper left")
    _save(fig, out, "fig_attack_two_sparse", written)


def fig_known_plaintext(res: Path, out: Path, written: list[str]) -> None:
    plt = _plt()
    t = pd.read_csv(res / "table_attack_known_plaintext.csv")
    t = t[t["eta"] > 0]
    fig, ax = plt.subplots(figsize=(ONE_COL, 2.0))
    x = np.logspace(-3.3, 1.6, 300)
    ax.plot(x, np.exp(-x), color=MUTED, linestyle="--", linewidth=1.1, label="predicted $(1-\\eta)^{n+1}$")
    ns = sorted(t["n"].unique())
    for c, n in zip(R_COLORS, ns):
        s = t[t["n"] == n]
        ax.scatter(s["eta_times_N"], s["success_rate"], s=13, color=c, edgecolor="white", linewidth=0.4,
                   marker="osD^v"[ns.index(n) % 5], label=f"$n$ = {n}", zorder=3)
    ax.set_xscale("log")
    ax.set_xlabel("$\\eta\\,(n+1)$")
    ax.set_ylabel("key-recovery rate")
    ax.set_ylim(-0.04, 1.04)
    ax.legend(loc="lower left", ncol=1, handletextpad=0.2, fontsize=5.9, borderaxespad=0.2, labelspacing=0.25)
    _save(fig, out, "fig_attack_known_plaintext", written)


def fig_aggregation_failures(res: Path, out: Path, written: list[str]) -> None:
    plt = _plt()
    from matplotlib.lines import Line2D

    t = pd.read_csv(res / "table_aggregation_correctness.csv")
    etas = sorted(t["eta"].unique())
    Rs = [r for r in sorted(t["R"].unique()) if r <= 51]
    floor = 1e-7
    fig, axes = plt.subplots(1, len(etas), figsize=(TWO_COL, 2.05), sharey=True, gridspec_kw={"wspace": 0.12})
    for ax, eta in zip(axes, etas):
        for c, R in zip(R_COLORS, Rs):
            s = t[(t["eta"] == eta) & (t["R"] == R)].sort_values("K")
            ax.plot(s["K"], np.clip(s["failure_bound"], floor, 1), color=c, linestyle=":", linewidth=1.0)
            y = s["coord_failure_rate"].values
            ax.plot(s["K"], np.maximum(y, floor), color=c, linewidth=1.3)
            hit = y > 0
            ax.scatter(s["K"][hit], y[hit], s=10, color=c, zorder=3)
            ax.scatter(s["K"][~hit], np.full((~hit).sum(), floor), s=10, facecolor="white", edgecolor=c, linewidth=0.9, zorder=3)
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_title(f"$\\eta$ = {eta:g}")
        ax.set_xlabel("clients $K$")
    axes[0].set_ylabel("coordinate failure rate")
    handles = [Line2D([], [], color=c, linewidth=1.3, label=f"$R$ = {R}") for c, R in zip(R_COLORS, Rs)]
    handles += [Line2D([], [], color=MUTED, linewidth=1.3, label="measured"),
                Line2D([], [], color=MUTED, linestyle=":", linewidth=1.0, label="analytic bound"),
                Line2D([], [], color=MUTED, marker="o", markerfacecolor="white", linestyle="none", label="no failure observed")]
    fig.legend(handles=handles, loc="lower center", ncol=8, bbox_to_anchor=(0.5, 0.97), handlelength=1.6, columnspacing=1.0)
    _save(fig, out, "fig_aggregation_failures", written)


def fig_she_cost(res: Path, out: Path, written: list[str]) -> None:
    plt = _plt()
    t = pd.read_csv(res / "table_she_benchmarks.csv")
    fig, (a, b) = plt.subplots(1, 2, figsize=(TWO_COL, 2.0), gridspec_kw={"wspace": 0.38})
    for i, k in enumerate(sorted(t["k"].unique())):
        s = t[t["k"] == k].sort_values("n")
        a.plot(s["n"], s["mul_s"], color=R_COLORS[i], marker="osD"[i], label=f"$k$ = {k}")
        b.plot(s["n"], s["product_bytes"] / 1e9, color=R_COLORS[i], marker="osD"[i], label=f"$k$ = {k}")
    for ax in (a, b):
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xlabel("secret dimension $n$")
    a.set_ylabel("multiply time per replica (s)")
    b.set_ylabel("product size per replica (GB)")
    a.legend(loc="upper left")
    _save(fig, out, "fig_she_cost", written)


# --------------------------------------------------------------------------- FL


def fig_fl_accuracy(res: Path, out: Path, written: list[str]) -> None:
    plt = _plt()
    from matplotlib.lines import Line2D

    H = pd.read_csv(res / "table_fl_curves.csv")
    K = int(H["clients"].max())
    panels = [(ds, part) for ds in ("mnist", "fmnist") for part in ("iid", "dir0.1")]
    models = ["lr", "mlp", "cnn"]
    fig, axes = plt.subplots(len(models), len(panels), figsize=(TWO_COL, 4.3), sharex=True, gridspec_kw={"hspace": 0.32, "wspace": 0.3})
    for i, model in enumerate(models):
        for j, (ds, part) in enumerate(panels):
            ax = axes[i, j]
            sel = H[(H["dataset"] == ds) & (H["partition"] == part) & (H["model"] == model) & (H["clients"] == K)]
            curves = {m: sel[sel["method"] == m].groupby("round")["test_acc"].mean() for m in ("plain", "sable", "ckks")}
            p = curves["plain"]
            ax.plot(p.index, p.values, color=METHOD_COLOR["plain"], linewidth=1.2)
            for m, start in (("sable", 5), ("ckks", 10)):
                c = curves[m]
                idx = [r for r in c.index if r % 10 == start % 10 and r >= start]
                ax.plot(idx, c.loc[idx].values, linestyle="none", marker=MARKERS[m], markersize=3.6,
                        markerfacecolor="white" if m == "ckks" else METHOD_COLOR[m], markeredgecolor=METHOD_COLOR[m],
                        markeredgewidth=0.9)
            lo = min(c.iloc[2:].min() for c in curves.values())
            ax.set_ylim(lo - 0.01, max(c.max() for c in curves.values()) + 0.01)
            if i == 0:
                ax.set_title(f"{'MNIST' if ds == 'mnist' else 'Fashion-MNIST'}, {'IID' if part == 'iid' else 'Dirichlet 0.1'}")
            if j == 0:
                ax.set_ylabel(f"{model.upper()} test accuracy")
            if i == len(models) - 1:
                ax.set_xlabel("round")
    handles = [Line2D([], [], color=METHOD_COLOR["plain"], linewidth=1.2, label="Plaintext FedAvg"),
               Line2D([], [], color=METHOD_COLOR["sable"], marker=MARKERS["sable"], linestyle="none", label="SABLE-HE"),
               Line2D([], [], color=METHOD_COLOR["ckks"], marker=MARKERS["ckks"], markerfacecolor="white", linestyle="none", label="CKKS")]
    fig.legend(handles=handles, loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.0))
    fig.subplots_adjust(top=0.9)
    _save(fig, out, "fig_fl_accuracy", written)


def fig_fl_gap(res: Path, out: Path, written: list[str]) -> None:
    plt = _plt()
    H = pd.read_csv(res / "table_fl_curves.csv")
    key = ["dataset", "model", "partition", "clients", "seed", "round"]
    W = H.pivot_table(index=key, columns="method", values="test_acc").reset_index()
    fig, ax = plt.subplots(figsize=(ONE_COL, 1.9))
    for m in ("sable", "ckks"):
        g = (W[m] - W["plain"]) * 100
        d = W.assign(gap=g).groupby("round")["gap"]
        lo, hi, mean = d.quantile(0.05), d.quantile(0.95), d.mean()
        ax.fill_between(lo.index, lo.values, hi.values, color=METHOD_COLOR[m], alpha=0.2, linewidth=0)
        ax.plot(mean.index, mean.values, color=METHOD_COLOR[m], linestyle="-" if m == "sable" else "--",
                label=f"{'SABLE-HE' if m == 'sable' else 'CKKS'}: mean, 5–95% band")
    ax.axhline(0, color=MUTED, linewidth=0.6)
    ax.set_xlabel("round")
    ax.set_ylabel("$\\Delta$ accuracy vs plaintext (pp)")
    ax.legend(loc="upper right", fontsize=6.2)
    _save(fig, out, "fig_fl_gap", written)


def fig_client_scaling(res: Path, out: Path, written: list[str], model: str = "mlp") -> None:
    plt = _plt()
    c = pd.read_csv(res / "table_fl_cost.csv")
    c = c[c["model"] == model]
    metrics = [("upload_bytes", "upload per client per round (bytes)"), ("client_encrypt_s", "client encryption per round (s)"),
               ("server_aggregate_s", "server aggregation per round (s)")]
    fig, axes = plt.subplots(1, 3, figsize=(TWO_COL, 2.25), gridspec_kw={"wspace": 0.42})
    for ax, (col, ylabel) in zip(axes, metrics):
        for m in ORDER:
            s = c[c["method"] == m].sort_values("clients")
            if not len(s) or (m == "plain" and col != "upload_bytes"):
                continue
            ax.plot(s["clients"], s[col].astype(float).clip(lower=1e-4), color=METHOD_COLOR[m], marker=MARKERS[m],
                    markersize=3.2, linestyle="--" if m == "plain" else "-", zorder=5 if m == "plain" else 3,
                    label=SHORT[m])
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_xlabel("clients $K$")
        ax.set_ylabel(ylabel)
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc="upper center", ncol=4, bbox_to_anchor=(0.5, -0.02), handlelength=1.8, columnspacing=1.2)
    d = int(c["d"].iloc[0])
    fig.suptitle(f"{model.upper()} ({d:,} parameters); SABLE-HE replicas grow with $K$ to keep failures below $10^{{-12}}$",
                 y=1.03, fontsize=7.2, color=MUTED)
    _save(fig, out, f"fig_client_scaling_{model}", written)


def fig_upload_bars(res: Path, out: Path, written: list[str], model: str = "mlp", K: int = 100) -> None:
    plt = _plt()
    c = pd.read_csv(res / "table_fl_cost.csv")
    s = c[(c["model"] == model) & (c["clients"] == K)].set_index("method").reindex(ORDER).dropna(subset=["upload_bytes"])
    fig, ax = plt.subplots(figsize=(ONE_COL, 2.1))
    y = np.arange(len(s))[::-1]
    ax.barh(y, s["upload_bytes"], color=[METHOD_COLOR[m] for m in s.index], height=0.62, edgecolor="white", linewidth=1.0)
    for yi, (m, row) in zip(y, s.iterrows()):
        mb = row["upload_bytes"] / 1e6
        ax.text(row["upload_bytes"] * 1.12, yi, f"{mb:.2f} MB  (×{row['upload_vs_plain']:.1f})" if mb < 10 else f"{mb:.0f} MB  (×{row['upload_vs_plain']:.0f})",
                va="center", fontsize=6.4, color=INK)
    ax.set_yticks(y, [SHORT[m] for m in s.index])
    ax.set_xscale("log")
    ax.set_xlim(right=s["upload_bytes"].max() * 30)
    ax.set_xlabel(f"upload per client per round (bytes), {model.upper()}, $K$ = {K}")
    ax.grid(axis="y", visible=False)
    _save(fig, out, f"fig_upload_{model}_K{K}", written)


def main(argv: list[str]) -> int:
    res = Path(argv[1])
    out = Path(argv[2]) if len(argv) > 2 else res / "paper_figures"
    out.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for f in (fig_two_sparse, fig_known_plaintext, fig_aggregation_failures, fig_she_cost, fig_fl_accuracy, fig_fl_gap,
              fig_client_scaling, fig_upload_bars):
        f(res, out, written)
    print("\n".join(written))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
