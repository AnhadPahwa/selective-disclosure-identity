from __future__ import annotations

import csv
from pathlib import Path
from statistics import mean, median
import matplotlib.pyplot as plt

BASE_DIR = Path(__file__).resolve().parent
TIER1_CSV = BASE_DIR / "tier1_tests.csv"
TIER2_CSV = BASE_DIR / "tier2_tests.csv"

# Drop first valid run to reduce warm-up distortion
EXCLUDE_FIRST_VALID_RUN = True


def to_float(value: str) -> float:
    return float(value.strip())


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def filter_valid_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [r for r in rows if r.get("scenario", "").strip() == "valid"]


def maybe_drop_first(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    if EXCLUDE_FIRST_VALID_RUN and len(rows) > 1:
        return rows[1:]
    return rows


def five_num_summary(xs: list[float]) -> str:
    xs = sorted(xs)
    n = len(xs)
    q1 = xs[n // 4]
    med = median(xs)
    q3 = xs[(3 * n) // 4]
    return (
        f"n={n}, mean={mean(xs):.2f}, median={med:.2f}, "
        f"min={xs[0]:.2f}, q1={q1:.2f}, q3={q3:.2f}, max={xs[-1]:.2f}"
    )


def style_axis(ax, title: str, ylabel: str):
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.grid(True, axis="y", alpha=0.3)


def make_tier1_verify_boxplot(t1_verify: list[float]) -> None:
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.boxplot([t1_verify], labels=["Tier 1 verify"])
    style_axis(ax, "Tier 1 Verification Latency", "Latency (ms)")
    fig.tight_layout()
    fig.savefig(BASE_DIR / "tier1_verify_boxplot.png", dpi=300)
    plt.close(fig)


def make_tier2_latency_panels(
    t2_verify: list[float],
    t2_prove: list[float],
    t2_total: list[float],
) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(10, 5))

    # Left panel: Tier 2 verify only
    axes[0].boxplot([t2_verify], labels=["Verify"])
    style_axis(axes[0], "Tier 2 Verification Latency", "Latency (ms)")

    # Right panel: prove + total
    axes[1].boxplot([t2_prove, t2_total], labels=["Prove", "Total"])
    style_axis(axes[1], "Tier 2 Proof and Total Latency", "Latency (ms)")

    fig.tight_layout()
    fig.savefig(BASE_DIR / "tier2_latency_panels.png", dpi=300)
    plt.close(fig)


def make_verify_comparison_split_axes(
    t1_verify: list[float],
    t2_verify: list[float],
) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(10, 5))

    axes[0].boxplot([t1_verify], labels=["Tier 1"])
    style_axis(axes[0], "Tier 1 Verification", "Latency (ms)")

    axes[1].boxplot([t2_verify], labels=["Tier 2"])
    style_axis(axes[1], "Tier 2 Verification", "Latency (ms)")

    fig.suptitle("Verification Latency Comparison by Tier")
    fig.tight_layout()
    fig.savefig(BASE_DIR / "verify_comparison_split_axes.png", dpi=300)
    plt.close(fig)


def make_tier2_prove_line(t2_prove: list[float]) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.5))
    runs = list(range(1, len(t2_prove) + 1))
    ax.plot(runs, t2_prove, marker="o")
    style_axis(ax, "Tier 2 Proof Generation by Run", "Latency (ms)")
    ax.set_xlabel("Valid run index")
    fig.tight_layout()
    fig.savefig(BASE_DIR / "tier2_prove_by_run.png", dpi=300)
    plt.close(fig)


def main() -> None:
    if not TIER1_CSV.exists():
        raise FileNotFoundError(f"Missing {TIER1_CSV}")
    if not TIER2_CSV.exists():
        raise FileNotFoundError(f"Missing {TIER2_CSV}")

    t1_rows = maybe_drop_first(filter_valid_rows(load_csv_rows(TIER1_CSV)))
    t2_rows = maybe_drop_first(filter_valid_rows(load_csv_rows(TIER2_CSV)))

    if not t1_rows:
        raise ValueError("No Tier 1 valid rows found.")
    if not t2_rows:
        raise ValueError("No Tier 2 valid rows found.")

    t1_verify = [to_float(r["verify_ms"]) for r in t1_rows]
    t2_verify = [to_float(r["verify_ms"]) for r in t2_rows]
    t2_prove = [to_float(r["prove_ms"]) for r in t2_rows]
    t2_total = [to_float(r["total_ms"]) for r in t2_rows]

    make_tier1_verify_boxplot(t1_verify)
    make_tier2_latency_panels(t2_verify, t2_prove, t2_total)
    make_verify_comparison_split_axes(t1_verify, t2_verify)
    make_tier2_prove_line(t2_prove)

    print("Wrote charts to:", BASE_DIR)
    print()
    print("Tier 1 verify:", five_num_summary(t1_verify))
    print("Tier 2 verify:", five_num_summary(t2_verify))
    print("Tier 2 prove :", five_num_summary(t2_prove))
    print("Tier 2 total :", five_num_summary(t2_total))


if __name__ == "__main__":
    main()