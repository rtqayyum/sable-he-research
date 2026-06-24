"""Phase 10 compaction-theory example."""

from sable.compaction_theory import analyze_compaction_family, comparison_table, theorem_statements


def main() -> None:
    print("Compaction-family comparison")
    for row in comparison_table(q=31, n=512, block_width=2, m_c=192):
        print(row["family"], "entries/block=", row["entries_per_block"], "role=", row["suggested_role"])

    print("\nCoordinate analysis")
    report = analyze_compaction_family("coordinate", q=31, n=512, block_width=1)
    print(report.to_jsonable())

    print("\nTheorem names")
    for thm in theorem_statements():
        print("-", thm["name"])


if __name__ == "__main__":
    main()
