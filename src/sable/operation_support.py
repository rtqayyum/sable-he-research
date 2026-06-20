"""Operation-support comparison matrix for SABLE-HE and common FHE families."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class OperationRow:
    operation: str
    sable_c4: str
    tfhe_fhew: str
    bfv_bgv: str
    ckks: str
    note: str


ROWS = [
    OperationRow("encrypted addition", "native; matrix add", "native via integer/Boolean APIs", "native", "native approximate", "Cheap for all major HE families."),
    OperationRow("encrypted subtraction", "native; add scaled by -1", "native for integer APIs; Boolean via gates", "native", "native approximate", "Same cost class as addition."),
    OperationRow("negation", "native scalar -1", "native for integer APIs", "native", "native approximate", "Unary linear operation."),
    OperationRow("plaintext/scalar add", "native beta I", "native/API dependent", "native", "native approximate", "SABLE uses beta times identity in expanded GSW form."),
    OperationRow("plaintext/scalar multiply", "native matrix scale", "native/API dependent", "native", "native approximate", "Linear public operation."),
    OperationRow("encrypted multiplication", "native but depth-limited", "Boolean AND or integer multiplication with bootstrapping/carries", "native depth-consuming", "native approximate depth-consuming", "Main nonlinear operation."),
    OperationRow("square", "native as multiplication", "integer API or gate circuit", "native", "native approximate", "Specialized optimizations not yet implemented in prototype."),
    OperationRow("public power", "repeated square/multiply", "integer API/gate circuit", "repeated multiply", "repeated approximate multiply", "Consumes multiplicative depth."),
    OperationRow("division", "not native; nonzero inverse x^(q-2) only", "integer API supports semantics in TFHE-rs", "not native generally", "not exact; approximate reciprocal possible", "SABLE division is expensive and undefined at zero."),
    OperationRow("comparison/order", "not native", "strong target via Boolean/integer circuits", "possible but expensive circuit", "usually via scheme switching or approximation", "SABLE needs polynomial or Boolean encoding."),
    OperationRow("Boolean AND", "xy over bits", "native bootstrapped gate", "arithmetic encoding", "not natural", "SABLE is competitive conceptually only for low-depth batches."),
    OperationRow("Boolean OR", "x+y-xy", "native bootstrapped gate", "arithmetic encoding", "not natural", "Uses one multiplication over F_q."),
    OperationRow("Boolean XOR", "x+y-2xy over odd q", "native bootstrapped gate", "arithmetic encoding", "not natural", "In F_2 XOR is linear; SABLE uses odd prime q, so this polynomial has one multiplication."),
]


def rows_as_dicts() -> list[dict[str, str]]:
    return [asdict(r) for r in ROWS]


def markdown_table() -> str:
    headers = ["operation", "SABLE-C4", "TFHE/FHEW", "BFV/BGV", "CKKS", "note"]
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for row in ROWS:
        d = asdict(row)
        lines.append("| " + " | ".join(d[h if h != "SABLE-C4" else "sable_c4"] if h != "TFHE/FHEW" and h != "BFV/BGV" and h != "CKKS" else "" for h in []) + " |")
    # Construct explicitly to keep field names readable.
    lines = ["| Operation | SABLE-C4 | TFHE/FHEW | BFV/BGV | CKKS | Note |", "|---|---|---|---|---|---|"]
    for r in ROWS:
        lines.append(f"| {r.operation} | {r.sable_c4} | {r.tfhe_fhew} | {r.bfv_bgv} | {r.ckks} | {r.note} |")
    return "\n".join(lines)
