# Supported Operations

SABLE-HE operates over a prime field `F_q`. Messages are represented modulo `q`.

## Native arithmetic helpers

The module `sable.operations` supports:

| Operation | Function | Notes |
|---|---|---|
| Addition | `ops.add(x, y)` | Native linear operation. |
| Subtraction | `ops.sub(x, y)` | Native linear operation. |
| Negation | `ops.neg(x)` | Public scalar `-1`. |
| Public scalar multiplication | `ops.scalar_mul(x, a)` | Multiplies encrypted message by public `a`. |
| Public constants | `ops.const_like(x, a)` | Produces an expanded ciphertext for public `a`. |
| Add public constant | `ops.add_plain(x, a)` | Adds public `a`. |
| Subtract public constant | `ops.sub_plain(x, a)` | Computes `x-a`. |
| Multiplication | `ops.mul(x, y)` | Main nonlinear operation. |
| Square | `ops.square(x)` | Equivalent to `x*x`. |
| Public powers | `ops.pow_plain(x, e)` | Repeated multiplication; depth grows. |
| Nonzero inverse | `ops.inverse_nonzero(x)` | Uses `x^(q-2)`; only for small toy fields. |

## Boolean gates

Bits are encoded as `0` and `1` in `F_q`:

| Gate | Function | Polynomial |
|---|---|---|
| NOT | `ops.gate_not(x)` | `1-x` |
| AND | `ops.gate_and(x, y)` | `xy` |
| OR | `ops.gate_or(x, y)` | `x+y-xy` |
| XOR | `ops.gate_xor(x, y)` | `x+y-2xy` |
| NAND | `ops.gate_nand(x, y)` | `1-xy` |
| NOR | `ops.gate_nor(x, y)` | `1-(x+y-xy)` |
| XNOR | `ops.gate_xnor(x, y)` | `1-(x+y-2xy)` |

## Not native

The package does not provide efficient native comparison, sorting, branching, lookup tables, or general division. These require separate circuit encodings and can become deep quickly.

## Multiplicative depth

Addition and public scalar multiplication are cheap relative to multiplication. Multiplication grows support and noise. Practical validation should keep multiplicative depth small.
