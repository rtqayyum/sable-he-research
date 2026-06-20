# Operation Support

SABLE-HE is a leveled arithmetic HE candidate over a prime field `F_q`.

| Operation | Supported? | Notes |
|---|---:|---|
| Addition | yes | Matrix addition in expanded representation. |
| Subtraction | yes | Add scaled by `-1`. |
| Negation | yes | Public scalar `-1`. |
| Public constant | yes | `beta * I` encrypts a public constant in the expanded GSW representation. |
| Public scalar multiplication | yes | Scale every matrix entry. |
| Encrypted multiplication | yes | Native nonlinear operation; consumes multiplicative depth. |
| Square | yes | Specialized as multiplication by itself. |
| Public power | yes | Repeated square-and-multiply; quickly consumes depth. |
| Inversion/division | limited | Nonzero inverse via `x^(q-2)` only; not efficient and undefined at zero. |
| Comparison/order | no native operation | Needs Boolean/polynomial circuit encoding. |
| Boolean NOT | yes | `1 - x`. |
| Boolean AND | yes | `xy`. |
| Boolean OR | yes | `x + y - xy`. |
| Boolean XOR | yes | `x + y - 2xy` over odd prime fields. |
| Boolean implication | yes | `1 - x + xy`. |

The package includes tests and examples for these low-degree operations. Multiplication is the main bottleneck, but the package is not limited to multiplication.
