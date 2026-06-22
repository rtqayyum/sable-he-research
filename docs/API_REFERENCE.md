# API reference overview

Important imports:

```python
from sable import PRESETS, keygen_sable, encrypt, expand, compact_sable, decrypt_sable
from sable import operations as ops
from sable.fl import EncryptedFLAggregator, PlainFLAggregator
from sable import pqc
from sable import cryptanalysis
```

Core arithmetic helpers:

- `ops.add`, `ops.sub`, `ops.neg`
- `ops.scalar_mul`, `ops.square`, `ops.mul`
- `ops.gate_and`, `ops.gate_or`, `ops.gate_xor`, `ops.gate_not`

Research status: APIs are stable for experimentation, but parameter sets are not certified.
