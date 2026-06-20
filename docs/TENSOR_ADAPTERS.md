# Tensor and model adapters

The `sable.fl` adapter layer flattens model-like structures before encryption and restores the same structure after decryption.

## Supported inputs

| Input type | Support |
|---|---|
| Python scalar | yes |
| `list` / `tuple` | yes, nested |
| `dict` | yes, insertion-order keys preserved |
| NumPy array | yes, if NumPy is installed |
| PyTorch tensor | yes, restored as a torch tensor if PyTorch is installed |
| TensorFlow-style tensor | yes, through `.numpy()`; restored as TensorFlow tensor if TensorFlow is installed, otherwise NumPy |
| Keras-style model | yes, through `get_weights()`; assignment through `set_weights()` |

## Example: NumPy arrays

```python
import numpy as np
from sable import PRESETS
from sable.fl import EncryptedFLAggregator

agg = EncryptedFLAggregator.from_params(PRESETS["fl_demo_clean"], scale=1000)

x = np.array([0.1, 0.2, 0.3])
y = np.array([0.3, 0.4, 0.5])

ex = agg.encrypt_model(x, seed=1)
ey = agg.encrypt_model(y, seed=2)

avg = agg.decrypt_model(agg.mean([ex, ey]))
print(avg)
```

## Example: Keras-style models

```python
# model_a and model_b are Keras models with the same architecture.
from sable.fl import EncryptedFLAggregator, assign_model_weights
from sable import PRESETS

agg = EncryptedFLAggregator.from_params(PRESETS["fl_demo_clean"], scale=1000)

e1 = agg.encrypt_model(model_a, seed=1)
e2 = agg.encrypt_model(model_b, seed=2)

global_weights = agg.decrypt_model(agg.fedavg([e1, e2], [100, 80]))
assign_model_weights(global_model, global_weights)
```

## Restored object type

For lists, tuples, dictionaries, NumPy arrays, Torch tensors, and TensorFlow tensors, SABLE restores the same logical structure. For Keras-style model objects, it restores the weight list because the model architecture cannot be reconstructed safely from weights alone.
