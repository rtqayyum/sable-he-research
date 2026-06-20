# Tensor and model adapters

The FL adapter flattens inputs into scalar values, encrypts each scalar, and stores a `TensorSpec` that restores the original structure after decryption.

Supported inputs:

```python
# Python list
[0.1, -0.2, 0.3]

# Dict of layers
{"dense/kernel": [[0.1, 0.2]], "dense/bias": [0.0]}

# NumPy array
np.array([0.1, 0.2])

# Keras model or Keras get_weights() list
model.get_weights()
model

# TensorFlow eager tensor
some_tensor

# PyTorch tensor
some_torch_tensor
```

Keras model workflow:

```python
from sable.fl import EncryptedFLAggregator, assign_model_weights

agg = EncryptedFLAggregator(kp, scale=1000)
encrypted_clients = [agg.encrypt_model(client_model) for client_model in client_models]
enc_avg = agg.fedavg(encrypted_clients, sample_counts)
weights = agg.decrypt_model(enc_avg)
assign_model_weights(global_model, weights)
```

For maximum portability, public examples use lists and NumPy arrays. TensorFlow/Keras/PyTorch imports are optional.
