"""NumPy/Keras-style weight-list FedAvg example."""

import numpy as np

from sable import PRESETS, keygen_c7
from sable.fl import EncryptedFLAggregator


params = PRESETS["fl_demo_clean"]
kp = keygen_c7(params, seed=123, mode="coordinate")
agg = EncryptedFLAggregator(kp, scale=1000)

client_a = [np.array([1.0, 2.0]), np.array([[3.0], [4.0]])]
client_b = [np.array([2.0, 4.0]), np.array([[6.0], [8.0]])]

enc_a = agg.encrypt_model(client_a, seed=11)
enc_b = agg.encrypt_model(client_b, seed=22)

enc_avg = agg.fedavg([enc_a, enc_b], [1, 3])
weights = agg.decrypt_model(enc_avg)

print(weights[0])
print(weights[1])
