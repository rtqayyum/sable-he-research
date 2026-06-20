import math

import pytest

from sable import PRESETS, keygen_c7
from sable import fl


def _kp():
    return keygen_c7(PRESETS["fl_demo"], seed=123, mode="coordinate")


def test_encrypted_fedavg_vector_matches_clear_fedavg():
    kp = _kp()
    clients = [[0.12, -0.34, 1.20], [0.10, -0.30, 1.25], [0.20, -0.40, 1.10]]
    counts = [80, 20, 100]
    encrypted = [fl.encrypt_array(kp, c, scale=1000, seed=1000 * i + 7) for i, c in enumerate(clients)]
    result = fl.decrypt_array(kp, fl.fedavg_encrypted(kp, encrypted, counts))
    expected = fl.clear_aggregate_arrays(clients, method="fedavg", weights=counts)
    assert result == pytest.approx(expected, abs=1e-12)


def test_plain_min_max_median_trimmed_and_krum():
    values = [[1.0, 10.0], [2.0, 20.0], [100.0, 30.0], [3.0, 40.0], [4.0, 50.0]]
    assert fl.clear_aggregate_arrays(values, method="min") == [1.0, 10.0]
    assert fl.clear_aggregate_arrays(values, method="max") == [100.0, 50.0]
    assert fl.clear_aggregate_arrays(values, method="median") == [3.0, 30.0]
    assert fl.clear_aggregate_arrays(values, method="trimmed_mean", trim_ratio=0.2) == pytest.approx([3.0, 30.0])
    selected = fl.PlainFLAggregator().krum(values, f=0)
    assert selected in values


def test_encrypted_min_is_explicitly_not_silent():
    with pytest.raises(fl.EncryptedComparisonNotSupported):
        fl.min_encrypted([])


def test_numpy_array_round_trip_if_available():
    np = pytest.importorskip("numpy")
    kp = _kp()
    a = np.array([1.25, -2.5, 3.75])
    encrypted = fl.encrypt_array(kp, a, scale=1000, seed=99)
    out = fl.decrypt_array(kp, encrypted)
    assert isinstance(out, np.ndarray)
    assert out.tolist() == pytest.approx(a.tolist())


def test_keras_style_weight_list_supports_fedavg():
    np = pytest.importorskip("numpy")
    kp = _kp()
    w1 = [np.array([1.0, 2.0]), np.array([[3.0], [4.0]])]
    w2 = [np.array([2.0, 4.0]), np.array([[6.0], [8.0]])]
    e1 = fl.encrypt_model_weights(kp, w1, scale=1000, seed=11)
    e2 = fl.encrypt_model_weights(kp, w2, scale=1000, seed=22)
    avg = fl.decrypt_model_weights(kp, fl.fedavg_encrypted(kp, [e1, e2], [1, 3]))
    assert avg[0].tolist() == pytest.approx([1.75, 3.5])
    assert avg[1].reshape(-1).tolist() == pytest.approx([5.25, 7.0])
