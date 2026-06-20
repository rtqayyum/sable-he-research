"""Encrypted FedAvg example for SABLE-HE."""

from sable import PRESETS
from sable.fl import EncryptedFLAggregator, PlainFLAggregator


def main() -> None:
    params = PRESETS["fl_demo_clean"]
    agg = EncryptedFLAggregator.from_params(params, key_seed=123, scale=1000)

    client_models = [
        [0.12, -0.34, 1.20],
        [0.10, -0.30, 1.25],
        [0.20, -0.40, 1.10],
    ]
    sample_counts = [80, 20, 100]

    encrypted = [agg.encrypt_model(model, seed=10_000 + i) for i, model in enumerate(client_models)]
    encrypted_global = agg.fedavg(encrypted, sample_counts)
    global_model = agg.decrypt_model(encrypted_global)

    reference = PlainFLAggregator().fedavg(client_models, sample_counts)

    print("encrypted FedAvg:", global_model)
    print("plaintext reference:", reference)


if __name__ == "__main__":
    main()
