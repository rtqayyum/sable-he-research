"""Small FL aggregation benchmark for the Python research implementation."""

from __future__ import annotations

import argparse
import time

from sable import PRESETS, keygen_c7
from sable.fl import EncryptedFLAggregator


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clients", type=int, default=3)
    parser.add_argument("--dim", type=int, default=8)
    parser.add_argument("--scale", type=int, default=1000)
    parser.add_argument("--preset", default="fl_demo")
    args = parser.parse_args()

    params = PRESETS[args.preset]
    kp = keygen_c7(params, seed=123, mode="coordinate")
    agg = EncryptedFLAggregator(kp, scale=args.scale, seed=1000)

    models = [[0.001 * (i + j + 1) for j in range(args.dim)] for i in range(args.clients)]
    counts = [10 + i for i in range(args.clients)]

    t0 = time.perf_counter()
    encrypted = [agg.encrypt_model(model, seed=1000 + i) for i, model in enumerate(models)]
    t1 = time.perf_counter()
    enc_avg = agg.fedavg(encrypted, counts)
    t2 = time.perf_counter()
    result = agg.decrypt_model(enc_avg)
    t3 = time.perf_counter()

    print({
        "clients": args.clients,
        "dim": args.dim,
        "encrypt_s": t1 - t0,
        "aggregate_s": t2 - t1,
        "decrypt_s": t3 - t2,
        "first_result": result[0] if result else None,
    })


if __name__ == "__main__":
    main()
