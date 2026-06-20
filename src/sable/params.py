"""Parameter objects and presets for the SABLE-HE validation prototype."""

from __future__ import annotations

from dataclasses import dataclass

from .field import is_prime


@dataclass(frozen=True)
class SableParams:
    name: str
    q: int
    n: int
    k: int
    eta: float
    n_c: int
    m_c: int
    eta_c: float
    replicas: int = 1
    c2_block_size: int = 2

    def __post_init__(self) -> None:
        if not is_prime(self.q):
            raise ValueError("q must be prime for this prototype")
        if self.q < 3:
            raise ValueError("q must be at least 3")
        if self.n <= 0 or self.n_c <= 0 or self.m_c <= 0:
            raise ValueError("dimensions must be positive")
        if self.k < 0 or self.k > self.n:
            raise ValueError("k must satisfy 0 <= k <= n")
        if not (0 <= self.eta <= 1):
            raise ValueError("eta must be in [0, 1]")
        if not (0 <= self.eta_c <= 1):
            raise ValueError("eta_c must be in [0, 1]")
        if self.replicas <= 0:
            raise ValueError("replicas must be positive")
        if self.c2_block_size <= 0:
            raise ValueError("c2_block_size must be positive")

    @property
    def N(self) -> int:
        return self.n + 1


PRESETS: dict[str, SableParams] = {

    "fl_demo_clean": SableParams(
        name="fl_demo_clean",
        q=1000003,
        n=16,
        k=1,
        eta=0.0,
        n_c=16,
        m_c=41,
        eta_c=0.0,
        replicas=3,
        c2_block_size=1,
    ),
    "toy_clean": SableParams(
        name="toy_clean",
        q=127,
        n=16,
        k=2,
        eta=0.0,
        n_c=16,
        m_c=41,
        eta_c=0.0,
        replicas=3,
    ),
    "toy_noisy": SableParams(
        name="toy_noisy",
        q=127,
        n=24,
        k=2,
        eta=0.002,
        n_c=24,
        m_c=81,
        eta_c=0.001,
        replicas=11,
    ),
    "toy_depth2": SableParams(
        name="toy_depth2",
        q=127,
        n=24,
        k=1,
        eta=0.0001,
        n_c=24,
        m_c=129,
        eta_c=0.0005,
        replicas=17,
    ),
    "prototype_medium": SableParams(
        name="prototype_medium",
        q=65537,
        n=512,
        k=3,
        eta=2**-20,
        n_c=256,
        m_c=1024,
        eta_c=2**-20,
        replicas=31,
    ),
    "exploratory_high_noise": SableParams(
        name="exploratory_high_noise",
        q=65537,
        n=8192,
        k=2,
        eta=0.01,
        n_c=4096,
        m_c=8192,
        eta_c=0.01,
        replicas=31,
    ),
    "candidate_depth1_rough": SableParams(
        name="candidate_depth1_rough",
        q=65537,
        n=512,
        k=3,
        eta=2**-10,
        n_c=512,
        m_c=4096,
        eta_c=2**-14,
        replicas=41,
    ),
    # C2 presets use a small prime field so q^ell block dictionaries are feasible.
    "c2_toy_clean": SableParams(
        name="c2_toy_clean",
        q=7,
        n=12,
        k=1,
        eta=0.0,
        n_c=16,
        m_c=37,
        eta_c=0.0,
        replicas=3,
        c2_block_size=2,
    ),
    "c2_toy_noisy": SableParams(
        name="c2_toy_noisy",
        q=7,
        n=16,
        k=1,
        eta=0.0005,
        n_c=24,
        m_c=97,
        eta_c=0.0005,
        replicas=11,
        c2_block_size=2,
    ),
    "c2_design_smallq": SableParams(
        name="c2_design_smallq",
        q=7,
        n=512,
        k=2,
        eta=2**-16,
        n_c=512,
        m_c=4096,
        eta_c=2**-14,
        replicas=31,
        c2_block_size=3,
    ),
    # Large-q C2 presets are for estimator-only exploration; key generation is
    # infeasible when q^ell is enormous.
    "c2_candidate_depth1": SableParams(
        name="c2_candidate_depth1",
        q=65537,
        n=512,
        k=3,
        eta=2**-12,
        n_c=512,
        m_c=4096,
        eta_c=0.01,
        replicas=129,
        c2_block_size=1,
    ),
    "c2_exploratory_large": SableParams(
        name="c2_exploratory_large",
        q=65537,
        n=2048,
        k=2,
        eta=2**-14,
        n_c=1024,
        m_c=8192,
        eta_c=0.02,
        replicas=129,
        c2_block_size=1,
    ),
    # C4 projective-basis presets.  c2_block_size is reused as the C4 block size.
    "c4_projective_toy_clean": SableParams(
        name="c4_projective_toy_clean",
        q=7,
        n=12,
        k=1,
        eta=0.0,
        n_c=16,
        m_c=37,
        eta_c=0.0,
        replicas=3,
        c2_block_size=2,
    ),
    "c4_projective_toy_noisy": SableParams(
        name="c4_projective_toy_noisy",
        q=7,
        n=16,
        k=1,
        eta=0.0005,
        n_c=24,
        m_c=97,
        eta_c=0.0005,
        replicas=11,
        c2_block_size=2,
    ),

    # C7 relation-screened compactor presets.  These make C7 the conservative
    # main compaction candidate after C6 rejected full projective dictionaries.
    "c7_standard_toy_clean": SableParams(
        name="c7_standard_toy_clean",
        q=7,
        n=14,
        k=1,
        eta=0.0,
        n_c=16,
        m_c=37,
        eta_c=0.0,
        replicas=3,
        c2_block_size=3,
    ),
    "c7_standard_toy_noisy": SableParams(
        name="c7_standard_toy_noisy",
        q=7,
        n=17,
        k=1,
        eta=0.0005,
        n_c=24,
        m_c=97,
        eta_c=0.0005,
        replicas=11,
        c2_block_size=3,
    ),
    "c7_screened_toy_clean": SableParams(
        name="c7_screened_toy_clean",
        q=7,
        n=14,
        k=1,
        eta=0.0,
        n_c=16,
        m_c=37,
        eta_c=0.0,
        replicas=3,
        c2_block_size=3,
    ),
    "c7_design_smallq": SableParams(
        name="c7_design_smallq",
        q=7,
        n=512,
        k=2,
        eta=2**-16,
        n_c=512,
        m_c=4096,
        eta_c=2**-14,
        replicas=31,
        c2_block_size=3,
    ),

    # Federated-learning documentation/demo preset with a larger prime field
    # for fixed-point model-weight examples.  This preset is intended for
    # reproducible examples and API validation, not as a certified parameter set.
    "fl_demo": SableParams(
        name="fl_demo",
        q=2147483647,
        n=14,
        k=1,
        eta=0.0,
        n_c=16,
        m_c=37,
        eta_c=0.0,
        replicas=3,
        c2_block_size=1,
    ),
    "fl_preview": SableParams(
        name="fl_preview",
        q=1000003,
        n=16,
        k=1,
        eta=0.0,
        n_c=16,
        m_c=41,
        eta_c=0.0,
        replicas=3,
        c2_block_size=1,
    ),

}


# Public FL examples use a larger prime field to make fixed-point FedAvg demos
# easier to read without modular wraparound.  These parameters are for
# reproducible examples and API validation; choose reviewed parameters before
# security-sensitive deployment.
PRESETS["fl_demo_clean"] = SableParams(
    name="fl_demo_clean",
    q=1_000_003,
    n=16,
    k=1,
    eta=0.0,
    n_c=16,
    m_c=41,
    eta_c=0.0,
    replicas=3,
    c2_block_size=1,
)

# Backward-compatible alias for the v0.2 FL documentation/tests.
PRESETS["fl_demo"] = PRESETS["fl_demo_clean"]
