"""SABLE-HE public research package.

Includes homomorphic arithmetic helpers, stable SABLE-HE compaction APIs,
and federated-learning aggregation utilities. The package does not ship
externally certified security parameters.
"""

from .version import __version__, __release_name__
from .params import PRESETS, SableParams
from .sable import (
    KeyPair,
    compact,
    compact_c2,
    compact_block_c2,
    compact_seeded_block_c2,
    compact_basis_c4,
    compact_c4_basis,
    compact_screened_c7,
    compact_c7_screened,
    compact_c7,
    decrypt,
    decrypt_c2,
    decrypt_block_c2,
    decrypt_seeded_block_c2,
    decrypt_basis_c4,
    decrypt_c4_basis,
    decrypt_screened_c7,
    decrypt_c7_screened,
    decrypt_c7,
    direct_decrypt_gsw,
    encrypt,
    eval_add,
    eval_mul,
    expand,
    keygen,
    keygen_sable,
    compact_sable,
    decrypt_sable,
    keygen_c2,
    keygen_block_c2,
    keygen_seeded_block_c2,
    keygen_basis_c4,
    keygen_c4_basis,
    keygen_screened_c7,
    keygen_c7_screened,
    keygen_c7,
)

from . import operations
from .operations import (
    add as eval_arith_add,
    add_plain as eval_add_const,
    const_like,
    div_nonzero,
    gate_and as bool_and,
    gate_nand as bool_nand,
    gate_nor as bool_nor,
    gate_not as bool_not,
    gate_or as bool_or,
    gate_xnor as bool_xnor,
    gate_xor as bool_xor,
    inverse_nonzero,
    mul as eval_arith_mul,
    neg as eval_neg,
    one_like,
    plain_sub as eval_const_minus,
    pow_plain as eval_power,
    scalar_mul as eval_scalar,
    square as eval_square,
    sub as eval_sub,
    sub_plain as eval_sub_const,
    zero_like,
)

from . import fl
from .fl import (
    AggregationResult,
    EncryptedArray,
    EncryptedComparisonNotSupported,
    EncryptedFLAggregator,
    EncryptedModel,
    EncryptedTensor,
    FLCapability,
    FixedPointEncoder,
    PlainFLAggregator,
    TensorSpec,
    UnsupportedEncryptedAggregation,
    aggregate_after_decrypt,
    aggregate_plain_arrays,
    aggregate_plain_models,
    assign_model_weights,
    clear_aggregate_arrays,
    clear_aggregate_models,
    decrypt_aggregation,
    decrypt_array,
    decrypt_model,
    decrypt_model_weights,
    encrypt_array,
    encrypt_model,
    encrypt_model_weights,
    extract_model_weights,
    fedavg,
    fedavg_encrypted,
    fedsgd_encrypted,
    fl_capabilities,
    flatten_tree,
    max_after_decrypt,
    max_encrypted,
    mean_encrypted,
    median_after_decrypt,
    median_encrypted,
    min_after_decrypt,
    min_encrypted,
    secure_sum_encrypted,
    sum_encrypted,
    trimmed_mean_after_decrypt,
    unflatten_tree,
    weighted_average_encrypted,
    weighted_mean_encrypted,
    weighted_sum_encrypted,
)

from . import cryptanalysis
from .cryptanalysis import (
    attack_surface_report,
    challenge_info as cryptanalysis_challenge_info,
    known_answer_vector as cryptanalysis_known_answer_vector,
    red_team_template as cryptanalysis_red_team_template,
    write_challenge_bundle as write_cryptanalysis_bundle,
)

from . import hardening
from .hardening import (
    artifact_manifest,
    generate_kat_bundle,
    release_gate,
    scan_public_repo,
    verify_kat_bundle,
    version_consistency,
)

from . import pqc
from . import phase4
from .phase4 import (
    phase4_info,
    generate_kats as generate_phase4_kats,
    write_kat_bundle as write_phase4_kat_bundle,
    verify_kat_bundle as verify_phase4_kat_bundle,
    public_repo_hygiene,
    release_artifact_check,
)


from . import proofs
from .proofs import (
    proof_info,
    security_game_spec,
    proof_obligations,
    hybrid_steps,
    sample_ledger as proof_sample_ledger,
    proof_package_manifest,
    write_proof_package,
)

from . import standardization
from .standardization import (
    parameter_template as standardization_parameter_template,
    readiness_report as standardization_readiness_report,
    review_checklist as standardization_review_checklist,
    security_assumptions_spec as standardization_security_assumptions_spec,
    standardization_info,
    write_review_package as write_standardization_review_package,
)





from .pqc import (
    AuthenticationError,
    BackendUnavailable,
    DemoPQCProvider,
    InsecureDemoProviderError,
    OQSPQCProvider,
    PQCEnvelope,
    PQCError,
    PQCKeyPair,
    PQCSuite,
    available_backend_names,
    capability_report as pqc_capability_report,
    get_provider as get_pqc_provider,
    make_signed_federated_update_envelope,
    open_federated_update_envelope,
    open_json as pqc_open_json,
    seal_json as pqc_seal_json,
)

try:  # pragma: no cover - defensive compatibility shim
    from .arithmetic import OPERATION_PROFILES, OperationProfile
except Exception:  # pragma: no cover
    OPERATION_PROFILES = {}
    OperationProfile = object  # type: ignore

__all__ = [
    "proofs", "proof_info", "security_game_spec", "proof_obligations", "hybrid_steps", "proof_sample_ledger", "proof_package_manifest", "write_proof_package",
    "standardization", "standardization_info", "standardization_readiness_report", "standardization_security_assumptions_spec", "standardization_parameter_template", "standardization_review_checklist", "write_standardization_review_package",
    "phase4", "phase4_info", "generate_phase4_kats", "write_phase4_kat_bundle", "verify_phase4_kat_bundle", "public_repo_hygiene", "release_artifact_check",
    "__version__", "__release_name__", "SableParams", "PRESETS", "KeyPair",
    "keygen", "keygen_sable", "compact_sable", "decrypt_sable", "keygen_c2", "keygen_block_c2", "keygen_seeded_block_c2",
    "keygen_basis_c4", "keygen_c4_basis", "keygen_screened_c7", "keygen_c7_screened", "keygen_c7",
    "encrypt", "expand", "eval_add", "eval_mul", "compact", "compact_c2", "compact_block_c2",
    "compact_seeded_block_c2", "compact_basis_c4", "compact_c4_basis", "compact_screened_c7",
    "compact_c7_screened", "compact_c7", "decrypt", "decrypt_c2", "decrypt_block_c2",
    "decrypt_seeded_block_c2", "decrypt_basis_c4", "decrypt_c4_basis", "decrypt_screened_c7",
    "decrypt_c7_screened", "decrypt_c7", "direct_decrypt_gsw",
    "operations", "const_like", "zero_like", "one_like", "eval_arith_add", "eval_arith_mul",
    "eval_sub", "eval_neg", "eval_scalar", "eval_add_const", "eval_sub_const", "eval_const_minus",
    "eval_square", "eval_power", "inverse_nonzero", "div_nonzero", "bool_not", "bool_and",
    "bool_or", "bool_xor", "bool_nand", "bool_nor", "bool_xnor", "OPERATION_PROFILES", "OperationProfile",
    "fl", "AggregationResult", "EncryptedArray", "EncryptedComparisonNotSupported", "EncryptedFLAggregator",
    "EncryptedModel", "EncryptedTensor", "FLCapability", "FixedPointEncoder", "PlainFLAggregator", "TensorSpec",
    "UnsupportedEncryptedAggregation", "aggregate_after_decrypt", "aggregate_plain_arrays", "aggregate_plain_models",
    "assign_model_weights", "clear_aggregate_arrays", "clear_aggregate_models", "decrypt_aggregation",
    "decrypt_array", "decrypt_model", "decrypt_model_weights", "encrypt_array", "encrypt_model",
    "encrypt_model_weights", "extract_model_weights", "fedavg", "fedavg_encrypted", "fedsgd_encrypted",
    "fl_capabilities",
    "cryptanalysis", "attack_surface_report", "cryptanalysis_challenge_info",
    "cryptanalysis_known_answer_vector", "cryptanalysis_red_team_template", "write_cryptanalysis_bundle", "flatten_tree", "max_after_decrypt", "max_encrypted", "mean_encrypted",
    "median_after_decrypt", "median_encrypted", "min_after_decrypt", "min_encrypted", "secure_sum_encrypted",
    "sum_encrypted", "trimmed_mean_after_decrypt", "unflatten_tree", "weighted_average_encrypted",
    "weighted_mean_encrypted", "weighted_sum_encrypted",
    "pqc", "PQCError", "BackendUnavailable", "AuthenticationError", "InsecureDemoProviderError",
    "PQCSuite", "PQCKeyPair", "PQCEnvelope", "DemoPQCProvider", "OQSPQCProvider",
    "available_backend_names", "get_pqc_provider", "pqc_capability_report",
    "pqc_seal_json", "pqc_open_json", "make_signed_federated_update_envelope",
    "open_federated_update_envelope",
]

# Phase 7 candidate parameter-set framework
from . import parameter_sets
from . import attack_estimators_phase8
from .attack_estimators_phase8 import (
    attack_estimator_info,
    estimate_candidate as estimate_attack_candidate,
    write_attack_package as write_phase8_attack_package,
)
__all__.extend([
    "parameter_sets", "attack_estimators_phase8", "attack_estimator_info",
    "estimate_attack_candidate", "write_phase8_attack_package",
])

# Phase 8 estimator module is available as sable.lpn_estimators.

from . import lpn_estimator

from . import advanced_attacks

# Phase 9 benchmark-comparison framework
from . import benchmarking
from .benchmarking import (
    benchmark_info,
    workloads as benchmark_workloads,
    baseline_specs as benchmark_baseline_specs,
    run_sable_suite as run_sable_benchmark_suite,
    write_benchmark_package as write_phase9_benchmark_package,
)
__all__.extend([
    "benchmarking", "benchmark_info", "benchmark_workloads", "benchmark_baseline_specs",
    "run_sable_benchmark_suite", "write_phase9_benchmark_package",
])

# Phase 10 relation-resistant compaction theory framework
from . import compaction_theory
from .compaction_theory import (
    compaction_theory_info,
    analyze_compaction_family,
    comparison_table as compaction_comparison_table,
    theorem_statements as compaction_theorem_statements,
    review_checklist as compaction_review_checklist,
    write_compaction_package as write_phase10_compaction_package,
)
__all__.extend([
    "compaction_theory", "compaction_theory_info", "analyze_compaction_family",
    "compaction_comparison_table", "compaction_theorem_statements",
    "compaction_review_checklist", "write_phase10_compaction_package",
])
