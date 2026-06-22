import copy
import json

import pytest

from sable import pqc


def _demo_material(seed=b"phase2-hardening"):
    provider = pqc.DemoPQCProvider(allow_insecure_demo=True, seed=seed)
    recipient = provider.kem_keypair()
    signer = provider.signature_keypair()
    env = pqc.make_signed_federated_update_envelope(
        {"weights": [1, 2, 3], "round": 7},
        sample_count=42,
        round_id="round-hardening",
        client_id="client-hardening",
        recipient_kem_public_key=recipient.public_key,
        sender_signature_secret_key=signer.secret_key,
        sender_signature_public_key=signer.public_key,
        provider=provider,
    )
    return provider, recipient, signer, env


def test_get_provider_demo_is_explicitly_gated():
    with pytest.raises(pqc.InsecureDemoProviderError):
        pqc.get_provider("demo")
    provider = pqc.get_provider("demo", allow_insecure_demo=True)
    assert provider.provider_name == "demo-nonsecure"
    assert provider.production_capable is False


def test_envelope_json_roundtrip_preserves_schema_and_payload():
    provider, recipient, signer, env = _demo_material()
    text = env.to_json()
    restored = pqc.PQCEnvelope.from_json(text)
    opened, metadata = pqc.open_federated_update_envelope(
        restored,
        recipient_kem_secret_key=recipient.secret_key,
        provider=provider,
        trusted_sender_signature_public_key=signer.public_key,
    )
    assert opened == {"weights": [1, 2, 3], "round": 7}
    assert metadata["sample_count"] == 42
    assert restored.schema == pqc.SCHEMA_VERSION


def test_wrong_trusted_sender_key_is_rejected():
    provider, recipient, signer, env = _demo_material()
    wrong_signer = provider.signature_keypair()
    with pytest.raises(pqc.AuthenticationError):
        pqc.open_federated_update_envelope(
            env,
            recipient_kem_secret_key=recipient.secret_key,
            provider=provider,
            trusted_sender_signature_public_key=wrong_signer.public_key,
        )


def test_ciphertext_tampering_is_rejected_by_signature_before_decryption():
    provider, recipient, signer, env = _demo_material()
    data = env.to_dict()
    data["ciphertext"] = pqc.b64e(b"tampered" + pqc.b64d(data["ciphertext"]))
    with pytest.raises(pqc.AuthenticationError):
        pqc.open_json(data, recipient_kem_secret_key=recipient.secret_key, provider=provider)


def test_schema_tampering_is_rejected():
    provider, recipient, signer, env = _demo_material()
    data = env.to_dict()
    data["schema"] = "sable-pqc-envelope-v0"
    with pytest.raises(pqc.AuthenticationError):
        pqc.open_json(data, recipient_kem_secret_key=recipient.secret_key, provider=provider)


def test_capability_report_is_serializable_and_backend_neutral():
    report = pqc.capability_report()
    json.dumps(report)
    assert report["schema"] == pqc.SCHEMA_VERSION
    assert report["default_suite"]["kem"] == "ML-KEM-768"
    assert report["default_suite"]["signature"] == "ML-DSA-65"
