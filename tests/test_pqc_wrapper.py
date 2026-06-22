import copy
import pytest

from sable import pqc


def test_demo_provider_requires_explicit_opt_in():
    with pytest.raises(pqc.InsecureDemoProviderError):
        pqc.DemoPQCProvider()


def test_pqc_envelope_roundtrip_json():
    provider = pqc.DemoPQCProvider(allow_insecure_demo=True, seed=b"test-seed")
    recipient = provider.kem_keypair()
    signer = provider.signature_keypair()
    payload = {"weights": [1, 2, 3], "round": 1}
    env = pqc.make_signed_federated_update_envelope(
        payload,
        sample_count=10,
        round_id="r1",
        client_id="c1",
        recipient_kem_public_key=recipient.public_key,
        sender_signature_secret_key=signer.secret_key,
        sender_signature_public_key=signer.public_key,
        provider=provider,
    )
    opened, metadata = pqc.open_federated_update_envelope(
        env,
        recipient_kem_secret_key=recipient.secret_key,
        trusted_sender_signature_public_key=signer.public_key,
        provider=provider,
    )
    assert opened == payload
    assert metadata["sample_count"] == 10
    assert metadata["round_id"] == "r1"


def test_pqc_envelope_tamper_rejected():
    provider = pqc.DemoPQCProvider(allow_insecure_demo=True, seed=b"tamper-seed")
    recipient = provider.kem_keypair()
    signer = provider.signature_keypair()
    env = pqc.seal_json(
        {"x": 1},
        recipient_kem_public_key=recipient.public_key,
        sender_signature_secret_key=signer.secret_key,
        sender_signature_public_key=signer.public_key,
        provider=provider,
    )
    data = env.to_dict()
    data["metadata"]["evil"] = True
    with pytest.raises(pqc.AuthenticationError):
        pqc.open_json(data, recipient_kem_secret_key=recipient.secret_key, provider=provider)


def test_pqc_capability_report_has_defaults():
    report = pqc.capability_report()
    assert report["default_suite"]["kem"] == "ML-KEM-768"
    assert report["default_suite"]["signature"] == "ML-DSA-65"
