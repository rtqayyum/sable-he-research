"""Phase 2 post-quantum wrapper layer for SABLE-HE.

This module provides a small, versioned envelope format around SABLE-HE payloads
using post-quantum key-encapsulation and signature interfaces.  It is designed
so that production deployments can plug in approved implementations of
ML-KEM/ML-DSA/SLH-DSA while the research package can still run deterministic
schema and integration tests without shipping a certified crypto module.

The bundled DemoPQCProvider is deliberately non-secure and exists only for
examples, unit tests, and format demonstrations.  Use a reviewed provider backed
by validated implementations for real deployments.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, MutableMapping, Protocol

SCHEMA_VERSION = "sable-pqc-envelope-v1"
DEFAULT_KEM = "ML-KEM-768"
DEFAULT_SIGNATURE = "ML-DSA-65"
DEFAULT_HASH = "SHA3-256"
DEFAULT_AEAD = "AES-256-GCM"


class PQCError(RuntimeError):
    """Base class for PQC wrapper errors."""


class BackendUnavailable(PQCError):
    """Raised when a requested cryptographic backend is not installed."""


class AuthenticationError(PQCError):
    """Raised when envelope authentication or signature verification fails."""


class InsecureDemoProviderError(PQCError):
    """Raised when the demo provider is requested without explicit opt-in."""


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialize an object as deterministic UTF-8 JSON bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def fingerprint(data: bytes, prefix: str = "sha3-256") -> str:
    return f"{prefix}:{hashlib.sha3_256(data).hexdigest()}"


def hkdf_sha3_256(secret: bytes, *, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Small HKDF-SHA3-256 implementation used to derive envelope AEAD keys."""
    if not salt:
        salt = b"\x00" * hashlib.sha3_256().digest_size
    prk = hmac.new(salt, secret, hashlib.sha3_256).digest()
    okm = b""
    prev = b""
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha3_256).digest()
        okm += prev
        counter += 1
    return okm[:length]


@dataclass(frozen=True)
class PQCSuite:
    """Algorithm labels for a SABLE PQC envelope."""

    kem: str = DEFAULT_KEM
    signature: str = DEFAULT_SIGNATURE
    hash: str = DEFAULT_HASH
    aead: str = DEFAULT_AEAD
    hybrid_mode: str = "pq-only"


@dataclass(frozen=True)
class PQCKeyPair:
    """Opaque public/secret key pair."""

    public_key: bytes
    secret_key: bytes
    algorithm: str
    key_type: str

    @property
    def public_fingerprint(self) -> str:
        return fingerprint(self.public_key)


@dataclass
class PQCEnvelope:
    """Portable sealed-and-signed SABLE payload envelope."""

    schema: str
    suite: PQCSuite
    payload_kind: str
    metadata: dict[str, Any]
    recipient_kem_public_key_fingerprint: str
    sender_signature_public_key: str
    kem_ciphertext: str
    nonce: str
    ciphertext: str
    aad: str
    signature: str = ""

    def unsigned_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["signature"] = ""
        return data

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PQCEnvelope":
        suite_data = data.get("suite", {})
        suite = suite_data if isinstance(suite_data, PQCSuite) else PQCSuite(**suite_data)
        return cls(
            schema=str(data["schema"]),
            suite=suite,
            payload_kind=str(data["payload_kind"]),
            metadata=dict(data.get("metadata", {})),
            recipient_kem_public_key_fingerprint=str(data["recipient_kem_public_key_fingerprint"]),
            sender_signature_public_key=str(data["sender_signature_public_key"]),
            kem_ciphertext=str(data["kem_ciphertext"]),
            nonce=str(data["nonce"]),
            ciphertext=str(data["ciphertext"]),
            aad=str(data["aad"]),
            signature=str(data.get("signature", "")),
        )

    @classmethod
    def from_json(cls, text: str) -> "PQCEnvelope":
        return cls.from_dict(json.loads(text))


class PQCProvider(Protocol):
    """Provider interface for PQ KEM and signature operations."""

    provider_name: str
    production_capable: bool

    def kem_keypair(self, algorithm: str = DEFAULT_KEM) -> PQCKeyPair: ...
    def encapsulate(self, public_key: bytes, algorithm: str = DEFAULT_KEM) -> tuple[bytes, bytes]: ...
    def decapsulate(self, ciphertext: bytes, secret_key: bytes, algorithm: str = DEFAULT_KEM) -> bytes: ...
    def signature_keypair(self, algorithm: str = DEFAULT_SIGNATURE) -> PQCKeyPair: ...
    def sign(self, message: bytes, secret_key: bytes, algorithm: str = DEFAULT_SIGNATURE) -> bytes: ...
    def verify(self, message: bytes, signature: bytes, public_key: bytes, algorithm: str = DEFAULT_SIGNATURE) -> bool: ...


class DemoPQCProvider:
    """Non-secure provider for examples and tests only.

    This provider has no cryptographic security.  It is intentionally gated by
    an explicit ``allow_insecure_demo`` flag so applications do not accidentally
    use it in production.
    """

    provider_name = "demo-nonsecure"
    production_capable = False

    def __init__(self, *, allow_insecure_demo: bool = False, seed: bytes | None = None) -> None:
        if not allow_insecure_demo:
            raise InsecureDemoProviderError(
                "DemoPQCProvider is non-secure. Pass allow_insecure_demo=True only for tests/examples."
            )
        self._counter = 0
        self._seed = seed or os.urandom(32)

    def _rand(self, n: int, label: bytes) -> bytes:
        out = b""
        while len(out) < n:
            self._counter += 1
            out += hashlib.shake_256(self._seed + label + self._counter.to_bytes(8, "big")).digest(64)
        return out[:n]

    def kem_keypair(self, algorithm: str = DEFAULT_KEM) -> PQCKeyPair:
        sk = self._rand(32, b"kem-sk")
        pk = sha3_256(b"demo-kem-pk" + sk)
        return PQCKeyPair(pk, sk, algorithm, "kem")

    def encapsulate(self, public_key: bytes, algorithm: str = DEFAULT_KEM) -> tuple[bytes, bytes]:
        ct = self._rand(48, b"kem-ct")
        ss = sha3_256(b"demo-kem-ss" + algorithm.encode() + public_key + ct)
        return ct, ss

    def decapsulate(self, ciphertext: bytes, secret_key: bytes, algorithm: str = DEFAULT_KEM) -> bytes:
        pk = sha3_256(b"demo-kem-pk" + secret_key)
        return sha3_256(b"demo-kem-ss" + algorithm.encode() + pk + ciphertext)

    def signature_keypair(self, algorithm: str = DEFAULT_SIGNATURE) -> PQCKeyPair:
        sk_core = self._rand(32, b"sig-sk")
        pk = sha3_256(b"demo-sig-pk" + sk_core)
        # Store pk with sk so the demo sign function can be verified by pk.
        return PQCKeyPair(pk, sk_core + pk, algorithm, "signature")

    def sign(self, message: bytes, secret_key: bytes, algorithm: str = DEFAULT_SIGNATURE) -> bytes:
        pk = secret_key[-32:]
        return hmac.new(pk, b"demo-sig" + algorithm.encode() + message, hashlib.sha3_256).digest()

    def verify(self, message: bytes, signature: bytes, public_key: bytes, algorithm: str = DEFAULT_SIGNATURE) -> bool:
        expected = hmac.new(public_key, b"demo-sig" + algorithm.encode() + message, hashlib.sha3_256).digest()
        return hmac.compare_digest(expected, signature)


class OQSPQCProvider:
    """Adapter for liboqs-python, when installed.

    The adapter is intentionally thin.  Deployments must pin liboqs/liboqs-python
    versions and select only standardized mechanisms such as ML-KEM and ML-DSA.
    """

    provider_name = "liboqs-python"
    production_capable = False  # liboqs-python describes itself as prototyping/evaluation software.

    def __init__(self) -> None:
        try:
            import oqs  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            raise BackendUnavailable("liboqs-python is not installed or liboqs is unavailable") from exc
        self.oqs = oqs

    def kem_keypair(self, algorithm: str = DEFAULT_KEM) -> PQCKeyPair:  # pragma: no cover - optional backend
        with self.oqs.KeyEncapsulation(algorithm) as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
        return PQCKeyPair(bytes(pk), bytes(sk), algorithm, "kem")

    def encapsulate(self, public_key: bytes, algorithm: str = DEFAULT_KEM) -> tuple[bytes, bytes]:  # pragma: no cover
        with self.oqs.KeyEncapsulation(algorithm) as kem:
            ct, ss = kem.encap_secret(public_key)
        return bytes(ct), bytes(ss)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes, algorithm: str = DEFAULT_KEM) -> bytes:  # pragma: no cover
        with self.oqs.KeyEncapsulation(algorithm, secret_key) as kem:
            ss = kem.decap_secret(ciphertext)
        return bytes(ss)

    def signature_keypair(self, algorithm: str = DEFAULT_SIGNATURE) -> PQCKeyPair:  # pragma: no cover
        with self.oqs.Signature(algorithm) as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
        return PQCKeyPair(bytes(pk), bytes(sk), algorithm, "signature")

    def sign(self, message: bytes, secret_key: bytes, algorithm: str = DEFAULT_SIGNATURE) -> bytes:  # pragma: no cover
        with self.oqs.Signature(algorithm, secret_key) as sig:
            return bytes(sig.sign(message))

    def verify(self, message: bytes, signature: bytes, public_key: bytes, algorithm: str = DEFAULT_SIGNATURE) -> bool:  # pragma: no cover
        with self.oqs.Signature(algorithm) as sig:
            return bool(sig.verify(message, signature, public_key))


def available_backend_names() -> list[str]:
    names = ["demo-nonsecure"]
    try:
        OQSPQCProvider()
        names.append("liboqs-python")
    except BackendUnavailable:
        pass
    return names


def get_provider(name: str = "demo", *, allow_insecure_demo: bool = False) -> PQCProvider:
    normalized = name.lower().replace("_", "-")
    if normalized in {"demo", "demo-nonsecure", "test"}:
        return DemoPQCProvider(allow_insecure_demo=allow_insecure_demo)
    if normalized in {"oqs", "liboqs", "liboqs-python"}:
        return OQSPQCProvider()
    raise BackendUnavailable(f"Unknown PQC provider: {name}")


def _xor_stream(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    stream = b""
    counter = 0
    while len(stream) < len(plaintext):
        counter_bytes = counter.to_bytes(8, "big")
        stream += hashlib.shake_256(b"sable-demo-aead" + key + nonce + aad + counter_bytes).digest(64)
        counter += 1
    return bytes(x ^ y for x, y in zip(plaintext, stream[: len(plaintext)]))


def _aead_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes, *, demo_only: bool) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    except Exception:
        if not demo_only:
            raise BackendUnavailable("cryptography[AESGCM] is required for real envelope encryption")
        ct = _xor_stream(key, nonce, aad, plaintext)
        tag = hmac.new(key, b"demo-aead" + nonce + aad + ct, hashlib.sha3_256).digest()
        return ct + tag
    return bytes(AESGCM(key).encrypt(nonce[:12], plaintext, aad))


def _aead_decrypt(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, *, demo_only: bool) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
    except Exception:
        if not demo_only:
            raise BackendUnavailable("cryptography[AESGCM] is required for real envelope decryption")
        if len(ciphertext) < 32:
            raise AuthenticationError("ciphertext too short")
        ct, tag = ciphertext[:-32], ciphertext[-32:]
        expected = hmac.new(key, b"demo-aead" + nonce + aad + ct, hashlib.sha3_256).digest()
        if not hmac.compare_digest(tag, expected):
            raise AuthenticationError("AEAD tag verification failed")
        return _xor_stream(key, nonce, aad, ct)
    try:
        return bytes(AESGCM(key).decrypt(nonce[:12], ciphertext, aad))
    except Exception as exc:
        raise AuthenticationError("AEAD decryption failed") from exc


def seal_bytes(
    payload: bytes,
    *,
    recipient_kem_public_key: bytes,
    sender_signature_secret_key: bytes,
    sender_signature_public_key: bytes,
    provider: PQCProvider,
    suite: PQCSuite | None = None,
    payload_kind: str = "bytes",
    metadata: Mapping[str, Any] | None = None,
    aad: Mapping[str, Any] | None = None,
) -> PQCEnvelope:
    """Seal and sign bytes into a SABLE PQC envelope."""
    suite = suite or PQCSuite()
    metadata_dict = dict(metadata or {})
    aad_dict = dict(aad or {})
    kem_ct, shared_secret = provider.encapsulate(recipient_kem_public_key, suite.kem)
    aad_bytes = canonical_json_bytes({"schema": SCHEMA_VERSION, "suite": asdict(suite), "aad": aad_dict, "payload_kind": payload_kind})
    key = hkdf_sha3_256(shared_secret, salt=sha3_256(aad_bytes), info=b"sable-pqc-envelope-v1", length=32)
    nonce = os.urandom(12)
    demo_only = not getattr(provider, "production_capable", False)
    ciphertext = _aead_encrypt(key, nonce, aad_bytes, payload, demo_only=demo_only)
    env = PQCEnvelope(
        schema=SCHEMA_VERSION,
        suite=suite,
        payload_kind=payload_kind,
        metadata=metadata_dict,
        recipient_kem_public_key_fingerprint=fingerprint(recipient_kem_public_key),
        sender_signature_public_key=b64e(sender_signature_public_key),
        kem_ciphertext=b64e(kem_ct),
        nonce=b64e(nonce),
        ciphertext=b64e(ciphertext),
        aad=b64e(aad_bytes),
    )
    sign_input = canonical_json_bytes(env.unsigned_dict())
    sig = provider.sign(sign_input, sender_signature_secret_key, suite.signature)
    env.signature = b64e(sig)
    return env


def open_bytes(
    envelope: PQCEnvelope | Mapping[str, Any] | str,
    *,
    recipient_kem_secret_key: bytes,
    provider: PQCProvider,
    trusted_sender_signature_public_key: bytes | None = None,
) -> bytes:
    """Verify and open a SABLE PQC envelope."""
    if isinstance(envelope, str):
        env = PQCEnvelope.from_json(envelope)
    elif isinstance(envelope, PQCEnvelope):
        env = envelope
    else:
        env = PQCEnvelope.from_dict(envelope)
    if env.schema != SCHEMA_VERSION:
        raise AuthenticationError(f"Unsupported envelope schema: {env.schema}")
    sender_pk = b64d(env.sender_signature_public_key)
    if trusted_sender_signature_public_key is not None and not hmac.compare_digest(sender_pk, trusted_sender_signature_public_key):
        raise AuthenticationError("sender signature public key does not match trusted key")
    sign_input = canonical_json_bytes(env.unsigned_dict())
    if not provider.verify(sign_input, b64d(env.signature), sender_pk, env.suite.signature):
        raise AuthenticationError("signature verification failed")
    kem_ct = b64d(env.kem_ciphertext)
    shared_secret = provider.decapsulate(kem_ct, recipient_kem_secret_key, env.suite.kem)
    aad_bytes = b64d(env.aad)
    key = hkdf_sha3_256(shared_secret, salt=sha3_256(aad_bytes), info=b"sable-pqc-envelope-v1", length=32)
    demo_only = not getattr(provider, "production_capable", False)
    return _aead_decrypt(key, b64d(env.nonce), aad_bytes, b64d(env.ciphertext), demo_only=demo_only)


def seal_json(payload: Any, **kwargs: Any) -> PQCEnvelope:
    return seal_bytes(canonical_json_bytes(payload), payload_kind=kwargs.pop("payload_kind", "json"), **kwargs)


def open_json(envelope: PQCEnvelope | Mapping[str, Any] | str, **kwargs: Any) -> Any:
    return json.loads(open_bytes(envelope, **kwargs).decode("utf-8"))


def make_signed_federated_update_envelope(
    update: Any,
    *,
    sample_count: int,
    round_id: str,
    client_id: str,
    recipient_kem_public_key: bytes,
    sender_signature_secret_key: bytes,
    sender_signature_public_key: bytes,
    provider: PQCProvider,
    suite: PQCSuite | None = None,
) -> PQCEnvelope:
    """Seal a federated-learning update with metadata for server ingestion."""
    metadata = {
        "application": "federated-learning",
        "round_id": round_id,
        "client_id": client_id,
        "sample_count": sample_count,
        "payload_format": "json-canonical",
    }
    return seal_json(
        update,
        recipient_kem_public_key=recipient_kem_public_key,
        sender_signature_secret_key=sender_signature_secret_key,
        sender_signature_public_key=sender_signature_public_key,
        provider=provider,
        suite=suite or PQCSuite(),
        payload_kind="sable.fl.model-update",
        metadata=metadata,
        aad={"round_id": round_id, "client_id": client_id, "sample_count": sample_count},
    )


def open_federated_update_envelope(
    envelope: PQCEnvelope | Mapping[str, Any] | str,
    *,
    recipient_kem_secret_key: bytes,
    provider: PQCProvider,
    trusted_sender_signature_public_key: bytes | None = None,
) -> tuple[Any, dict[str, Any]]:
    """Open a federated-learning envelope and return ``(payload, metadata)``."""
    env = PQCEnvelope.from_json(envelope) if isinstance(envelope, str) else (envelope if isinstance(envelope, PQCEnvelope) else PQCEnvelope.from_dict(envelope))
    payload = open_json(
        env,
        recipient_kem_secret_key=recipient_kem_secret_key,
        provider=provider,
        trusted_sender_signature_public_key=trusted_sender_signature_public_key,
    )
    return payload, dict(env.metadata)


def capability_report() -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION,
        "default_suite": asdict(PQCSuite()),
        "available_backends": available_backend_names(),
        "production_note": (
            "The envelope format is backend-neutral. The bundled demo provider is non-secure. "
            "Production deployments must use reviewed implementations of ML-KEM/ML-DSA/SLH-DSA "
            "and a validated symmetric cryptographic module where certification is required."
        ),
    }
