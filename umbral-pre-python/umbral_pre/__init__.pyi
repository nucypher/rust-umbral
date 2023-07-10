from typing import Optional, Tuple, List, final


@final
class SecretKey:

    @staticmethod
    def random() -> SecretKey:
        ...

    def public_key(self) -> PublicKey:
        ...

    def to_be_bytes(self) -> bytes:
        ...

    @staticmethod
    def from_be_bytes(data: bytes) -> SecretKey:
        ...


@final
class SecretKeyFactory:

    @staticmethod
    def random() -> SecretKeyFactory:
        ...

    @staticmethod
    def seed_size() -> int:
        ...

    def make_secret(self, label: bytes) -> bytes:
        ...

    def make_key(self, label: bytes) -> SecretKey:
        ...

    def make_factory(self, label: bytes) -> SecretKeyFactory:
        ...

    @staticmethod
    def from_secure_randomness(seed: bytes) -> SecretKeyFactory:
        ...


@final
class PublicKey:

    @staticmethod
    def from_compressed_bytes(data: bytes) -> PublicKey:
        ...

    def to_compressed_bytes(self) -> bytes:
        ...

    @staticmethod
    def recover_from_prehash(prehash: bytes, signature: RecoverableSignature) -> PublicKey:
        ...


@final
class Signer:

    def __init__(self, secret_key: SecretKey):
        ...

    def sign(self, message: bytes) -> Signature:
        ...

    def verifying_key(self) -> PublicKey:
        ...


@final
class Signature:

    def verify(self, verifying_pk: PublicKey, message: bytes) -> bool:
        ...

    @staticmethod
    def from_der_bytes(data: bytes) -> Signature:
        ...

    def to_der_bytes(self) -> bytes:
        ...

    @staticmethod
    def from_be_bytes(data: bytes) -> Signature:
        ...

    def to_be_bytes(self) -> bytes:
        ...


@final
class RecoverableSignature:

    @staticmethod
    def from_be_bytes(data: bytes) -> RecoverableSignature:
        ...

    def to_be_bytes(self) -> bytes:
        ...


@final
class Capsule:

    @staticmethod
    def from_bytes(data: bytes) -> Capsule:
        ...

    def __bytes__(self) -> bytes:
        ...

    def to_bytes_simple(self) -> bytes:
        ...


@final
class KeyFrag:

    def verify(
            self,
            verifying_pk: PublicKey,
            delegating_pk: Optional[PublicKey] = ...,
            receiving_pk: Optional[PublicKey] = ...,
    ) -> VerifiedKeyFrag:
        ...

    def skip_verification(self) -> VerifiedKeyFrag:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> KeyFrag:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class VerifiedKeyFrag:

    def __bytes__(self) -> bytes:
        ...

    def unverify(self) -> KeyFrag:
        ...


def generate_kfrags(
        delegating_sk: SecretKey,
        receiving_pk: PublicKey,
        signer: Signer,
        threshold: int,
        shares: int,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
) -> List[VerifiedKeyFrag]:
    ...


@final
class CapsuleFrag:

    def verify(
            self,
            capsule: Capsule,
            verifying_pk: PublicKey,
            delegating_pk: PublicKey,
            receiving_pk: PublicKey,
    ) -> VerifiedCapsuleFrag:
        ...

    def skip_verification(self) -> VerifiedCapsuleFrag:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> CapsuleFrag:
        ...

    def __bytes__(self) -> bytes:
        ...

    def to_bytes_simple(self) -> bytes:
        ...


@final
class VerifiedCapsuleFrag:

    def __bytes__(self) -> bytes:
        ...

    def unverify(self) -> CapsuleFrag:
        ...

    def to_bytes_simple(self) -> bytes:
        ...


def reencrypt(capsule: Capsule, kfrag: VerifiedKeyFrag) -> VerifiedCapsuleFrag:
    ...


@final
class CurvePoint:
    coordinates: Tuple[bytes, bytes]


@final
class Parameters:

    def __init__(self, *args) -> None:
        ...

    u: CurvePoint


@final
class ReencryptionEvidence:

    def __init__(
            self,
            capsule: Capsule,
            vcfrag: VerifiedCapsuleFrag,
            verifying_pk: PublicKey,
            delegating_pk: PublicKey,
            receiving_pk: PublicKey,
    ):
        ...

    def __bytes__(self) -> bytes:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> ReencryptionEvidence:
        ...

    e: CurvePoint
    ez: CurvePoint
    e1: CurvePoint
    e1h: CurvePoint
    e2: CurvePoint

    v: CurvePoint
    vz: CurvePoint
    v1: CurvePoint
    v1h: CurvePoint
    v2: CurvePoint

    uz: CurvePoint
    u1: CurvePoint
    u1h: CurvePoint
    u2: CurvePoint

    kfrag_validity_message_hash: bytes
    kfrag_signature_v: bool
