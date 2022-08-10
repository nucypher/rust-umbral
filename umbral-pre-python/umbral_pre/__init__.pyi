from typing import Optional, Tuple, List, Sequence


class SecretKey:

    @staticmethod
    def random() -> SecretKey:
        ...

    def public_key(self) -> PublicKey:
        ...

    def to_secret_bytes(self) -> bytes:
        ...

    @staticmethod
    def from_bytes() -> SecretKey:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


class SecretKeyFactory:

    @staticmethod
    def random() -> SecretKeyFactory:
        ...

    @staticmethod
    def seed_size() -> int:
        ...

    @staticmethod
    def from_secure_randomness(seed: bytes) -> SecretKeyFactory:
        ...

    def make_key(self, label: bytes) -> SecretKey:
        ...

    def make_factory(self, label: bytes) -> SecretKeyFactory:
        ...

    def to_secret_bytes(self) -> bytes:
        ...

    @staticmethod
    def from_bytes() -> SecretKeyFactory:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


class PublicKey:

    @staticmethod
    def from_bytes() -> PublicKey:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


class Signer:

    def __init__(self, secret_key: SecretKey):
        ...

    def sign(self, message: bytes) -> Signature:
        ...

    def verifying_key(self) -> PublicKey:
        ...


class Signature:

    def verify(self, verifying_pk: PublicKey, message: bytes) -> bool:
        ...

    @staticmethod
    def from_bytes() -> Signature:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


class Capsule:

    @staticmethod
    def serialized_size() -> int:
        ...


def encrypt(delegating_pk: PublicKey, plaintext: bytes) -> Tuple[Capsule, bytes]:
    ...


def decrypt_original(delegating_sk: SecretKey, capsule: Capsule, ciphertext: bytes) -> bytes:
    ...


class KeyFrag:

    def verify(
            self,
            verifying_pk: PublicKey,
            delegating_pk: Optional[PublicKey],
            receiving_pk: Optional[PublicKey],
            ) -> VerifiedKeyFrag:
        ...

    def skip_verification(self) -> VerifiedKeyFrag:
        ...

    @staticmethod
    def from_bytes() -> KeyFrag:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


class VerifiedKeyFrag:

    def from_verified_bytes(self, data: bytes) -> VerifiedKeyFrag:
        ...

    def unverify(self) -> KeyFrag:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


def generate_kfrags(
        delegating_sk: SecretKey,
        receiving_pk: PublicKey,
        signer: SecretKey,
        threshold: int,
        shares: int,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
        ) -> List[VerifiedKeyFrag]:
    ...


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
    def from_bytes() -> CapsuleFrag:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


class VerifiedCapsuleFrag:

    @staticmethod
    def from_verified_bytes(data: bytes) -> VerifiedCapsuleFrag:
        ...

    def unverify(self) -> CapsuleFrag:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


def reencrypt(capsule: Capsule, kfrag: VerifiedKeyFrag) -> VerifiedCapsuleFrag:
    ...


def decrypt_reencrypted(
        receiving_sk: SecretKey,
        delegating_pk: PublicKey,
        capsule: Capsule,
        cfrags: Sequence[VerifiedCapsuleFrag],
        ciphertext: bytes,
        ) -> Optional[bytes]:
    ...
