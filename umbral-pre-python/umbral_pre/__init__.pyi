from typing import Optional, Tuple, List, Sequence


class SecretKey:

    @staticmethod
    def random() -> SecretKey:
        ...

    def public_key(self) -> PublicKey:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> SecretKey:
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

    def make_secret(self, label: bytes) -> bytes:
        ...

    def make_key(self, label: bytes) -> SecretKey:
        ...

    def make_factory(self, label: bytes) -> SecretKeyFactory:
        ...

    @staticmethod
    def from_secure_randomness(data: bytes) -> SecretKeyFactory:
        ...


class PublicKey:

    @staticmethod
    def from_compressed_bytes(data: bytes) -> PublicKey:
        ...

    def to_compressed_bytes(self) -> bytes:
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
    def from_der_bytes(data: bytes) -> Signature:
        ...

    def to_der_bytes(self) -> bytes:
        ...


class Capsule:

    @staticmethod
    def from_bytes(data: bytes) -> Capsule:
        ...

    def __bytes__(self) -> bytes:
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
    def from_bytes(data: bytes) -> KeyFrag:
        ...

    def __bytes__(self) -> bytes:
        ...


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


class VerifiedCapsuleFrag:

    def __bytes__(self) -> bytes:
        ...

    def unverify(self) -> CapsuleFrag:
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
