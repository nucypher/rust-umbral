from typing import Optional, Tuple, List, Sequence


class SecretKey:

    @staticmethod
    def random() -> SecretKey:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


class SecretKeyFactory:

    @staticmethod
    def random() -> SecretKeyFactory:
        ...

    def secret_key_by_label(self, label: bytes) -> SecretKey:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


class PublicKey:

    @staticmethod
    def from_secret_key(sk: SecretKey) -> PublicKey:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


class Signer:

    def __init__(secret_key: SecretKey):
        ...

    def sign(message: bytes) -> Signature:
        ...

    def verifying_key() -> PublicKey:
        ...


class Signature:

    def verify(verifying_key: PublicKey, message: bytes) -> bool:
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

    @staticmethod
    def serialized_size() -> int:
        ...


class VerifiedKeyFrag:

    def from_verified_bytes(data: bytes) -> VerifiedKeyFrag:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


def generate_kfrags(
        delegating_sk: SecretKey,
        receiving_pk: PublicKey,
        signer: SecretKey,
        threshold: int,
        num_kfrags: int,
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

    @staticmethod
    def serialized_size() -> int:
        ...


class VerifiedCapsuleFrag:

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
