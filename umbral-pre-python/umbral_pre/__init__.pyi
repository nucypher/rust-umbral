from typing import Optional, Tuple, List, Sequence


class SecretKey:
    @staticmethod
    def random() -> SecretKey:
        ...


class SecretKeyFactory:

    @staticmethod
    def random() -> SecretKeyFactory:
        ...

    def secret_key_by_label(self, label: bytes) -> SecretKey:
        ...


class PublicKey:
    @staticmethod
    def from_secret_key(sk: SecretKey) -> PublicKey:
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


class Capsule: ...


def encrypt(pk: PublicKey, plaintext: bytes) -> Tuple[Capsule, bytes]:
    ...


def decrypt_original(sk: SecretKey, capsule: Capsule, ciphertext: bytes) -> bytes:
    ...


class KeyFrag:
    def verify(
            self,
            verifying_pk: PublicKey,
            delegating_pk: Optional[PublicKey],
            receiving_pk: Optional[PublicKey],
            ) -> VerifiedKeyFrag:
        ...


class VerifiedKeyFrag:
    def from_verified_bytes(data: bytes) -> VerifiedKeyFrag:
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


class VerifiedCapsuleFrag:
    ...


def reencrypt(capsule: Capsule, kfrag: VerifiedKeyFrag) -> VerifiedCapsuleFrag:
    ...


def decrypt_reencrypted(
        decrypting_sk: SecretKey,
        delegating_pk: PublicKey,
        capsule: Capsule,
        cfrags: Sequence[VerifiedCapsuleFrag],
        ciphertext: bytes,
        ) -> Optional[bytes]:
    ...
