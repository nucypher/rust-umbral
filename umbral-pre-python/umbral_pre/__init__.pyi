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
            signing_pk: PublicKey,
            delegating_pk: Optional[PublicKey],
            receiving_pk: Optional[PublicKey],
            ) -> bool:
        ...


def generate_kfrags(
        delegating_sk: SecretKey,
        receiving_pk: PublicKey,
        signing_sk: SecretKey,
        threshold: int,
        num_kfrags: int,
        sign_delegating_key: bool,
        sign_receiving_key: bool,
        ) -> List[KeyFrag]:
    ...


class CapsuleFrag:
    def verify(
            self,
            capsule: Capsule,
            delegating_pk: PublicKey,
            receiving_pk: PublicKey,
            signing_pk: PublicKey,
            metadata: Optional[bytes],
            ) -> bool:
        ...


def reencrypt(capsule: Capsule, kfrag: KeyFrag, metadata: Optional[bytes]) -> CapsuleFrag:
    ...


def decrypt_reencrypted(
        decrypting_sk: SecretKey,
        delegating_pk: PublicKey,
        capsule: Capsule,
        cfrags: Sequence[CapsuleFrag],
        ciphertext: bytes,
        ) -> Optional[bytes]:
    ...
