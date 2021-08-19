Welcome to umbral-pre's documentation!
======================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

This package contains the Python bindings for `the main library <https://github.com/nucypher/rust-umbral/tree/master/umbral-pre>`_ written in Rust. It implements the `Umbral <https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf>`_ proxy reencryption scheme.

Usage example
-------------

.. literalinclude:: ../example/example.py


API reference
-------------

.. py:module:: umbral_pre

.. py:class:: SecretKey

    An ``umbral-pre`` secret key object.

    .. py:staticmethod:: random() -> SecretKey

        Generates a new secret key.

    .. py:method:: public_key() -> PublicKey

        Returns a public key corresponding to this secret key.

    .. py:method:: to_secret_bytes() -> bytes

        Serializes the object into a bytestring.

        Made into an explicit method instead of `__bytes__` to avoid unintentional exposure of the secret data.

    .. py:staticmethod:: from_bytes(data: bytes) -> SecretKey

        Restores the object from a bytestring.

    .. py:staticmethod:: serialized_size() -> int

        Returns the size in bytes of the serialized representation of this object.

.. py:class:: SecretKeyFactory

    A deterministic generator of :py:class:`SecretKey` objects.

    .. py:staticmethod:: random() -> SecretKeyFactory

        Generates a new random factory.

    .. py:staticmethod:: seed_size() -> int

        Returns the seed size required by :py:meth:`~SecretKeyFactory.from_secure_randomness`.

    .. py:staticmethod:: from_secure_randomness(seed: bytes) -> SecretKeyFactory

        Creates a secret key factory using the given random bytes.
        The length of the bytestring must be the one returned by :py:meth:`~SecretKeyFactory.seed_size`.

        **Warning:** make sure the given seed has been obtained
        from a cryptographically secure source of randomness!

    .. py:method:: secret_key_by_label(label: bytes) -> SecretKey

        Generates a new :py:class:`SecretKey` using ``label`` as a seed.

    .. py:method:: secret_key_factory_by_label(label: bytes) -> SecretKeyFactory

        Generates a new :py:class:`SecretKeyFactory` using ``label`` as a seed.

    .. py:method:: to_secret_bytes() -> bytes

        Serializes the object into a bytestring.

        Made into an explicit method instead of `__bytes__` to avoid unintentional exposure of the secret data.

    .. py:staticmethod:: from_bytes(data: bytes) -> SecretKey

        Restores the object from a bytestring.

    .. py:staticmethod:: serialized_size() -> int

        Returns the size in bytes of the serialized representation of this object.

.. py:class:: PublicKey

    An ``umbral-pre`` public key object.

    .. py:method:: __bytes__() -> bytes

        Serializes the object into a bytestring.

    .. py:staticmethod:: from_bytes(data: bytes) -> PublicKey

        Restores the object from a bytestring.

    .. py:staticmethod:: serialized_size() -> int

        Returns the size in bytes of the serialized representation of this object.

    .. py:method:: __hash__() -> int

        Returns a hash of self.

.. py:class:: Signer(secret_key: SecretKey)

    An object possessing the capability to create signatures.
    For safety reasons serialization is prohibited.

    .. py:method:: sign(message: bytes) -> Signature

        Hashes and signs the message.

    .. py:method:: verifying_key() -> PublicKey

        Returns the public verification key corresponding to the secret key used for signing.

.. py:class:: Signature

    Wrapper for ECDSA signatures.

    .. py:method:: verify(verifying_key: PublicKey, message: bytes) -> bool

        Returns ``True`` if the ``message`` was signed by someone possessing the secret counterpart
        to ``verifying_key``.

    .. py:method:: __bytes__() -> bytes

        Serializes the object into a bytestring.

    .. py:staticmethod:: from_bytes(data: bytes) -> Signature

        Restores the object from a bytestring.

    .. py:staticmethod:: serialized_size() -> int

        Returns the size in bytes of the serialized representation of this object.

.. py:class:: Capsule

    An encapsulated symmetric key.

    .. py:method:: __bytes__() -> bytes

        Serializes the object into a bytestring.

    .. py:staticmethod:: from_bytes(data: bytes) -> Capsule

        Restores the object from a bytestring.

    .. py:staticmethod:: serialized_size() -> int

        Returns the size in bytes of the serialized representation of this object.

    .. py:method:: __hash__() -> int

        Returns a hash of self.

.. py:function:: encrypt(delegating_pk: PublicKey, plaintext: bytes) -> Tuple[Capsule, bytes]

    Creates a symmetric key, encrypts ``plaintext`` with it, and returns the encapsulated symmetric key along with the ciphertext. ``delegating_pk`` is the public key of the delegator.

.. py:function:: decrypt_original(delegating_sk: SecretKey, capsule: Capsule, ciphertext: bytes) -> bytes

    Decrypts ``ciphertext`` with the secret key of the delegator.

.. py:function:: generate_kfrags(delegating_sk: SecretKey, receiving_pk: PublicKey, signer: Signer, threshold: int, num_kfrags: int, sign_delegating_key: bool, sign_receiving_key: bool) -> List[VerifiedKeyFrag]

    Generates ``num_kfrags`` key fragments that can be used to reencrypt the capsule for the holder of the secret key corresponding to ``receiving_pk``. ``threshold`` fragments will be enough for decryption.

    If ``sign_delegating_key`` or ``sign_receiving_key`` are ``True``, include these keys in the signature allowing proxies to verify the fragments were created with a given key or for a given key, respectively.

.. py:function:: reencrypt(capsule: Capsule, kfrag: VerifiedKeyFrag) -> VerifiedCapsuleFrag

    Reencrypts a capsule using a key fragment.

.. py:function:: decrypt_reencrypted(receiving_sk: SecretKey, delegating_pk: PublicKey, capsule: Capsule, cfrags: Sequence[VerifiedCapsuleFrag], ciphertext: bytes) -> Optional[bytes]

    Attempts to decrypt the plaintext using the original capsule and reencrypted capsule fragments (at least ``threshold`` of them, see :py:func:`generate_kfrags`).

.. py:class:: KeyFrag

    A fragment of a public key used by proxies during reencryption.

    .. py:method:: verify(verifying_pk: PublicKey, delegating_pk: Optional[PublicKey], receiving_pk: Optional[PublicKey]) -> VerifiedKeyFrag:

        Verifies the integrity of the fragment using the signing key and, optionally, the delegating and the receiving keys (if they were included in the signature in :py:func:`generate_kfrags`).

    .. py:method:: __bytes__() -> bytes

        Serializes the object into a bytestring.

    .. py:staticmethod:: from_bytes(data: bytes) -> KeyFrag

        Restores the object from a bytestring.

    .. py:staticmethod:: serialized_size() -> int

        Returns the size in bytes of the serialized representation of this object.

    .. py:method:: __hash__() -> int

        Returns a hash of self.

.. py:class:: VerifiedKeyFrag

    A verified key fragment, good for reencryption.

    .. py:method:: from_verified_bytes(data: bytes) -> VerifiedKeyFrag

        Restores a verified keyfrag directly from serialized bytes,
        skipping :py:meth:`KeyFrag.verify` call.

        Intended for internal storage;
        make sure that the bytes come from a trusted source.

    .. py:method:: __bytes__() -> bytes

        Serializes the object into a bytestring.

    .. py:staticmethod:: serialized_size() -> int

        Returns the size in bytes of the serialized representation of this object.

.. py:class:: CapsuleFrag

    A reencrypted fragment of an encapsulated symmetric key.

    .. py:method:: verify(capsule: Capsule, verifying_pk: PublicKey, delegating_pk: PublicKey, receiving_pk: PublicKey) -> VerifiedCapsuleFrag

        Verifies the integrity of the fragment.

    .. py:method:: __bytes__() -> bytes

        Serializes the object into a bytestring.

    .. py:staticmethod:: from_bytes(data: bytes) -> CapsuleFrag

        Restores the object from a bytestring.

    .. py:staticmethod:: serialized_size() -> int

        Returns the size in bytes of the serialized representation of this object.

    .. py:method:: __hash__() -> int

        Returns a hash of self.

.. py:class:: VerifiedCapsuleFrag

    A verified capsule fragment, good for decryption.

    .. py:method:: from_verified_bytes(data: bytes) -> VerifiedCapsuleFrag

        Restores a verified capsule frag directly from serialized bytes,
        skipping :py:meth:`CapsuleFrag.verify` call.

        Intended for internal storage;
        make sure that the bytes come from a trusted source.

    .. py:method:: __bytes__() -> bytes

        Serializes the object into a bytestring.

    .. py:staticmethod:: serialized_size() -> int

        Returns the size in bytes of the serialized representation of this object.


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
