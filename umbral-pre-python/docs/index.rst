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

.. py:class:: SecretKeyFactory

    A deterministic generator of :py:class:`SecretKey` objects.

    .. py:staticmethod:: random() -> SecretKeyFactory

        Generates a new random factory.

    .. py:method:: secret_key_by_label(label: bytes) -> SecretKey

        Generates a new :py:class:`SecretKey` using ``label`` as a seed.

    .. py:method:: __bytes__() -> bytes

        Serializes the object into a bytestring.

    .. py:staticmethod:: from_bytes(data: bytes) -> SecretKey

        Restores the object from a bytestring.

.. py:class:: PublicKey

    An ``umbral-pre`` public key object.

    .. py:staticmethod:: from_secret_key(sk: SecretKey) -> PublicKey

        Creates a public key corresponding to the given secret key.

    .. py:method:: __bytes__() -> bytes

        Serializes the object into a bytestring.

    .. py:staticmethod:: from_bytes(data: bytes) -> PublicKey

        Restores the object from a bytestring.

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

.. py:class:: Capsule

    An encapsulated symmetric key.

    .. py:method:: __bytes__() -> bytes

        Serializes the object into a bytestring.

    .. py:staticmethod:: from_bytes(data: bytes) -> Capsule

        Restores the object from a bytestring.

    .. py:method:: __hash__() -> int

        Returns a hash of self.

.. py:function:: encrypt(pk: PublicKey, plaintext: bytes) -> Tuple[Capsule, bytes]

    Creates a symmetric key, encrypts ``plaintext`` with it, and returns the encapsulated symmetric key along with the ciphertext. ``pk`` is the public key of the recipient.

.. py:function:: decrypt_original(sk: SecretKey, capsule: Capsule, ciphertext: bytes) -> bytes

    Decrypts ``ciphertext`` with the key used to encrypt it.

.. py:function:: generate_kfrags(delegating_sk: SecretKey, receiving_pk: PublicKey, signing_sk: SecretKey, threshold: int, num_kfrags: int, sign_delegating_key: bool, sign_receiving_key: bool) -> List[KeyFrag]

    Generates ``num_kfrags`` key fragments that can be used to reencrypt the capsule for the holder of the secret key corresponding to ``receiving_pk``. ``threshold`` fragments will be enough for decryption.

    If ``sign_delegating_key`` or ``sign_receiving_key`` are ``True``, include these keys in the signature allowing proxies to verify the fragments were created with a given key or for a given key, respectively.

.. py:function:: reencrypt(capsule: Capsule, kfrag: KeyFrag, metadata: Optional[bytes]) -> CapsuleFrag

    Reencrypts a capsule using a key fragment.
    May include optional ``metadata`` to sign.

.. py:function:: decrypt_reencrypted(decrypting_sk: SecretKey, delegating_pk: PublicKey, capsule: Capsule, cfrags: Sequence[CapsuleFrag], ciphertext: bytes) -> Optional[bytes]

    Attempts to decrypt the plaintext using the original capsule and reencrypted capsule fragments (at least ``threshold`` of them, see :py:func:`generate_kfrags`).

.. py:class:: KeyFrag

    A fragment of a public key used by proxies during reencryption.

    .. py:method:: verify(verifying_pk: PublicKey, delegating_pk: Optional[PublicKey], receiving_pk: Optional[PublicKey]) -> bool:

        Verifies the integrity of the fragment using the signing key and, optionally, the delegating and the receiving keys (if they were included in the signature in :py:func:`generate_kfrags`).

    .. py:method:: __bytes__() -> bytes

        Serializes the object into a bytestring.

    .. py:staticmethod:: from_bytes(data: bytes) -> KeyFrag

        Restores the object from a bytestring.

    .. py:method:: __hash__() -> int

        Returns a hash of self.

.. py:class:: CapsuleFrag

    A reencrypted fragment of an encapsulated symmetric key.

    .. py:method:: verify(capsule: Capsule, delegating_pk: PublicKey, receiving_pk: PublicKey, verifying_pk: PublicKey, metadata: Optional[bytes]) -> bool

        Verifies the integrity of the fragment.

    .. py:method:: __bytes__() -> bytes

        Serializes the object into a bytestring.

    .. py:staticmethod:: from_bytes(data: bytes) -> CapsuleFrag

        Restores the object from a bytestring.

    .. py:method:: __hash__() -> int

        Returns a hash of self.


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
