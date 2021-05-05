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

.. py:class:: PublicKey

    An ``umbral-pre`` public key object.

    .. py:staticmethod:: from_secret_key(sk: SecretKey) -> PublicKey

        Creates a public key corresponding to the given secret key.

.. py:class:: Capsule

    An encapsulated symmetric key.

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

    .. py:method:: verify(signing_pk: PublicKey, delegating_pk: Optional[PublicKey], receiving_pk: Optional[PublicKey]) -> bool:

        Verifies the integrity of the fragment using the signing key and, optionally, the delegating and the receiving keys (if they were included in the signature in :py:func:`generate_kfrags`).

.. py:class:: CapsuleFrag

    A reencrypted fragment of an encapsulated symmetric key.

    .. py:method:: verify(capsule: Capsule, delegating_pk: PublicKey, receiving_pk: PublicKey, signing_pk: PublicKey, metadata: Optional[bytes]) -> bool

        Verifies the integrity of the fragment.


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
