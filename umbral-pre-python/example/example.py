import umbral_pre

# As in any public-key cryptosystem, users need a pair
# of public and private keys.
# Additionally, users that delegate access to their data
# (like Alice, in this example) need a signing keypair.

# Key Generation (on Alice's side)
alice_sk = umbral_pre.SecretKey.random()
alice_pk = umbral_pre.PublicKey.from_secret_key(alice_sk)
signing_sk = umbral_pre.SecretKey.random()
signer = umbral_pre.Signer(signing_sk)
verifying_pk = umbral_pre.PublicKey.from_secret_key(signing_sk)

# Key Generation (on Bob's side)
bob_sk = umbral_pre.SecretKey.random()
bob_pk = umbral_pre.PublicKey.from_secret_key(bob_sk)

# Now let's encrypt data with Alice's public key.
# Invocation of `encrypt()` returns both the ciphertext
# and the encapsulated symmetric key use to encrypt it.
# Note that anyone with Alice's public key
# can perform this operation.

plaintext = b"peace at dawn"
capsule, ciphertext = umbral_pre.encrypt(alice_pk, plaintext)

# Since data was encrypted with Alice's public key,
# Alice can open the capsule and decrypt the ciphertext
# with her private key.

plaintext_alice = umbral_pre.decrypt_original(
    alice_sk, capsule, ciphertext);
assert plaintext_alice == plaintext

# When Alice wants to grant Bob access to open her encrypted
# messages, she creates re-encryption key fragments,
# or "kfrags", which are then sent to `n` proxies or Ursulas.

n = 3 # how many fragments to create
m = 2 # how many should be enough to decrypt

# Split Re-Encryption Key Generation (aka Delegation)
verified_kfrags = umbral_pre.generate_kfrags(
    alice_sk, bob_pk, signer, m, n,
    True, # add the delegating key (alice_pk) to the signature
    True, # add the receiving key (bob_pk) to the signature
)

# Bob asks several Ursulas to re-encrypt the capsule
# so he can open it.
# Each Ursula performs re-encryption on the capsule
# using the kfrag provided by Alice, thus obtaining
# a "capsule fragment", or cfrag.

# Bob collects the resulting cfrags from several Ursulas.
# Bob must gather at least `m` cfrags
# in order to open the capsule.

# Simulate network transfer
kfrag0 = KeyFrag.from_bytes(bytes(verified_kfrags[0]))
kfrag1 = KeyFrag.from_bytes(bytes(verified_kfrags[1]))

# Ursulas must check that the received kfrags
# are valid and perform the reencryption.

# Ursula 0
metadata0 = b"metadata0"
verified_kfrag0 = kfrag0.verify(verifying_pk, alice_pk, bob_pk)
verified_cfrag0 = umbral_pre.reencrypt(capsule, kfrags[0], metadata0)

# Ursula 1
metadata1 = b"metadata1"
verified_kfrag1 = kfrag1.verify(verifying_pk, alice_pk, bob_pk)
verified_cfrag1 = umbral_pre.reencrypt(capsule, kfrags[1], metadata1)

# ...

# Simulate network transfer
cfrag0 = CapsuleFrag.from_bytes(bytes(verified_cfrag0))
cfrag1 = CapsuleFrag.from_bytes(bytes(verified_cfrag1))

# Finally, Bob opens the capsule by using at least `m` cfrags,
# and then decrypts the re-encrypted ciphertext.

# Bob must check that cfrags are valid
verified_cfrag0 = cfrag0.verify(capsule, verifying_pk, alice_pk, bob_pk, metadata0)
verified_cfrag1 = cfrag1.verify(capsule, verifying_pk, alice_pk, bob_pk, metadata1)

# Decryption by Bob
plaintext_bob = umbral_pre.decrypt_reencrypted(
    bob_sk, alice_pk, capsule, [verified_cfrag0, verified_cfrag1], ciphertext)
assert plaintext_bob == plaintext
