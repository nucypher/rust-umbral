import umbral

# Generation of global parameters
params = umbral.Parameters()

# Key Generation (Alice)
delegating_sk = umbral.SecretKey.random()
delegating_pk = umbral.PublicKey.from_secret_key(delegating_sk)

signing_sk = umbral.SecretKey.random()
signing_pk = umbral.PublicKey.from_secret_key(signing_sk)

# Key Generation (Bob)
receiving_sk = umbral.SecretKey.random()
receiving_pk = umbral.PublicKey.from_secret_key(receiving_sk)

# Encryption by an unnamed data source
plaintext = b"peace at dawn"
capsule, ciphertext = umbral.encrypt(params, delegating_pk, plaintext)

# Decryption by Alice
plaintext_alice = umbral.decrypt_original(delegating_sk, capsule, ciphertext);
assert plaintext_alice == plaintext

threshold = 2
num_frags = threshold + 1

# Split Re-Encryption Key Generation (aka Delegation)
kfrags = umbral.generate_kfrags(
    params,
    delegating_sk,
    receiving_pk,
    signing_sk,
    threshold,
    num_frags,
    True,
    True,
)

# Ursulas check that the received kfrags are valid
assert all(kfrag.verify(signing_pk, delegating_pk, receiving_pk) for kfrag in kfrags)

# Bob requests re-encryption to some set of `threshold` ursulas
cfrags = [umbral.reencrypt(capsule, kfrag, b"metadata") for kfrag in kfrags]

# Bob checks that the received cfrags are valid
assert all(cfrag.verify(capsule, delegating_pk, receiving_pk, signing_pk) for cfrag in cfrags)

# Decryption by Bob
plaintext_bob = umbral.decrypt_reencrypted(receiving_sk, delegating_pk, capsule, cfrags, ciphertext)
assert plaintext_bob == plaintext
