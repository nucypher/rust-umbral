import * as umbral from "umbral-pre";

let enc = new TextEncoder();
let dec = new TextDecoder("utf-8");

// As in any public-key cryptosystem, users need a pair of public and private keys.
// Additionally, users that delegate access to their data (like Alice, in this example)
// need a signing keypair.

// Key Generation (on Alice's side)
let alice_sk = umbral.SecretKey.random();
let alice_pk = umbral.PublicKey.from_secret_key(alice_sk);
let signing_sk = umbral.SecretKey.random();
let signing_pk = umbral.PublicKey.from_secret_key(signing_sk);

// Key Generation (on Bob's side)
let bob_sk = umbral.SecretKey.random();
let bob_pk = umbral.PublicKey.from_secret_key(bob_sk);

// Now let's encrypt data with Alice's public key.
// Invocation of `encrypt()` returns both the ciphertext and a capsule.
// Note that anyone with Alice's public key can perform this operation.

let params = new umbral.Parameters();
let plaintext = "Plaintext message";
let plaintext_bytes = enc.encode(plaintext);

// The API here slightly differs from that in Rust.
// Since wasm-pack does not support returning tuples, we return an object containing
// the ciphertext and the capsule.
let result = umbral.encrypt(params, alice_pk, plaintext_bytes);
let ciphertext = result.ciphertext;
let capsule = result.capsule;

// Since data was encrypted with Alice's public key, Alice can open the capsule
// and decrypt the ciphertext with her private key.

let plaintext_alice = umbral.decrypt_original(alice_sk, capsule, ciphertext);
console.assert(dec.decode(plaintext_alice) == plaintext, "decrypt_original() failed");

// When Alice wants to grant Bob access to open her encrypted messages,
// she creates re-encryption key fragments, or "kfrags", which are then
// sent to `n` proxies or Ursulas.

let n = 3; // how many fragments to create
let m = 2; // how many should be enough to decrypt
let kfrags = umbral.generate_kfrags(
    params, alice_sk, bob_pk, signing_sk, m, n,
    true, // add the delegating key (alice_pk) to the signature
    true, // add the receiving key (bob_pk) to the signature
    );

// Bob asks several Ursulas to re-encrypt the capsule so he can open it.
// Each Ursula performs re-encryption on the capsule using the kfrag provided by Alice,
// obtaining this way a "capsule fragment", or cfrag.

// Bob collects the resulting cfrags from several Ursulas.
// Bob must gather at least `m` cfrags in order to open the capsule.

// Ursulas can optionally check that the received kfrags are valid
// and perform the reencryption

let metadata = "asbdasdasd";

// Ursula 0
console.assert(
    kfrags[0].verify_with_delegating_and_receiving_keys(signing_pk, alice_pk, bob_pk),
    "kfrag0 is invalid");
let cfrag0 = umbral.reencrypt(capsule, kfrags[0], enc.encode(metadata));

// Ursula 1
console.assert(
    kfrags[1].verify_with_delegating_and_receiving_keys(signing_pk, alice_pk, bob_pk),
    "kfrag1 is invalid");
let cfrag1 = umbral.reencrypt(capsule, kfrags[1], enc.encode(metadata));

// ...

// Finally, Bob opens the capsule by using at least `m` cfrags,
// and then decrypts the re-encrypted ciphertext.

// Bob can optionally check that cfrags are valid
console.assert(cfrag0.verify(capsule, alice_pk, bob_pk, signing_pk), "cfrag0 is invalid");
console.assert(cfrag1.verify(capsule, alice_pk, bob_pk, signing_pk), "cfrag1 is invalid");

// Another deviation from the Rust API.
// wasm-pack does not support taking arrays as arguments,
// so we build a capsule+cfrags object before decryption.
let plaintext_bob = capsule
    .with_cfrag(cfrag0)
    .with_cfrag(cfrag1)
    .decrypt_reencrypted(bob_sk, alice_pk, ciphertext);

console.assert(dec.decode(plaintext_bob) == plaintext, "decrypt_reencrypted() failed");
