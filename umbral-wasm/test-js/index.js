import * as wasm from "wasm-umbral";

const delegating_sk = wasm.UmbralSecretKey.random();
const delegating_pk = wasm.UmbralPublicKey.from_secret_key(delegating_sk);
const params = new wasm.UmbralParameters();

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8");
const msg = "Plaintext message";
const msg_bytes = enc.encode(msg);

const result = wasm.encrypt(params, delegating_pk, msg_bytes);
const ciphertext = result.ciphertext;
const capsule = result.capsule;

const plaintext = wasm.decrypt_original(ciphertext, capsule, delegating_sk);
if (dec.decode(plaintext) == msg) {
    console.log("decrypt_original() passed.")
}

const receiving_sk = wasm.UmbralSecretKey.random();
const receiving_pk = wasm.UmbralPublicKey.from_secret_key(receiving_sk);

const signing_sk = wasm.UmbralSecretKey.random();
const signing_pk = wasm.UmbralPublicKey.from_secret_key(signing_sk);

const threshold = 2;
const num_frags = 3;
const kfrags = wasm.generate_kfrags(
    params,
    delegating_sk,
    receiving_pk,
    signing_sk,
    threshold,
    num_frags,
    true,
    true);

const prepared_capsule = capsule.with_correctness_keys(
    delegating_pk, receiving_pk, signing_pk);

/*
for kfrag in kfrags {
    if kfrag.verify(signing_pk, delegating_pk, receiving_pk) {
        console.log("kfrag verified")
    }
}

const cfrags = kfrags.map(kfrag => prepared_capsule.reencrypt(kfrag, null, true));

const reenc_plaintext = wasm.decrypt_reencrypted(
    ciphertext,
    prepared_capsule,
    cfrags.slice(0, 2),
    receiving_privkey,
    true);

if reenc_plaintext == msg {
    console.log("decrypt_reencrypted() passed.")
}
*/
