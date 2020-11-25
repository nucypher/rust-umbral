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

kfrags.forEach(function (kfrag) {
    if (kfrag.verify(signing_pk, delegating_pk, receiving_pk)) {
        console.log("kfrag verified");
    }
});

let metadata = "asbdasdasd";
const cfrags = kfrags.map(kfrag => prepared_capsule.reencrypt(kfrag, enc.encode(metadata), true));


const reenc_plaintext = prepared_capsule
    .with_cfrag(cfrags[0])
    .with_cfrag(cfrags[1])
    .decrypt_reencrypted(ciphertext, receiving_sk, true);

if (dec.decode(reenc_plaintext) == msg) {
    console.log("decrypt_reencrypted() passed.")
}
