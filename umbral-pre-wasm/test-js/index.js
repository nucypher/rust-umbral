import * as wasm from "wasm-umbral";

let delegating_sk = wasm.UmbralSecretKey.random();
let delegating_pk = wasm.UmbralPublicKey.from_secret_key(delegating_sk);
let params = new wasm.UmbralParameters();

let enc = new TextEncoder();
let dec = new TextDecoder("utf-8");
let msg = "Plaintext message";
let msg_bytes = enc.encode(msg);

let result = wasm.encrypt(params, delegating_pk, msg_bytes);
let ciphertext = result.ciphertext;
let capsule = result.capsule;

let plaintext = wasm.decrypt_original(ciphertext, capsule, delegating_sk);
if (dec.decode(plaintext) == msg) {
    console.log("decrypt_original() passed.")
}

let receiving_sk = wasm.UmbralSecretKey.random();
let receiving_pk = wasm.UmbralPublicKey.from_secret_key(receiving_sk);

let signing_sk = wasm.UmbralSecretKey.random();
let signing_pk = wasm.UmbralPublicKey.from_secret_key(signing_sk);

let threshold = 2;
let num_frags = 3;
let kfrags = wasm.generate_kfrags(
    params,
    delegating_sk,
    receiving_pk,
    signing_sk,
    threshold,
    num_frags,
    true,
    true);

let prepared_capsule = capsule.with_correctness_keys(
    delegating_pk, receiving_pk, signing_pk);

kfrags.forEach(function (kfrag) {
    if (kfrag.verify(signing_pk, delegating_pk, receiving_pk)) {
        console.log("kfrag verified");
    }
});

let metadata = "asbdasdasd";
let cfrags = kfrags.map(kfrag => prepared_capsule.reencrypt(kfrag, enc.encode(metadata), true));


let reenc_plaintext = prepared_capsule
    .with_cfrag(cfrags[0])
    .with_cfrag(cfrags[1])
    .decrypt_reencrypted(ciphertext, receiving_sk, true);

if (dec.decode(reenc_plaintext) == msg) {
    console.log("decrypt_reencrypted() passed.")
}
