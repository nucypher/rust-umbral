import * as wasm from "wasm-umbral";

const sk = wasm.UmbralSecretKey.random();
const pk = wasm.UmbralPublicKey.from_secret_key(sk);
const params = new wasm.UmbralParameters();

const msg = "Plaintext message"

const result = wasm.encrypt(params, pk, msg);
console.log(result);
console.log(result.ciphertext);
console.log(result.capsule);
