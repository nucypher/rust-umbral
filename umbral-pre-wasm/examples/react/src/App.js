import "./App.css";

import { useEffect, useState } from "react";

function App() {
  const [umbral, setUmbral] = useState();
  const [alice_sk, setAliceKey] = useState();
  const [bob_sk, setBobKey] = useState();

  const [plaintext, setPlaintext] = useState();
  const [result, setResult] = useState();

  const [cfrags, setCfrags] = useState([]);

  const loadUmbral = async () => {
    const wumbral = await import("umbral-pre");
    setUmbral(wumbral);
  };

  const reset = () => {
    setPlaintext(null);
    setResult(null);
    setAliceKey(umbral.SecretKey.random());
    setBobKey(umbral.SecretKey.random());
    setCfrags([]);
  };

  const testUmbral = () => {
    let enc = new TextEncoder();
    let dec = new TextDecoder("utf-8");

    // As in any public-key cryptosystem, users need a pair of public and private keys.
    // Additionally, users that delegate access to their data (like Alice, in this example)
    // need a signing keypair.

    // Key Generation (on Alice's side)
    let alice_sk = umbral.SecretKey.random();
    let alice_pk = alice_sk.publicKey();
    let signing_sk = umbral.SecretKey.random();
    let signer = new umbral.Signer(signing_sk);

    // Key Generation (on Bob's side)
    let bob_sk = umbral.SecretKey.random();
    let bob_pk = bob_sk.publicKey();

    // Now let's encrypt data with Alice's public key.
    // Invocation of `encrypt()` returns both the ciphertext and a capsule.
    // Note that anyone with Alice's public key can perform this operation.

    let plaintext_bytes = enc.encode(plaintext);

    // The API here slightly differs from that in Rust.
    // Since wasm-pack does not support returning tuples, we return an object containing
    // the ciphertext and the capsule.
    let result = umbral.encrypt(alice_pk, plaintext_bytes);
    let ciphertext = result.ciphertext;
    let capsule = result.capsule;

    // Since data was encrypted with Alice's public key, Alice can open the capsule
    // and decrypt the ciphertext with her private key.

    let plaintext_alice = umbral.decryptOriginal(alice_sk, capsule, ciphertext);
    console.assert(
      dec.decode(plaintext_alice) === plaintext,
      "decryptOriginal() failed"
    );

    // When Alice wants to grant Bob access to open her encrypted messages,
    // she creates re-encryption key fragments, or "kfrags", which are then
    // sent to `n` proxies or Ursulas.

    let n = 3; // how many fragments to create
    let m = 2; // how many should be enough to decrypt
    let kfrags = umbral.generateKFrags(
      alice_sk,
      bob_pk,
      signer,
      m,
      n,
      true, // add the delegating key (alice_pk) to the signature
      true // add the receiving key (bob_pk) to the signature
    );

    // Bob asks several Ursulas to re-encrypt the capsule so he can open it.
    // Each Ursula performs re-encryption on the capsule using the kfrag provided by Alice,
    // obtaining this way a "capsule fragment", or cfrag.

    // Bob collects the resulting cfrags from several Ursulas.
    // Bob must gather at least `m` cfrags in order to open the capsule.

    // Ursulas can optionally check that the received kfrags are valid
    // and perform the reencryption

    // Ursula 0
    let cfrag0 = umbral.reencrypt(capsule, kfrags[0]);

    // Ursula 1
    let cfrag1 = umbral.reencrypt(capsule, kfrags[1]);

    // ...
    setCfrags([cfrag0, cfrag1]);

    // Finally, Bob opens the capsule by using at least `m` cfrags,
    // and then decrypts the re-encrypted ciphertext.

    // Another deviation from the Rust API.
    // wasm-pack does not support taking arrays as arguments,
    // so we build a capsule+cfrags object before decryption.
    let plaintext_bob = capsule
      .withCFrag(cfrag0)
      .withCFrag(cfrag1)
      .decryptReencrypted(bob_sk, alice_pk, ciphertext);

    console.assert(
      dec.decode(plaintext_bob) === plaintext,
      "decryptReencrypted() failed"
    );

    console.log("Success!");

    setResult(dec.decode(plaintext_bob));
  };

  useEffect(() => {
    loadUmbral();
  }, []);

  return (
    <div className="App">
      <header className="App-header">
        {umbral ? (
          <div className="stack left">
            <div>
              <div>Create Alice and Bob</div>
              <button onClick={(e) => reset()}>Go</button>
              <div>{alice_sk && alice_sk.toString()}</div>
              <div>
                {alice_sk && (
                  <span>Alice: {alice_sk.publicKey().toString()}</span>
                )}
              </div>
              <div>
                {bob_sk && <span>Bob: {bob_sk.publicKey().toString()}</span>}
              </div>
            </div>

            {alice_sk && (
              <div>
                plaintext:{" "}
                <input
                  type="text"
                  onChange={(e) => setPlaintext(e.target.value)}
                />
                <button onClick={(e) => testUmbral()}>Go</button>
              </div>
            )}
            {result && (
              <div>
                cfrags:{" "}
                {cfrags.map((cf) => {
                  return (
                    <div key={cf.toString()}>
                      <small>{cf.toString()}</small>
                    </div>
                  );
                })}
              </div>
            )}
            {result && <div>result: {result}</div>}
          </div>
        ) : (
          <span>loading umbral</span>
        )}
      </header>
    </div>
  );
}

export default App;
