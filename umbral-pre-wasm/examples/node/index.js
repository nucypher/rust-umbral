import * as umbral from "umbral-pre";

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8");

const sk_bytes = Buffer.from(
  "0c6f4dc1935a45db426058988717ccf3137948754ab973a6e477ce076056e4cd",
  "hex"
);
const sk = umbral.SecretKey.fromBytes(sk_bytes);
const signer = new umbral.Signer(sk);

const message = "message";
const signature = signer.sign(message).toBytes();

console.log({ message: enc.encode(message) });
console.log({ signature });
