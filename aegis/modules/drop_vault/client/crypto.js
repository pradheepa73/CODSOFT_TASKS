async function genAesKey() {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
  );
}

async function encryptFile(file, aesKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = await file.arrayBuffer();
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, pt);
  return { iv, ct };
}

async function importServerPub(b64) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey("raw", raw, { name: "X25519" }, false, []);
}

async function exportRaw(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

async function uploadFile(file, serverPubB64, user) {
  const aes = await genAesKey();
  const { iv, ct } = await encryptFile(file, aes);

  const eph = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const clientPub = await exportRaw(eph.publicKey);

  const serverPub = await importServerPub(serverPubB64);
  const bits = await crypto.subtle.deriveBits(
    { name: "X25519", public: serverPub }, eph.privateKey, 256
  );
  const wrapKey = await crypto.subtle.importKey(
    "raw", bits, { name: "AES-GCM" }, false, ["encrypt"]
  );
  const rawAes = await crypto.subtle.exportKey("raw", aes);
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: wrapIv }, wrapKey, rawAes
  );

  const fd = new FormData();
  fd.append("user", user);
  fd.append("filename", file.name);
  fd.append("client_pubkey", clientPub);
  fd.append("wrapped_key", btoa(String.fromCharCode(...new Uint8Array(wrapped))));
  fd.append("nonce", btoa(String.fromCharCode(...wrapIv)));
  fd.append("blob", new Blob([ct]));

  const r = await fetch("/vault/upload", { method: "POST", body: fd });
  return r.json();
}

window.DropVault = { uploadFile };