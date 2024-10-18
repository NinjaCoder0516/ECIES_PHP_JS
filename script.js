// Utils helper class
class Utils {
  static hex2bin(str) {
    if (str.length % 2 === 1) str = "0" + str;
    let bytes = new Uint8Array(str.length / 2);
    for (let i = 0; i < str.length; i += 2) {
      bytes[i / 2] = parseInt(str.substring(i, i + 2), 16);
    }
    return bytes;
  }

  static bin2hex(uint8Array) {
    return Array.from(uint8Array)
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  }

  static substring(str, start, end) {
    return str.substring(start, end);
  }

  static arrayValue(array, key, defaultValue = false) {
    return key in array ? array[key] : defaultValue;
  }
}

// Crypto helper class
class Crypto {
  static async hmacSha256(key, data) {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      key,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", cryptoKey, data);
    return new Uint8Array(signature);
  }

  static async aes256GcmEncrypt(data, key, iv) {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      cryptoKey,
      data
    );
    return new Uint8Array(encrypted);
  }

  static async aes256GcmDecrypt(data, key, iv) {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      cryptoKey,
      data
    );
    return new TextDecoder().decode(decrypted);
  }
}

// ECIES helper class
class ECIES {
  constructor(privateKey, publicKey, opts = { noKey: true, shortTag: true }) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.opts = opts;
    this.rBuf = null;
    this.kEkM = null;
    this.kE = null;
    this.kM = null;
  }

  getRbuf() {
    if (!this.rBuf) {
      this.rBuf = Utils.hex2bin(this.privateKey.getPublic(true, "hex"));
    }
    return this.rBuf;
  }

  async getSharedKey() {
    const shared = this.privateKey.derive(this.publicKey.getPublic());
    const bin = Utils.hex2bin(shared.toString("hex"));
    const hash = await crypto.subtle.digest("SHA-512", bin);
    return new Uint8Array(hash);
  }

  async getkEkM() {
    if (!this.kEkM) {
      this.kEkM = await this.getSharedKey();
    }
    return this.kEkM;
  }

  async getkE() {
    if (!this.kE) {
      const kEkM = await this.getkEkM();
      this.kE = kEkM.slice(0, 32);
    }
    return this.kE;
  }

  async getkM() {
    if (!this.kM) {
      const kEkM = await this.getkEkM();
      this.kM = kEkM.slice(32, 64);
    }
    return this.kM;
  }

  getPrivateEncKey() {
    const hex = this.privateKey.getPrivate("hex");
    return Utils.hex2bin(hex);
  }

  async encrypt(message, ivbuf = null) {
    const encoder = new TextEncoder();
    const messageBytes = encoder.encode(message);

    if (!ivbuf) {
      const hmac = await Crypto.hmacSha256(
        this.getPrivateEncKey(),
        messageBytes
      );
      ivbuf = hmac.slice(0, 16);
    }

    const kE = await this.getkE();
    const cipherText = await Crypto.aes256GcmEncrypt(messageBytes, kE, ivbuf);

    const c = new Uint8Array([...ivbuf, ...cipherText]);
    const kM = await this.getkM();
    let d = await Crypto.hmacSha256(kM, c);

    if (Utils.arrayValue(this.opts, "shortTag")) {
      d = d.slice(0, 4);
    }

    let encbuf;
    if (Utils.arrayValue(this.opts, "noKey")) {
      encbuf = new Uint8Array([...c, ...d]);
    } else {
      const rBuf = this.getRbuf();
      encbuf = new Uint8Array([...rBuf, ...c, ...d]);
    }

    return encbuf;
  }

  async decrypt(encbuf) {
    let offset = 0;
    let tagLength = 32;

    if (Utils.arrayValue(this.opts, "shortTag")) {
      tagLength = 4;
    }

    if (!Utils.arrayValue(this.opts, "noKey")) {
      offset = 33;
      this.publicKey = Utils.substring(encbuf, 0, 33);
    }

    const c = encbuf.slice(offset, encbuf.length - tagLength);
    const d = encbuf.slice(encbuf.length - tagLength);

    const kM = await this.getkM();
    let d2 = await Crypto.hmacSha256(kM, c);

    if (Utils.arrayValue(this.opts, "shortTag")) {
      d2 = d2.slice(0, 4);
    }

    const equal = d.every((byte, i) => byte === d2[i]);
    if (!equal) throw new Error("Invalid checksum");

    const iv = c.slice(0, 16);
    const cipherText = c.slice(16);

    const kE = await this.getkE();
    const decrypted = await Crypto.aes256GcmDecrypt(cipherText, kE, iv);

    return decrypted;
  }
}

$(document).ready(function () {
  const apiUrl = "api.php";

  // Generate JS keys
  $("#generateKeysJS").click(() => {
    const ec = new elliptic.ec("secp256k1");
    const key = ec.genKeyPair();
    $("#jsPrivateKey").val(key.getPrivate("hex"));
    $("#jsPublicKey").val(key.getPublic("hex"));
  });

  // Fetch PHP public key
  $("#generateKeysPHP").click(async () => {
    const response = await $.get(apiUrl, { action: "generateKeysPHP" });
    const json_data = JSON.parse(response);
    $("#phpPublicKey").val(json_data.publicKey);
    $("#phpPrivateKey").val(json_data.privateKey);
  });

  // Encrypt using JS
  $("#encryptJS").click(async () => {
    const ec = new elliptic.ec("secp256k1");
    const message = $("#message").val();
    const privateKey = await ec.keyFromPrivate($("#jsPrivateKey").val(), "hex");
    const publicKey = await ec.keyFromPublic($("#jsPublicKey").val(), "hex");

    const ecies = new ECIES(privateKey, publicKey);
    const cipher = await ecies.encrypt(message);
    const encrypted = Utils.bin2hex(cipher);

    $("#encrypted").val(encrypted);
  });

  // Decrypt using JS
  $("#decryptJS").click(async () => {
    const ec = new elliptic.ec("secp256k1");
    const encrypted = $("#encrypted").val();
    const privateKey = await ec.keyFromPrivate($("#jsPrivateKey").val(), "hex");
    const publicKey = await ec.keyFromPublic($("#jsPublicKey").val(), "hex");

    const ecies = new ECIES(privateKey, publicKey);
    const decrypted = await ecies.decrypt(Utils.hex2bin(encrypted));
    $("#decrypted").val(decrypted);
  });

  // Encrypt using PHP (via AJAX)
  $("#encryptPHP").click(async () => {
    const message = $("#message").val();

    const response = await $.post(apiUrl, {
      action: "encrypt",
      privateKey: $("#phpPrivateKey").val(),
      publicKey: $("#phpPublicKey").val(),
      message,
    });

    const json_data = JSON.parse(response);
    $("#encrypted").val(json_data.encrypted);
  });

  // Decrypt using PHP (via AJAX)
  $("#decryptPHP").click(async () => {
    const encryptedMessage = $("#encrypted").val();
    const response = await $.post(apiUrl, {
      action: "decrypt",
      privateKey: $("#phpPrivateKey").val(),
      publicKey: $("#phpPublicKey").val(),
      encrypted: encryptedMessage,
    });

    const json_data = JSON.parse(response);
    $("#decrypted").val(json_data.decrypted);
  });
});
