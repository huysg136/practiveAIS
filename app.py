from cipher.rsa.rsa_cipher import GenerateKeys, Encrypt, Decrypt
from cipher.rsa.rsa_cipher_demo import RSADemo
from cipher.des.des_cipher import DESDemo
from cipher.triple_des.triple_des_cipher import TripleDESDemo
from cipher.aes.aes_cipher import AESCipher
from flask import Flask, flash, redirect, render_template, request, send_file, session, jsonify
import os
import json
import hashlib
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
app.secret_key = "1343"

# Khởi tạo các cipher
aes_cipher = AESCipher("my_secret_key123")
descipherdemo = DESDemo()
tripledes_demo = TripleDESDemo()
rsacipherdemo = RSADemo

# Biến global lưu key
CURRENT_DES_KEY = None
DEFAULT_KEY = None

OUTPUT = "output"
os.makedirs(OUTPUT, exist_ok=True)

# ============================================
# BITCOIN INTEGRATION - Data Structures
# ============================================

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def hash160(b: bytes) -> bytes:
    """RIPEMD160(SHA256(x))"""
    h = sha256(b)
    r = hashlib.new("ripemd160")
    r.update(h)
    return r.digest()

def pubkey_bytes_uncompressed(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

def sign(priv: ec.EllipticCurvePrivateKey, msg: bytes) -> bytes:
    return priv.sign(msg, ec.ECDSA(hashes.SHA256()))

def verify(pub: ec.EllipticCurvePublicKey, sig: bytes, msg: bytes) -> bool:
    try:
        pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

@dataclass(frozen=True)
class Outpoint:
    txid: str
    vout: int

@dataclass
class TxIn:
    prevout: Outpoint
    pubkey_hex: str = ""
    sig_hex: str = ""
    sequence: int = 0xFFFFFFFF

@dataclass
class TxOut:
    value: int
    pubkey_hash_hex: str

@dataclass
class Transaction:
    version: int
    vin: List[TxIn]
    vout: List[TxOut]
    locktime: int = 0

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "vin": [
                {
                    "prevout": asdict(i.prevout),
                    "pubkey_hex": i.pubkey_hex,
                    "sig_hex": i.sig_hex,
                    "sequence": i.sequence,
                }
                for i in self.vin
            ],
            "vout": [asdict(o) for o in self.vout],
            "locktime": self.locktime,
        }

    def txid(self) -> str:
        raw = json.dumps(self.to_dict(), sort_keys=True).encode()
        return sha256(sha256(raw)).hex()

    def signing_digest(self) -> bytes:
        stripped = {
            "version": self.version,
            "vin": [{"prevout": asdict(i.prevout), "sequence": i.sequence} for i in self.vin],
            "vout": [asdict(o) for o in self.vout],
            "locktime": self.locktime,
        }
        raw = json.dumps(stripped, sort_keys=True).encode()
        return sha256(raw)

@dataclass
class UTXO:
    outpoint: Outpoint
    value: int
    pubkey_hash_hex: str

class MiniNode:
    def __init__(self):
        self.utxos: Dict[Tuple[str, int], UTXO] = {}
        self.mempool: Dict[str, Transaction] = {}
        self.chain: List[Dict] = []

    def add_utxo(self, utxo: UTXO):
        self.utxos[(utxo.outpoint.txid, utxo.outpoint.vout)] = utxo

    def get_utxo(self, outpoint: Outpoint) -> Optional[UTXO]:
        return self.utxos.get((outpoint.txid, outpoint.vout))

    def remove_utxo(self, outpoint: Outpoint):
        self.utxos.pop((outpoint.txid, outpoint.vout), None)

    def validate_tx(self, tx: Transaction) -> Tuple[bool, str, int]:
        if not tx.vin or not tx.vout:
            return False, "Tx must have at least 1 input and 1 output.", 0

        digest = tx.signing_digest()
        total_in = 0
        seen_inputs = set()

        for idx, txin in enumerate(tx.vin):
            key = (txin.prevout.txid, txin.prevout.vout)
            if key in seen_inputs:
                return False, f"Double-spend inside tx: duplicated input at vin[{idx}].", 0
            seen_inputs.add(key)

            utxo = self.get_utxo(txin.prevout)
            if utxo is None:
                return False, f"Referenced UTXO not found for vin[{idx}] outpoint={key}.", 0

            if not txin.pubkey_hex or not txin.sig_hex:
                return False, f"Missing unlocking data (pubkey/signature) in vin[{idx}].", 0

            pubkey_bytes = bytes.fromhex(txin.pubkey_hex)
            sig = bytes.fromhex(txin.sig_hex)

            try:
                pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pubkey_bytes)
            except ValueError:
                return False, f"Invalid pubkey encoding in vin[{idx}].", 0

            computed_h160 = hash160(pubkey_bytes).hex()
            if computed_h160 != utxo.pubkey_hash_hex:
                return False, f"Pubkey-hash mismatch in vin[{idx}].", 0

            if not verify(pub, sig, digest):
                return False, f"Invalid signature in vin[{idx}].", 0

            total_in += utxo.value

        total_out = sum(o.value for o in tx.vout)
        if total_out <= 0:
            return False, "Total output must be positive.", 0

        if total_in < total_out:
            return False, f"Insufficient inputs: total_in={total_in} < total_out={total_out}.", 0

        fee = total_in - total_out
        return True, "Transaction is valid.", fee

    def accept_to_mempool(self, tx: Transaction) -> Tuple[bool, str]:
        ok, msg, fee = self.validate_tx(tx)
        if not ok:
            return False, msg
        txid = tx.txid()
        self.mempool[txid] = tx
        return True, f"Accepted to mempool. txid={txid[:16]}.. fee={fee}"

    def mine_block(self) -> Tuple[bool, str]:
        if not self.mempool:
            return False, "Mempool is empty."

        txs = list(self.mempool.values())
        txids = [t.txid() for t in txs]

        for tx in txs:
            for txin in tx.vin:
                self.remove_utxo(txin.prevout)

            this_txid = tx.txid()
            for vout_index, o in enumerate(tx.vout):
                self.add_utxo(
                    UTXO(outpoint=Outpoint(this_txid, vout_index), value=o.value, pubkey_hash_hex=o.pubkey_hash_hex)
                )

        height = len(self.chain)
        self.chain.append({"height": height, "txids": txids, "timestamp": int(__import__('time').time())})

        self.mempool.clear()
        return True, f"Mined block #{height} with {len(txids)} tx(s)."

class Wallet:
    def __init__(self, name: str):
        self.name = name
        self.priv = ec.generate_private_key(ec.SECP256K1())
        self.pub = self.priv.public_key()

    def pubkey_bytes(self) -> bytes:
        return pubkey_bytes_uncompressed(self.pub)

    def pubkey_hex(self) -> str:
        return self.pubkey_bytes().hex()

    def pubkey_hash_hex(self) -> str:
        return hash160(self.pubkey_bytes()).hex()

# Global Bitcoin state
bitcoin_node = MiniNode()
bitcoin_wallets = {}

# ============================================
# ROUTES - MAIN
# ============================================

@app.route("/")
def home():
    return render_template("index.html", selected_algo=session.get("algorithm", "RSA"))

# ============================================
# BITCOIN ROUTES
# ============================================

@app.route("/bitcoin")
def bitcoin_home():
    return render_template("bitcoin.html")

@app.route("/bitcoin/generate_wallet", methods=["POST"])
def bitcoin_generate_wallet():
    data = request.get_json()
    name = data.get("name", "User")
    
    wallet = Wallet(name)
    bitcoin_wallets[name] = wallet
    
    return jsonify({
        "success": True,
        "name": name,
        "pubkey_hash": wallet.pubkey_hash_hex(),
        "pubkey": wallet.pubkey_hex()
    })

@app.route("/bitcoin/create_genesis", methods=["POST"])
def bitcoin_create_genesis():
    data = request.get_json()
    wallet_name = data.get("wallet_name")
    amount = data.get("amount", 100)
    
    if wallet_name not in bitcoin_wallets:
        return jsonify({"success": False, "error": "Wallet not found"})
    
    wallet = bitcoin_wallets[wallet_name]
    
    funding_tx = Transaction(
        version=1,
        vin=[TxIn(prevout=Outpoint("COINBASE", 0))],
        vout=[TxOut(value=amount, pubkey_hash_hex=wallet.pubkey_hash_hex())],
        locktime=0
    )
    
    txid = funding_tx.txid()
    for i, o in enumerate(funding_tx.vout):
        bitcoin_node.add_utxo(UTXO(Outpoint(txid, i), o.value, o.pubkey_hash_hex))
    
    return jsonify({
        "success": True,
        "txid": txid,
        "amount": amount
    })

@app.route("/bitcoin/get_utxos", methods=["GET"])
def bitcoin_get_utxos():
    utxo_list = []
    for (txid, vout), utxo in bitcoin_node.utxos.items():
        utxo_list.append({
            "txid": txid,
            "vout": vout,
            "value": utxo.value,
            "pubkey_hash": utxo.pubkey_hash_hex
        })
    return jsonify({"utxos": utxo_list})

@app.route("/bitcoin/create_transaction", methods=["POST"])
def bitcoin_create_transaction():
    data = request.get_json()
    sender_name = data.get("sender")
    recipient_name = data.get("recipient")
    amount = data.get("amount")
    fee = data.get("fee", 1)
    
    if sender_name not in bitcoin_wallets or recipient_name not in bitcoin_wallets:
        return jsonify({"success": False, "error": "Wallet not found"})
    
    sender = bitcoin_wallets[sender_name]
    recipient = bitcoin_wallets[recipient_name]
    
    # Find sender's UTXOs
    sender_utxos = [u for u in bitcoin_node.utxos.values() 
                    if u.pubkey_hash_hex == sender.pubkey_hash_hex()]
    
    if not sender_utxos:
        return jsonify({"success": False, "error": "No UTXOs available"})
    
    # Select UTXOs
    total_in = 0
    inputs = []
    for utxo in sender_utxos:
        inputs.append(utxo.outpoint)
        total_in += utxo.value
        if total_in >= amount + fee:
            break
    
    if total_in < amount + fee:
        return jsonify({"success": False, "error": "Insufficient funds"})
    
    change = total_in - amount - fee
    
    # Build transaction
    tx = Transaction(
        version=1,
        vin=[TxIn(prevout=op) for op in inputs],
        vout=[
            TxOut(value=amount, pubkey_hash_hex=recipient.pubkey_hash_hex()),
            TxOut(value=change, pubkey_hash_hex=sender.pubkey_hash_hex())
        ] if change > 0 else [TxOut(value=amount, pubkey_hash_hex=recipient.pubkey_hash_hex())],
        locktime=0
    )
    
    # Sign transaction
    digest = tx.signing_digest()
    for txin in tx.vin:
        txin.pubkey_hex = sender.pubkey_hex()
        txin.sig_hex = sign(sender.priv, digest).hex()
    
    # Validate and add to mempool
    ok, msg = bitcoin_node.accept_to_mempool(tx)
    
    return jsonify({
        "success": ok,
        "message": msg,
        "txid": tx.txid() if ok else None,
        "total_in": total_in,
        "amount": amount,
        "fee": fee,
        "change": change
    })

@app.route("/bitcoin/mine_block", methods=["POST"])
def bitcoin_mine_block():
    ok, msg = bitcoin_node.mine_block()
    return jsonify({"success": ok, "message": msg})

@app.route("/bitcoin/get_mempool", methods=["GET"])
def bitcoin_get_mempool():
    mempool_data = {}
    for txid, tx in bitcoin_node.mempool.items():
        mempool_data[txid] = tx.to_dict()
    return jsonify({"mempool": mempool_data})

@app.route("/bitcoin/get_blockchain", methods=["GET"])
def bitcoin_get_blockchain():
    return jsonify({"chain": bitcoin_node.chain})

# ============================================
# CIPHER ROUTES (ORIGINAL)
# ============================================

@app.route("/enterprimes")
def enter_primes():
    return render_template("/RSA_templates/enterprimes.html")

@app.route("/generate_keys_manual", methods=["POST"])
def generate_keys_manual():
    p = int(request.form["p"])
    q = int(request.form["q"])

    try:
        public_key_val, private_key_val, p_val, q_val, phi_val = rsacipherdemo.GenerateKeys(p, q)
    except ValueError as err:
        return render_template("/RSA_templates/enterprimes.html", error=str(err))

    e_val, n_val = public_key_val
    d_val, n_val = private_key_val

    return render_template(
        "/RSA_templates/keys.html",
        public_key=public_key_val,
        private_key=private_key_val,
        q=q_val,
        p=p_val,
        phi=phi_val,
        e=e_val,
        n=n_val,
        d=d_val
    )

@app.route("/set_algorithm", methods=["POST"])
def set_algorithms():
    algo = request.form.get("algo", "RSA")
    session["algorithm"] = algo
    return render_template("index.html", selected_algo=algo)

@app.route("/encrypt_with_key", methods=["POST"])
def encrypt_with_key():
    algo = session.get("algorithm", "RSA")
    session["used_algorithm"] = algo

    file = request.files["input_file"]
    out_path = os.path.join(OUTPUT, f"{algo}_encrypted.txt")

    match algo:
        case "RSA":
            raw_key = request.form.get("public_key", "").replace(" ", "")
            plaintext = file.read().decode("utf-8")

            if "," not in raw_key:
                flash("Public key phải có dạng e,n (ví dụ: 17,3233)", "error")
                return render_template("/RSA_templates/enterprimes.html")

            parts = raw_key.split(",")
            if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                flash("Public key không hợp lệ. Vui lòng nhập dạng e,n", "error")
                return render_template("/RSA_templates/enterprimes.html")

            e, n = map(int, parts)
            public_key = (e, n)

            cipher_block = rsacipherdemo.Encrypt(plaintext, public_key)
            with open(out_path, "w") as f:
                f.write(" ".join(str(x) for x in cipher_block))
            return send_file(out_path, as_attachment=True)

        case "DES":
            key_str = "nhauyen"
            key_bytes = key_str.encode("utf-8")
            plaintext = file.read().decode("utf-8")
            if len(key_bytes) < 8:
                key_bytes += b"\x00" * (8 - len(key_bytes))
            CURRENT_DES_KEY = key_bytes

            ciphertext = descipherdemo.Encrypt(plaintext, CURRENT_DES_KEY)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(ciphertext)
            return send_file(out_path, as_attachment=True)

        case "3DES":
            k1 = b"key1key1"
            k2 = b"key2key2"
            k3 = b"key3key3"
            plaintext = file.read().decode("utf-8")
            ciphertext = tripledes_demo.Encrypt(plaintext, k1, k2, k3)

            with open(out_path, "w", encoding="utf-8") as f:
                f.write(ciphertext)
            return send_file(out_path, as_attachment=True)

        case "AES":
            key_str = "mysecretkey12345"
            aes = AESCipher(key_str)
            plaintext_bytes = file.read()

            out_path = os.path.join(OUTPUT, f"{algo}_encrypted.bin")
            ciphertext_bytes = aes.encrypt(plaintext_bytes)

            with open(out_path, "wb") as f:
                f.write(ciphertext_bytes)
            return send_file(out_path, as_attachment=True)

        case _:
            return {"error": "Algorithm not supported"}

@app.route("/decrypt_with_key", methods=["POST"])
def decrypt_with_key():
    algo = session.get("algorithm", "RSA")
    used_algo = session.get("used_algorithm")
    file = request.files["input_file"]
    out_path = os.path.join(OUTPUT, f"{algo}_decrypted.txt")

    if used_algo != algo:
        flash(f"Wrong algorithm! File was encrypted with {used_algo}, not {algo}.")
        return render_template("index.html")

    match algo:
        case "RSA":
            raw_key = request.form.get("private_key", "").replace(" ", "")

            if "," not in raw_key:
                flash("Private key phải có dạng d,n (ví dụ: 2753,3233)", "error")
                return render_template("/RSA_templates/enterprimes.html")

            parts = raw_key.split(",")
            if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                flash("Private key không hợp lệ. Vui lòng nhập dạng d,n", "error")
                return render_template("/RSA_templates/enterprimes.html")

            d, n = map(int, parts)
            private_key = (d, n)

            cipher_text = file.read().decode("utf-8")
            cipher_blocks = [int(x) for x in cipher_text.split(" ")]

            plaintext = rsacipherdemo.Decrypt(cipher_blocks, private_key)
            with open(out_path, "w") as f:
                f.write(str(plaintext))
            return send_file(out_path, as_attachment=True)

        case "DES":
            key_bytes = b"nhauyen"
            if len(key_bytes) < 8:
                key_bytes += b"\x00" * (8 - len(key_bytes))
            cipher_text = file.read().decode("utf-8")
            plaintext = descipherdemo.Decrypt(cipher_text, key_bytes)

            with open(out_path, "w", encoding="utf-8") as f:
                f.write(plaintext)
            return send_file(out_path, as_attachment=True)

        case "3DES":
            k1 = b"key1key1"
            k2 = b"key2key2"
            k3 = b"key3key3"

            cipher_text = file.read().decode("utf-8")
            plaintext = tripledes_demo.Decrypt(cipher_text, k1, k2, k3)

            with open(out_path, "w", encoding="utf-8") as f:
                f.write(plaintext)
            return send_file(out_path, as_attachment=True)

        case "AES":
            key_str = "mysecretkey12345"
            aes = AESCipher(key_str)
            cipher_bytes = file.read()

            plain_bytes = aes.decrypt(cipher_bytes)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(plain_bytes.decode("utf-8", errors="ignore"))
            return send_file(out_path, as_attachment=True)

        case _:
            return {"error": "Algorithm not supported"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)