from cipher.rsa.rsa_cipher import GenerateKeys, Encrypt, Decrypt
from cipher.rsa.rsa_cipher_demo import RSADemo
from cipher.des.des_cipher import DESDemo
from cipher.triple_des.triple_des_cipher import TripleDESDemo
from cipher.aes.aes_cipher import AESCipher
from flask import Flask, flash, redirect, render_template, request, send_file, session
import os

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

###### MAIN HOMEPAGE #######
@app.route("/")
def home():
    return render_template("index.html", selected_algo=session.get("algorithm", "RSA"))

##### RSA ONLY - LET USERS CHOOSE 2 PRIME NUMBERS #####
@app.route("/enterprimes")
def enter_primes():
    return render_template("/RSA_templates/enterprimes.html")

#### RSA ONLY - GENERATE PUBLIC AND PRIVATE KEY FOR RSA #####
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

##### LET USER CHOOSE ALGORITHMS #####
@app.route("/set_algorithm", methods=["POST"])
def set_algorithms():
    algo = request.form.get("algo", "RSA")
    session["algorithm"] = algo
    return render_template("index.html", selected_algo=algo)

##########################################
########### ENCRYPT WITH KEY #############
##########################################
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

            # --- FIX FORMAT ERROR ---
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

##########################################
########### DECRYPT WITH KEY #############
##########################################
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

            # --- FIX FORMAT ERROR ---
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
