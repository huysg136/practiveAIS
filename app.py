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
CURRENT_PUBLIC_KEY = None 
CURRENT_PRIVATE_KEY = None
CURRENT_DES_KEY = None
DEFAULT_KEY = None

OUTPUT = "output"
os.makedirs(OUTPUT, exist_ok=True)

###### MAIN HOMEPAGE #######
@app.route("/")
def home():
    return render_template("index.html", selected_algo = session.get("algorithm", "RSA"))

##### RSA ONLY - LET USERS CHOOSE 2 PRIME NUMBERS #####
@app.route("/enterprimes")
def enter_primes():
    return render_template("/RSA_templates/enterprimes.html")

#### RSA ONLY - GENERATE PUBLIC AND PRIVATE KEY FOR RSA #####
@app.route("/generate_keys_manual", methods=["POST"])
def generate_keys_manual():
    global CURRENT_PUBLIC_KEY, CURRENT_PRIVATE_KEY
    p = int(request.form["p"])
    q = int(request.form["q"])
    
    try:
        CURRENT_PUBLIC_KEY, CURRENT_PRIVATE_KEY, p_val, q_val, phi_val = rsacipherdemo.GenerateKeys(p, q)
    except ValueError as err:
        return render_template("/RSA_templates/enterprimes.html", error=str(err))

    e_val,n_val = CURRENT_PUBLIC_KEY
    d_val,n_val = CURRENT_PRIVATE_KEY

    return render_template(
        "/RSA_templates/keys.html",
        public_key=CURRENT_PUBLIC_KEY,
        private_key=CURRENT_PRIVATE_KEY,
        q = q_val,
        p = p_val,
        phi = phi_val,
        e = e_val,
        n = n_val,
        d = d_val
    )

##### LET USER CHOOSE ALGORITHMS / STORE SELECTED ALGORITHM IN SESSION ######
@app.route("/set_algorithm", methods=["POST"])
def set_algorithms():
    algo = request.form.get("algo", "RSA")
    session["algorithm"] = algo
    return render_template("index.html", selected_algo=algo)

###### ENCRYPT USING KEY PROVIDED #######
@app.route("/encrypt_with_key", methods=["POST"])
def encrypt_with_key():
    algo = session.get("algorithm", "RSA")
    session["used_algorithm"] = algo

    file  = request.files["input_file"]
    out_path = os.path.join(OUTPUT, f"{algo}_encrypted.txt")

    match algo:
        case "RSA":
            global CURRENT_PUBLIC_KEY 
            plaintext = file.read().decode("utf-8")
            if CURRENT_PUBLIC_KEY is None: 
                flash("You must generate an RSA key pair before encrypting.", "error")
                return render_template("/RSA_templates/enterprimes.html")
            
            cipher_block = rsacipherdemo.Encrypt(plaintext, CURRENT_PUBLIC_KEY)
            with open(out_path,"w") as f:
                f.write(" ".join(str(x) for x in cipher_block))
            return send_file(out_path, as_attachment=True)
        
        case "DES":
            key_str = "nhauyen"
            key_bytes = key_str.encode('utf-8')
            plaintext = file.read().decode("utf-8")
            if len(key_bytes) < 8:
                key_bytes += b'\x00' * (8 - len(key_bytes))
            CURRENT_DES_KEY = key_bytes
            ciphertext = descipherdemo.Encrypt(plaintext, CURRENT_DES_KEY)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(ciphertext)
            return send_file(out_path, as_attachment=True)

        case "3DES":
            # Triple DES EDE với 3 key cố định 8 bytes
            k1 = b'key1key1'
            k2 = b'key2key2'
            k3 = b'key3key3'
            plaintext = file.read().decode("utf-8")
            ciphertext = tripledes_demo.Encrypt(plaintext, k1, k2, k3)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(ciphertext)
            return send_file(out_path, as_attachment=True)
        
        case "AES": 
            key_str = "mysecretkey12345"  # 16 bytes
            aes = AESCipher(key_str)
            file.seek(0)
            plaintext_bytes = file.read()
            out_path = os.path.join(OUTPUT, f"{algo}_encrypted.bin")
            ciphertext_bytes = aes.encrypt(plaintext_bytes)
            with open(out_path, "wb") as f:
                f.write(ciphertext_bytes)
            return send_file(out_path, as_attachment=True)

        case _:
            return {"error": "Algorithm not supported"}
    
    return send_file(out_path, as_attachment=True)

###### DECRYPT USING KEY PROVIDED #######
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
            global CURRENT_PRIVATE_KEY 
            cipher_text = file.read().decode("utf-8")
            if CURRENT_PRIVATE_KEY is None: 
                flash("You must generate an RSA key pair before decrypting.", "error")
                return render_template("/RSA_templates/enterprimes.html")
            cipher_blocks = [int(x) for x in cipher_text.split(" ")]
            plaintext = rsacipherdemo.Decrypt(cipher_blocks, CURRENT_PRIVATE_KEY)
            with open(out_path,"w") as f:
                f.write(str(plaintext))
            return send_file(out_path, as_attachment=True)
        
        case "DES":
            key_bytes = b'nhauyen'
            if len(key_bytes) < 8:
                key_bytes += b'\x00' * (8 - len(key_bytes))
            cipher_text = file.read().decode("utf-8")
            plaintext = descipherdemo.Decrypt(cipher_text, key_bytes)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(plaintext)
            return send_file(out_path, as_attachment=True)

        case "3DES":
            k1 = b'key1key1'
            k2 = b'key2key2'
            k3 = b'key3key3'
            cipher_text = file.read().decode("utf-8")
            plaintext = tripledes_demo.Decrypt(cipher_text, k1, k2, k3)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(plaintext)
            return send_file(out_path, as_attachment=True)
        
        case "AES":
            key_str = "mysecretkey12345"
            aes = AESCipher(key_str)
            file.seek(0)
            cipher_bytes = file.read()
            plain_bytes = aes.decrypt(cipher_bytes)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(plain_bytes.decode("utf-8", errors="ignore"))
            return send_file(out_path, as_attachment=True)
        
        case _:
            return {"error": "Algorithm not supported"}
        
    return send_file(out_path, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
