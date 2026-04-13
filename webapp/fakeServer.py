import secrets
import hashlib
import hmac
from flask import Flask, request, jsonify

app = Flask(__name__)


N = None
g = None
v_int = None
v_hex = None
k = None
I = None
A_int = None
B_int = None
A_hex = None
B_hex = None
salt_hex = None
salt_bytes = None
b = None

def startup():
    global g, k, N, salt_hex, b
    g = 2
    k = 3
    N = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)
    salt_hex = secrets.token_hex(16)
    b = 1

    print(f'N: {N}')
    print(f'g: {g}')
    print(f'k: {k}')
    print(f"salt_hex: {salt_hex}")

@app.route('/get_salt', methods=['GET'])
def get_salt():
    print(f"salt_hex: {salt_hex}")
    return jsonify({"salt": salt_hex}), 201

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    global v_int, v_hex
    v_hex = data.get('v')
    print(f"v_hex: {v_hex}")
    v_int = int(v_hex, 16)
    
    return "OK", 200


@app.route('/auth_first_step', methods=['POST'])
def authenticate_first_step():

    data = request.get_json()

    global I, A_int, A_hex, B_int, B_hex
    I = data.get('I')
    A_int = int(data.get('A'), 16)
    A_hex = data.get('A')
    print(f"A_hex: {A_hex}")
    B_int = g
    B_hex = '0'+hex(g)[2:]
    print(f"B_hex: {B_hex}")
    return jsonify({"B": B_hex, "u": "01"}), 200

@app.route('/auth_last_step', methods=['POST'])
def authenticate_last_step():
    
    data = request.get_json()
    client_HMAC = data.get('HMAC')

    # ----------------------------------------------------
    global v_int, N
    n_length = (N.bit_length() + 7) // 8
    base = A_int*(v_int**1)
    exponent = 1
    S_int = pow(base,exponent,N)
    #S = (A * v ** u)**b % n
    #K = SHA256(S)
    print(f"S_int: {S_int}")

    S_bytes = S_int.to_bytes(n_length, byteorder='big')
    
    print(f"S_bytes (hex): {S_bytes.hex()}")

    K_hex = hashlib.sha256(S_bytes).hexdigest()
    K_bytes = hashlib.sha256(S_bytes).digest()

    global salt_bytes
    salt_bytes = bytes.fromhex(salt_hex)

    generated_HMAC = hmac.new(K_bytes, salt_bytes, hashlib.sha256).hexdigest()
    # ----------------------------------------------------
    # TODO CRACK THE PASSWORD FROM THE GIVEN HMAC BY THE CLIENT
    password_dictionary = {"password"}
    for p in password_dictionary:
        x_gen_hash = hashlib.sha256(salt_bytes+p.encode('ascii'))
        xH_hex = x_gen_hash.hexdigest()
        x = int(xH_hex,16)
        S_gen_int = (A_int * pow(g,x,N)) % N
        S_gen_bytes = S_gen_int.to_bytes(n_length, byteorder='big')
        K_gen_hex = hashlib.sha256(S_gen_bytes).hexdigest()
        K_gen_bytes = hashlib.sha256(S_gen_bytes).digest()
        cracked_HMAC = hmac.new(K_gen_bytes, salt_bytes, hashlib.sha256).hexdigest()
        if(cracked_HMAC == client_HMAC):
            print(f"Password cracked: {p}")

        
    # ----------------------------------------------------
    print(f"generated_HMAC: {generated_HMAC}")
    if client_HMAC == generated_HMAC:
        return "Authentication OK", 200
    else:
        return "Authentication Failed", 401 

if __name__ == '__main__':
    startup()
    app.run(port=5000)
