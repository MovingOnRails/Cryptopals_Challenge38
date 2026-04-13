# Client.py
import requests
import hashlib
import secrets
import hmac


password = "password"
password_bytes = None
v_int = None
v_hex = None
g = 2
k = 3
N = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff', 16)
salt_hex = None
A_int = None
A_hex = None
a = 0
B_int = None
B_hex = None
u_int = None
u_hex = None


#------------------------------------------------------------------------
def get_salt():
    
    print("------------------get_salt()------------------")
    try:
        response = requests.get("http://localhost:5000/get_salt")
        
        print(f"Status Code: {response.status_code}")
        
        # 3. .json() must be called as a method
        if response.status_code == 201:
            data = response.json() 
            global salt_hex
            salt_hex = data.get("salt")
            print(f"salt_hex: {salt_hex}")
            
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

#------------------------------------------------------------------------
def register():
    print("------------------register()------------------")
    try:
        global salt_hex, salt_bytes

        salt_bytes = bytes.fromhex(salt_hex)
        global password, password_bytes
        password_bytes = password.encode('ascii')
        xH_bytes_hash = hashlib.sha256(salt_bytes+password_bytes)
        xH_bytes = xH_bytes_hash.digest()
        x = int.from_bytes(xH_bytes, byteorder='big')
        global v_int, v_hex
        v_int = pow(g,x,N)
        v_hex = hex(v_int)[2:]
        print(f"v_hex: {v_hex}")
        payload = { "v": v_hex}
        response = requests.post("http://localhost:5000/register",json=payload)
        print(f"response status: {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")


def auth_first_step():
    print("------------------auth_first_step()------------------")
    try:

        global g, a, N, A_int, A_hex
        A_int = pow(g,a,N)
        A_hex = hex(A_int)[2:]
        payload = {
            'I': 'alice@alicemail.com',
            'A': A_hex
        }
        response = requests.post("http://localhost:5000/auth_first_step",json=payload)
        print(f"response status: {response.status_code}")
        if(response.status_code == 200):
            data = response.json()
            global B_int, B_hex, u_hex, u_int
            B_hex = data.get("B")
            B_int = int(B_hex, 16)
            u_hex = data.get("u")
            u_int = int(u_hex, 16)

            print(f"B_hex {B_hex}")
            print(f"B_int {B_int}")
            print(f"u_hex {u_hex}")
            print(f"u_int {u_int}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def auth_last_step():
    print("------------------auth_last_step()------------------")
    global salt_bytes
    xH_bytes_hash = hashlib.sha256(salt_bytes+password_bytes)
    xH_hex = xH_bytes_hash.hexdigest()
    x = int(xH_hex,16)

    global a, u_int, N
    term1 = a
    term2 = u_int*x
    exponent = term1+term2
    S_int = pow(B_int,exponent,N)
    
    n_length = (N.bit_length() + 7) // 8
    S_bytes = S_int.to_bytes(n_length, byteorder='big')
    print(f"S_bytes (hex): {S_bytes.hex()}")
    K_hash = hashlib.sha256(S_bytes)
    K_bytes = K_hash.digest()

    client_HMAC = hmac.new(K_bytes, salt_bytes, hashlib.sha256).hexdigest()
    print(f"client_HMAC: {client_HMAC}")
    # Send HMAC to the fake server
    payload = { "HMAC": client_HMAC}
    response = requests.post("http://localhost:5000/auth_last_step", json=payload)
    print(f"response status code: {response.status_code}")
    print(f"response text {response.text}")


#------------------------------------------------------------------------
if __name__ == '__main__':
    while a == 0:
        a = secrets.randbelow(N)
    get_salt()
    register()
    auth_first_step()
    auth_last_step()