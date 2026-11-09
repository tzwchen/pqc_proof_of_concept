import socket
import os
import oqs
from Cryptodome.Cipher import AES

HOST = "127.0.0.1"
PORT = 8989

SIG_ALG = "ML-DSA-65"   # CRYSTALS-Dilithium
KEM_ALG = "ML-KEM-768"  # CRYSTALS-Kyber

def run_client():
    print("[Client] Initializing PQC Identity (Dilithium)...")
    client_sig = oqs.Signature(SIG_ALG)
    client_pub_cert = client_sig.generate_keypair()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[Client] Connecting to server at {HOST}:{PORT}...")
    client_socket.connect((HOST, PORT))

    try:
        # --- STEP 1: CERTIFICATE EXCHANGE ---
        server_cert_len = int.from_bytes(client_socket.recv(4), "big")
        server_pub_cert = client_socket.recv(server_cert_len)
        print(f"[Client] Received Server Dilithium Certificate ({len(server_pub_cert)} bytes).")

        client_socket.sendall(len(client_pub_cert).to_bytes(4, "big") + client_pub_cert)

        # --- STEP 2: CHALLENGE / RESPONSE AUTHENTICATION ---
        challenge = client_socket.recv(32)
        client_signature = client_sig.sign(challenge)
        
        client_socket.sendall(len(client_signature).to_bytes(4, "big") + client_signature)
        
        auth_status = client_socket.recv(1)
        if auth_status != b"\x01":
            print("[Client] Authentication rejected by server.")
            return
        print("[Client] ✅ Authenticated successfully with server.")

        # --- STEP 3: KYBER KEY DERIVATION (KEM) ---
        with oqs.KeyEncapsulation(KEM_ALG) as client_kem:
            client_kem_pub = client_kem.generate_keypair()
            client_socket.sendall(len(client_kem_pub).to_bytes(4, "big") + client_kem_pub)

            ct_len = int.from_bytes(client_socket.recv(4), "big")
            ciphertext = client_socket.recv(ct_len)

            shared_secret = client_kem.decap_secret(ciphertext)
            print(f"[Client] Kyber Shared Secret Derived! Key (hex): {shared_secret[:8].hex()}...")
            print("[Client] --- Secure Tunnel Established. Type messages below ('exit' to quit) ---")

        aes_key = shared_secret[:32]

        # --- STEP 4: INTERACTIVE LIVE CHAT LOOP ---
        while True:
            # Prompt user for live input message
            msg = input("\n[Your message]: ")
            
            enc_cipher = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = enc_cipher.encrypt_and_digest(msg.encode())
            nonce = enc_cipher.nonce

            client_socket.sendall(len(nonce).to_bytes(4, "big") + nonce +
                                  len(tag).to_bytes(4, "big") + tag +
                                  len(ciphertext).to_bytes(4, "big") + ciphertext)

            if msg.lower() == "exit":
                print("[Client] Closing connection...")
                break

            # Receive encrypted response from server
            resp_nonce_len = int.from_bytes(client_socket.recv(4), "big")
            resp_nonce = client_socket.recv(resp_nonce_len)
            resp_tag_len = int.from_bytes(client_socket.recv(4), "big")
            resp_tag = client_socket.recv(resp_tag_len)
            resp_ct_len = int.from_bytes(client_socket.recv(4), "big")
            resp_encrypted = client_socket.recv(resp_ct_len)

            dec_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=resp_nonce)
            decrypted_resp = dec_cipher.decrypt_and_verify(resp_encrypted, resp_tag)
            print(f"[Server reply]: {decrypted_resp.decode()}")

    except Exception as e:
        print(f"[Client Error]: {e}")
    finally:
        client_socket.close()
        print("[Client] Connection closed.")

if __name__ == "__main__":
    run_client()
