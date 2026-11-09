import socket
import os
import oqs
from Cryptodome.Cipher import AES

HOST = "127.0.0.1"
PORT = 8989

SIG_ALG = "ML-DSA-65"   # CRYSTALS-Dilithium
KEM_ALG = "ML-KEM-768"  # CRYSTALS-Kyber

def run_server():
    print("[Server] Initializing PQC Identity (Dilithium)...")
    server_sig = oqs.Signature(SIG_ALG)
    server_pub_cert = server_sig.generate_keypair()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    
    print(f"[Server] Listening for client on {HOST}:{PORT}...")
    conn, addr = server_socket.accept()
    print(f"[Server] Client connected from {addr}")

    try:
        # --- STEP 1: CERTIFICATE EXCHANGE ---
        conn.sendall(len(server_pub_cert).to_bytes(4, "big") + server_pub_cert)
        
        client_cert_len = int.from_bytes(conn.recv(4), "big")
        client_pub_cert = conn.recv(client_cert_len)
        print(f"[Server] Received Client Dilithium Certificate ({len(client_pub_cert)} bytes).")

        # --- STEP 2: CHALLENGE / RESPONSE AUTHENTICATION ---
        challenge = os.urandom(32)
        conn.sendall(challenge)
        
        sig_len = int.from_bytes(conn.recv(4), "big")
        client_signature = conn.recv(sig_len)
        
        client_verifier = oqs.Signature(SIG_ALG)
        if client_verifier.verify(challenge, client_signature, client_pub_cert):
            print("[Server] Client Challenge/Response Signature VERIFIED.")
            conn.sendall(b"\x01")
        else:
            print("[Server] Client Authentication FAILED.")
            conn.sendall(b"\x00")
            return

        # --- STEP 3: KYBER KEY DERIVATION (KEM) ---
        client_kem_pub_len = int.from_bytes(conn.recv(4), "big")
        client_kem_pub = conn.recv(client_kem_pub_len)

        with oqs.KeyEncapsulation(KEM_ALG) as server_kem:
            ciphertext, shared_secret = server_kem.encap_secret(client_kem_pub)
            
        conn.sendall(len(ciphertext).to_bytes(4, "big") + ciphertext)
        print(f"[Server] Kyber Shared Secret Derived! Key (hex): {shared_secret[:8].hex()}...")
        print("[Server] --- Secure Tunnel Established. Ready for live chat ---")

        aes_key = shared_secret[:32]

        # --- STEP 4: INTERACTIVE LIVE CHAT LOOP ---
        while True:
            # Receive message from client
            header = conn.recv(4)
            if not header:
                break
            nonce_len = int.from_bytes(header, "big")
            nonce = conn.recv(nonce_len)
            tag_len = int.from_bytes(conn.recv(4), "big")
            tag = conn.recv(tag_len)
            ct_len = int.from_bytes(conn.recv(4), "big")
            encrypted_msg = conn.recv(ct_len)

            dec_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            decrypted_msg = dec_cipher.decrypt_and_verify(encrypted_msg, tag)
            print(f"\n[Client says]: {decrypted_msg.decode()}")

            if decrypted_msg.decode().lower() == "exit":
                print("[Server] Client requested disconnect.")
                break

            # Prompt server operator for a reply
            reply_text = input("[Server reply]: ")
            enc_cipher = AES.new(aes_key, AES.MODE_GCM)
            resp_ciphertext, resp_tag = enc_cipher.encrypt_and_digest(reply_text.encode())
            resp_nonce = enc_cipher.nonce

            conn.sendall(len(resp_nonce).to_bytes(4, "big") + resp_nonce +
                         len(resp_tag).to_bytes(4, "big") + resp_tag +
                         len(resp_ciphertext).to_bytes(4, "big") + resp_ciphertext)

    except Exception as e:
        print(f"[Server Error]: {e}")
    finally:
        conn.close()
        server_socket.close()
        print("[Server] Connection closed.")

if __name__ == "__main__":
    run_server()
