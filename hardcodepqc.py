import socket
import threading
import os
import oqs
from Cryptodome.Cipher import AES

HOST = "127.0.0.1"
PORT = 8989

# Post-Quantum Algorithm definitions
SIG_ALG = "ML-DSA-65"   # CRYSTALS-Dilithium
KEM_ALG = "ML-KEM-768"  # CRYSTALS-Kyber

def server_worker():
    print("[Server] Initializing PQC Identity (Dilithium)...")
    server_sig = oqs.Signature(SIG_ALG)
    server_pub_cert = server_sig.generate_keypair()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    
    conn, addr = server_socket.accept()
    print(f"[Server] Client connected from {addr}")

    try:
        # --- STEP 1: CERTIFICATE EXCHANGE ---
        conn.sendall(len(server_pub_cert).to_bytes(4, "big") + server_pub_cert)
        
        client_cert_len = int.from_bytes(conn.recv(4), "big")
        client_pub_cert = conn.recv(client_cert_len)
        print(f"[Server] Received Client Dilithium Certificate ({len(client_pub_cert)} bytes).")

        #STEP 2: CHALLENGE / RESPONSE AUTHENTICATION
        challenge = os.urandom(32)
        conn.sendall(challenge)
        
        sig_len = int.from_bytes(conn.recv(4), "big")
        client_signature = conn.recv(sig_len)
        
        client_verifier = oqs.Signature(SIG_ALG)
        if client_verifier.verify(challenge, client_signature, client_pub_cert):
            print("[Server] ✅ Client Challenge/Response Signature VERIFIED.")
            conn.sendall(b"\x01") # Auth OK
        else:
            print("[Server] ❌ Client Authentication FAILED.")
            conn.sendall(b"\x00")
            return

        #STEP 3: KYBER KEY DERIVATION (KEM / DH EQUIVALENT)
        client_kem_pub_len = int.from_bytes(conn.recv(4), "big")
        client_kem_pub = conn.recv(client_kem_pub_len)

        with oqs.KeyEncapsulation(KEM_ALG) as server_kem:
            ciphertext, shared_secret = server_kem.encap_secret(client_kem_pub)
            
        conn.sendall(len(ciphertext).to_bytes(4, "big") + ciphertext)
        print(f"[Server] Kyber Shared Secret Derived Successfully! Key (hex): {shared_secret[:8].hex()}...")

        #STEP 4: ENCRYPTED TUNNEL COMMUNICATION (Using PyCryptodome AES-GCM) 
        nonce_len = int.from_bytes(conn.recv(4), "big")
        nonce = conn.recv(nonce_len)
        tag_len = int.from_bytes(conn.recv(4), "big")
        tag = conn.recv(tag_len)
        ct_len = int.from_bytes(conn.recv(4), "big")
        encrypted_msg = conn.recv(ct_len)

        #Derive 256-bit symmetric key and decrypt using PyCryptodome GCM
        aes_key = shared_secret[:32]
        dec_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_msg = dec_cipher.decrypt_and_verify(encrypted_msg, tag)
        print(f"[Server] Decrypted tunnel message: '{decrypted_msg.decode()}'")

        #Send response back over tunnel
        reply = b"Hello from PQC Server! Tunnel active and secure via PyCryptodome."
        enc_cipher = AES.new(aes_key, AES.MODE_GCM)
        resp_ciphertext, resp_tag = enc_cipher.encrypt_and_digest(reply)
        resp_nonce = enc_cipher.nonce

        conn.sendall(len(resp_nonce).to_bytes(4, "big") + resp_nonce +
                     len(resp_tag).to_bytes(4, "big") + resp_tag +
                     len(resp_ciphertext).to_bytes(4, "big") + resp_ciphertext)

    except Exception as e:
        print(f"[Server Error]: {e}")
    finally:
        conn.close()
        server_socket.close()

def client_worker():
    import time
    time.sleep(0.5)

    print("[Client] Initializing PQC Identity (Dilithium)...")
    client_sig = oqs.Signature(SIG_ALG)
    client_pub_cert = client_sig.generate_keypair()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    try:
        #STEP 1: CERTIFICATE EXCHANGE
        server_cert_len = int.from_bytes(client_socket.recv(4), "big")
        server_pub_cert = client_socket.recv(server_cert_len)
        print(f"[Client] Received Server Dilithium Certificate ({len(server_pub_cert)} bytes).")

        client_socket.sendall(len(client_pub_cert).to_bytes(4, "big") + client_pub_cert)

        #STEP 2: CHALLENGE / RESPONSE AUTHENTICATION
        challenge = client_socket.recv(32)
        client_signature = client_sig.sign(challenge)
        
        client_socket.sendall(len(client_signature).to_bytes(4, "big") + client_signature)
        
        auth_status = client_socket.recv(1)
        if auth_status != b"\x01":
            print("[Client] Authentication rejected by server.")
            return
        print("[Client] Authenticated successfully with server.")

        #STEP 3: KYBER KEY DERIVATION (KEM)
        with oqs.KeyEncapsulation(KEM_ALG) as client_kem:
            client_kem_pub = client_kem.generate_keypair()
            client_socket.sendall(len(client_kem_pub).to_bytes(4, "big") + client_kem_pub)

            ct_len = int.from_bytes(client_socket.recv(4), "big")
            ciphertext = client_socket.recv(ct_len)

            shared_secret = client_kem.decap_secret(ciphertext)
            print(f"[Client] Kyber Shared Secret Derived Successfully! Key (hex): {shared_secret[:8].hex()}...")

        #STEP 4: ENCRYPTED TUNNEL COMMUNICATION (Using PyCryptodome AES-GCM)
        aes_key = shared_secret[:32]
        tunnel_msg = b"Hello Quantum World! Secure data passing through PQC tunnel using PyCryptodome."
        
        enc_cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = enc_cipher.encrypt_and_digest(tunnel_msg)
        nonce = enc_cipher.nonce

        client_socket.sendall(len(nonce).to_bytes(4, "big") + nonce +
                              len(tag).to_bytes(4, "big") + tag +
                              len(ciphertext).to_bytes(4, "big") + ciphertext)

        #Receive encrypted response
        resp_nonce_len = int.from_bytes(client_socket.recv(4), "big")
        resp_nonce = client_socket.recv(resp_nonce_len)
        resp_tag_len = int.from_bytes(client_socket.recv(4), "big")
        resp_tag = client_socket.recv(resp_tag_len)
        resp_ct_len = int.from_bytes(client_socket.recv(4), "big")
        resp_encrypted = client_socket.recv(resp_ct_len)

        dec_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=resp_nonce)
        decrypted_resp = dec_cipher.decrypt_and_verify(resp_encrypted, resp_tag)
        print(f"[Client] Decrypted tunnel reply: '{decrypted_resp.decode()}'")

    except Exception as e:
        print(f"[Client Error]: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    t_server = threading.Thread(target=server_worker)
    t_client = threading.Thread(target=client_worker)

    t_server.start()
    t_client.start()

    t_server.join()
    t_client.join()
