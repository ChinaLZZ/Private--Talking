import socket
import threading
import json
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
import base64


# 1. 加密/解密工具

#旧异或
def xor_crypt(data, key=0x5A):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return bytes([b ^ key for b in data]).decode('latin1')

def xor_decrypt(data, key=0x5A):
    if isinstance(data, str):
        data = data.encode('latin1')
    return bytes([b ^ key for b in data]).decode('utf-8')

#RSA

def rsa_init():
    random_generator = Random.new().read
    rsa = RSA.generate(2048, random_generator)
    private_key = rsa.exportKey().decode('utf-8')
    public_key = rsa.publickey().exportKey().decode('utf-8')
    return (private_key,public_key)

def rsa_encrypt(message, public_key):
    public_key = bytes(public_key, encoding='utf-8')
    rsa_key = RSA.importKey(public_key)
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted_message = base64.b64encode(cipher.encrypt(message.encode("utf-8")))
    return str(encrypted_message.decode("utf-8"))

def rsa_decrypt(encrypted_message, private_key):
    private_key = bytes(private_key, encoding='utf-8')
    rsa_key = RSA.importKey(private_key)
    cipher = PKCS1_v1_5.new(rsa_key)
    decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message), Random.new().read)
    return str(decrypted_message.decode("utf-8"))



HOST = '0.0.0.0'
PORT = 5000
PRIVATE_KEY = ''
PUBLIC_KEY = ''

clients = {}  # username: (socket, address)
lock = threading.Lock()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '127.0.0.1'

def broadcast_online_users():
    with lock:
        user_list = list(clients.keys())
        msg = json.dumps({'type': 'online_users', 'online_users': user_list})
        for sock, _ in clients.values():
            try:
                sock.send(msg.encode('utf-8'))
            except:
                pass

def handle_client(client_socket, address):
    username = None
    try:
        data = client_socket.recv(1024).decode('utf-8')
        info = json.loads(data)
        username = info['username']
        key = info['rsa_key']
        with lock:
            if username in clients:
                client_socket.send(json.dumps({'type': 'error', 'message': '用户名已存在'}).encode('utf-8'))
                client_socket.close()
                return
            clients[username] = (client_socket, address,key)
        # 连接成功响应
        client_socket.send(json.dumps({'type': 'connection_success', 'rsa_key':  PUBLIC_KEY ,'online_users': list(clients.keys())}).encode('utf-8'))
        broadcast_online_users()  # 新用户上线，广播
        while True:
            data = client_socket.recv(4096).decode('utf-8')
            if not data:
                break
            msg = json.loads(data)
            msg_type = msg.get('type')
            if msg_type == 'private_message':
                receiver = msg.get('receiver')
                if receiver in clients:
                    try:
                        clients[receiver][0].send(json.dumps({
                            'type': 'private_message',
                            'sender': username,
                            'message': rsa_encrypt(rsa_decrypt(msg.get('message'),PRIVATE_KEY),clients[receiver][2]),  
                            'is_private': msg.get('is_private', False),
                            'timestamp': ''
                        }).encode('utf-8'))
                    except:
                        pass
    except Exception as e:
        pass
    finally:
        with lock:
            if username and username in clients:
                del clients[username]
        broadcast_online_users()  # 用户下线，广播
        client_socket.close()

def main():
    ip = get_local_ip()
    print(f"当前IP: {ip} 端口: {PORT}")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    
    key = rsa_init()
    global PUBLIC_KEY,PRIVATE_KEY
    PUBLIC_KEY = key[0]
    PRIVATE_KEY = key[1]
    
    while True:
        client_socket, address = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, address), daemon=True).start()

if __name__ == '__main__':
    main()