import socket
import threading
import json

HOST = '0.0.0.0'
PORT = 5000

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
        with lock:
            if username in clients:
                client_socket.send(json.dumps({'type': 'error', 'message': '用户名已存在'}).encode('utf-8'))
                client_socket.close()
                return
            clients[username] = (client_socket, address)
        # 连接成功响应
        client_socket.send(json.dumps({'type': 'connection_success', 'online_users': list(clients.keys())}).encode('utf-8'))
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
                            'message': msg.get('message'),  # 密文原样转发
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
    while True:
        client_socket, address = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, address), daemon=True).start()

if __name__ == '__main__':
    main()