from Crypto.Util import number
from aescipher import AESCipher
import socket, select

def receive_message(client_socket):
    try:
        msg = client_socket.recv(1024)
        if not len(msg):
            return False
        return msg.decode()

    except:
        return False

def secure_receive_message(client_socket):
    global ciphers
    try:
        cipher = ciphers[client_socket]
        msg = client_socket.recv(1024)
        if not len(msg):
            return False
        return cipher.decrypt(msg)

    except:
        return False

def mod_exp(x, e, m):
    X = x
    E = e
    Y = 1
    while E > 0:
        if E % 2 == 0:
            X = (X * X) % m
            E = E/2
        else:
            Y = (X * Y) % m
            E = E - 1
    return Y

def encrypt_traffic(client_socket):
    # diffie hellman implementation
    global ciphers
    mykey = number.getPrime(128)
    base = number.getPrime(128)
    mod = number.getPrime(128)
    client_socket.send((str(base) + '|' + str(mod)).encode())
    client_socket.send(str(mod_exp(base, mykey, mod)).encode())
    msg = int(client_socket.recv(1024).decode())
    sk = str(mod_exp(msg, mykey, mod))
    print(f'AES secret key for {clients[client_socket]}: ', sk)
    cipher = AESCipher(sk)
    ciphers[client_socket] = cipher

IP = "127.0.0.1"
PORT = 10000
server_socket = socket.socket()
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((IP, PORT))
server_socket.listen()

sockets_list = [server_socket]
clients = {}
ciphers = {}

print(f'Listening for connections on {IP}:{PORT}...')

while True:
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)
    for notified_socket in read_sockets:
        if notified_socket == server_socket:
            client_socket, client_address = server_socket.accept()
            user = receive_message(client_socket)
            if user is False:
                continue
            sockets_list.append(client_socket)
            clients[client_socket] = user

            print('Accepted new connection from {}:{}, username: {}'.format(*client_address, user))
            encrypt_traffic(client_socket)
        else:
            message = secure_receive_message(notified_socket)
            user = clients[notified_socket]
            if message is False:
                print('Closed connection from: {}'.format(clients[notified_socket]))
                for client_socket in clients:
                    if client_socket != notified_socket:
                        formatted = user + '|' + '~'
                        client_socket.send(formatted.encode())
                sockets_list.remove(notified_socket)
                del clients[notified_socket]
                continue

            print(f'Received message from {user}: {message}')
            for client_socket in clients:
                if client_socket != notified_socket:
                    formatted = user + '|' + message
                    cipher = ciphers[client_socket]
                    client_socket.send(cipher.encrypt(formatted))
    for notified_socket in exception_sockets:
        sockets_list.remove(notified_socket)
        del clients[notified_socket]