import socket
import threading
import ssl
from OpenSSL import SSL
import socks

class SecureSocks5Server:
    def __init__(self, host='0.0.0.0', port=1080, certfile='server.crt', keyfile='server.key'):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server = ssl.wrap_socket(self.server, server_side=True, certfile=self.certfile, keyfile=self.keyfile)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"Secure SOCKS5 server started on {self.host}:{self.port}")

    def handle_client(self, client_socket):
        try:
            # Handshake
            client_socket.recv(262)  # Receive the handshake request
            client_socket.sendall(b'\x05\x00')  # Send handshake response (no authentication)

            # Request
            data = client_socket.recv(4)
            mode = data[1]

            if mode == 1:  # CONNECT command
                address_type = data[3]
                if address_type == 1:  # IPv4
                    address = socket.inet_ntoa(client_socket.recv(4))
                elif address_type == 3:  # Domain name
                    domain_length = client_socket.recv(1)[0]
                    address = client_socket.recv(domain_length).decode()
                port = int.from_bytes(client_socket.recv(2), 'big')

                # Connect to the target server
                remote_socket = socks.socksocket()
                remote_socket.connect((address, port))

                # Reply to the client
                client_socket.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + port.to_bytes(2, 'big'))

                # Transfer data between client and remote server
                while True:
                    remote_socket.settimeout(1)
                    client_socket.settimeout(1)
                    try:
                        data = client_socket.recv(4096)
                        if len(data) > 0:
                            remote_socket.sendall(data)
                    except socket.timeout:
                        pass
                    try:
                        data = remote_socket.recv(4096)
                        if len(data) > 0:
                            client_socket.sendall(data)
                    except socket.timeout:
                        pass
            client_socket.close()
        except Exception as e:
            print(f"Error: {e}")
            client_socket.close()

    def start(self):
        while True:
            client_socket, addr = self.server.accept()
            print(f"Accepted connection from {addr}")
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_handler.start()

