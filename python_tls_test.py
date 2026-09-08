import socket
import ssl


HOST = "example.com"
PORT = 443


print("====================================")
print("       PYTHON TLS TEST CLIENT")
print("====================================")
print()

context = ssl.create_default_context()


with socket.create_connection(
    (HOST, PORT),
    timeout=10
) as sock:

    with context.wrap_socket(
        sock,
        server_hostname=HOST
    ) as tls_sock:

        print("TLS connection established")
        print()

        print("TLS Version:")
        print(tls_sock.version())

        print()

        print("Cipher:")
        print(tls_sock.cipher())

        print()

        print("Connection successful.")