import socket

sock = socket.socket()
sock.bind(("0.0.0.0",9000))
sock.listen(5)

print("Aguardando conexoes...")

while True:

    cliente,endereco = sock.accept()

    dados = cliente.recv(4096)

    print(
        f"{endereco[0]} -> "
        f"{dados.decode()}"
    )

    cliente.close()
