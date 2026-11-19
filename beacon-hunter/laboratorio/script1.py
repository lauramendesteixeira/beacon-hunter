import socket
import platform
import getpass
import time
from datetime import datetime

SERVIDOR = "127.0.0.1"     # coloque o IP da sua máquina
                          # veja através do ipconfig no cmd
                          # Adaptador de Rede sem fio Wi-Fi  
PORTA = 9000

while True:

    try:

        hostname = socket.gethostname()

        mensagem = (
            f"{datetime.now()} | "
            f"Host={hostname} | "
            f"Usuario={getpass.getuser()} | "
            f"Sistema={platform.system()}"
        )

        s = socket.socket()
        s.connect((SERVIDOR, PORTA))
        s.send(mensagem.encode())
        s.close()

        print("Informacoes enviadas")

    except:
        pass

    time.sleep(30)
