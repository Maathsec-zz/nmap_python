"""
FIAP
Defesa Cibernética - 1TDCF - 2021
Development e Coding for Security
Prof. MS. Fábio H. Cabrini
Atividade: Checkpoint NMAP em python
Alunos:
Laura Giancoli Aschenbrenner - RM 87194
Matheus Lambert Moreira - RM 87079
"""

import nmap
import socket

def nmapScan(host, ip, port):
# Executa um port scan no protocolo TCP no ativo recebido
    try:
        NMAPSCAN = nmap.PortScanner()
        NMAPSCAN.scan(ip, str(port))
        state = NMAPSCAN[ip]['tcp'][int(port)]['state']
        name = NMAPSCAN[ip]['tcp'][int(port)]['name']
        print("[*] tcp/" + port + " " + \
                state + " " + name)
    except:
        print("Nao foi possivel obter informacoes suficientes sobre a porta "\
                + port)
        pass

# Armazena as entradas do usuario
host = input("Host: ") 
ports = input("Porta(s): ")
ports = ports.split()


if not host or not ports:
	print("Voce precisa especificar um alvo e a(s) porta(s).")
	exit(0)

else:
	ip = socket.gethostbyname(host)
	print("Resultados para: " + host + " (" + ip + ")")
	for port in ports:
		nmapScan(host, ip, port)
