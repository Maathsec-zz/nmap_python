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

def nmapTCP(host, ip, port):
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


def nmapUDP(host, ip, port):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=ip, ports=str(port), arguments='-Pn -sU ', sudo=True)
        state = scanner[ip]['udp'][int(port)]['state']
        name = scanner[ip]['udp'][int(port)]['name']
        print("[*] udp/" + port + " " + \
                state + " " + name)
    
    except:
        print("Não foi possível realizar o UDP scan")
           
        pass

# Armazena as entradas do usuario
host = input("Host: ") 
ports = input("Porta(s): ")
ports = ports.split()
protocolo = input("Qual o protocolo? (Digite \"UDP\" ou \"TCP\"): ")

if not host or not ports or not protocolo:
	print("Voce precisa especificar um alvo, a(s) porta(s) e o protocolo.")
	exit(0)

else:
	if (protocolo == "TCP"):
                ip = socket.gethostbyname(host)
                print("Resultados no protocolo TCP para: " + host + " (" + ip + ")")
                for port in ports:
                        nmapTCP(host, ip, port)

	elif (protocolo == "UDP"):
                ip = socket.gethostbyname(host)
                print("Resultados no protocolo UDP para: " + host + " (" + ip + ")")
                for port in ports:
                        nmapUDP(host, ip, port)
