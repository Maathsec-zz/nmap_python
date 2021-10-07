# PortScanner

O código foi validado no sistema kali linux.

##Dependências

1. python3
2. python-nmap

##Modo de uso

```python3 nmap.py```
Adicione o HOST
Quando solicitado, adicione a(s) porta(s) neste formato: 80 443 8080
(Com espaços como separador das portas)

Exemplo da saída do script:
```
#python3 nmap.py
Host: 127.0.0.1
Porta(s): 80 443 8080
Resultados para: 127.0.0.1 (127.0.0.1)
[*] tcp/80 closed http
[*] tcp/443 closed https
[*] tcp/8080 closed http-proxy

```

