import requests

# Abre o arquivo de texto para leitura
with open('consult_ips.txt', 'r') as file:
    # Lê cada linha do arquivo
    ips = file.readlines()
    # Remove espaços em branco e quebras de linha em cada linha e armazena os IPs em uma lista
    ips = [ip.strip() for ip in ips]

malicious_ip =[]
headers = {
    "accept": "application/json",
    "x-apikey": "bc21056dd7408e89531a0254061512fc6285c52cc1ff40c606efb4ba0de421c4"
}

for ip in ips:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(url, headers=headers)

    # Verifica se a solicitação foi bem-sucedida
    if response.status_code == 200:
        # Converte a resposta JSON em um dicionário Python
        data = response.json()
        
        # Extrai as informações necessárias
        ip = data["data"]["id"]
        criticality = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        location = data["data"]["attributes"]["country"]
        
        # Imprime as informações
        print("IP:", ip)
        print("Criticidade do IP:", criticality)
        print("Localizacao:", location)
        if criticality >= 50:
            print("Risco Alto")
        elif criticality < 50 and criticality >= 5:
            print("Risco Medio")
            malicious_ip.append(ip + ' ('+ location +')')
        else:
            print("Risco Baixo")
        print(" ")
        print("___________________________________________________________________________")
        print(" ")


    else:
        print("Falha na solicitação. Código de status:", response.status_code)

# Salva os IPs maliciosos em um arquivo de texto
with open('malicious_ips.txt', 'w') as file:
    for ip in malicious_ip:
        file.write(ip + '\n')

print("IP's maliciosos: ", malicious_ip)
print("Script finalizado!")