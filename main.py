import json
from time import sleep
import requests
from requests.exceptions import ConnectionError
import platform  # For getting the operating system name
import subprocess  # For executing a shell command


# config = {"wan_IP": "192.168.0.1",
#           "router_IP": "192.168.1.1",
#           "http_username": "admin",
#           "http_password": "admin",
#           "ssid": "SerEla",
#           "wifi_password": "novamulher01"}

def load_config():
    f = open('config.json')
    return json.load(f)

#carrega configuracoes do json
config = load_config()

urlwds = "http://" + config["router_IP"] + "/goform/WDSScan"
urlpost = "http://" + config["router_IP"] + "/goform/wirelessMode"
urlreboot = "http://" + config["router_IP"] + "/goform/SysToolReboot"


# funcao que faz um request pra url no roteador e retorna lista de roteadores no formato [ssid, mac, canal,
# encriptação, sinal]
def query_aps():
    r = "<Response [401]>"

    # o loop é necessário pois o roteador aparentemente responde 401 na primeira tentativa por algum motivo.
    while str(r) == "<Response [401]>":
        try:
            # na primeira vez as vezes retorna "<Response [401]>" e executa sem erros se ocorrer o loop executa novamente
            r = str(requests.get(urlwds, auth=(config["http_username"], config["http_password"])))
        except ConnectionError as e:
            # quando o request nao falha com 401, o roteador responde mas por alguma não conformidade com o protocolo
            # http a resposta acaba causando com uma exceção, felizmente a resposta que o roteador forneceu é adicionada
            # ao erro da excessão tornando possível capturar a exception para extrair a resposta
            r = str(e)
    # r = "('Connection aborted.', BadStatusLine('PERGUNTAPROCACHORRO,e0:1c:fc:a0:27:06,1,AES  ,5    ;
    # SUAVEDEPIL 2.4,ac:f9:70:42:c9:80,1,AES  ,34   ;Jujubeachwear,98:da:c4:eb:19:d2,2,AES  ,20   ;
    # Madame Gi_2G,14:6b:9a:16:43:82,4,AES  ,15   ;Tenda_FAD340,e8:65:d4:fa:d3:40,4,NONE ,15   ;
    # SerEla,e4:c3:2a:66:17:c8,10,AES  ,100  ;Conceito Studio,98:da:c4:89:c4:74,11,AES  ,15   ;
    # AkiSushiBAR_WIFI,54:e6:fc:a9:46:ea,13,AES  ,24   ;LIVE TIM_0176_2G,8c:dc:02:16:fb:66,13,AES  ,0    \r\n'))"
    # remove a porção inicial ate o segundo parentesis como tambem os parentesis e caracteres de escape ao final da
    # string, fazendo uma conversão para lista separando no ";"
    lista_crua = ",".join(r[1:-1].split(",")[1:])[16:-6].split(";")
    # print(lista_crua)
    # quebra a lista em uma nova lista de listas, com todos os caracteres de espaco removidos
    saida = list(map(lambda x: list(map(lambda y: y.strip(), x.split(","))), lista_crua))
    return saida


def get_wifi_data():
    dados = query_aps()
    wifi_data = list(filter(lambda x: x[0] == config["ssid"], dados))[0]
    return wifi_data


def upload_wifi_data(wifi_data):
    # ['SerEla', 'e4:c3:2a:66:17:c8', '10', 'AES', '100']
    # wlMode=1&sta_ssid=SerEla&sta_mac=e4%3Ac3%3A2a%3A66%3A17%3Ac8&sta_channel=10&sta_security_mode=3&wep_mode=0&
    # wep_default_key=1&WEPSelect=1&wep_key_1=&wep_key_2=&wep_key_3=&wep_key_4=&cipher=1&passphrase=novamulher01&
    # wlsSlt=radiobutton
    # 0:close 1;wep 2:wpa 3:wpa2 ou AES
    sec_mode = {'NONE': 0,
                'WEP': 1,
                'TKIP': 2,
                'AES': 3
                }
    data = {'wlMode': 1,
            'sta_ssid': wifi_data[0],
            'sta_mac': wifi_data[1],
            'sta_channel': wifi_data[2],
            'sta_security_mode': sec_mode[wifi_data[3]],
            'wep_mode': 0,
            'wep_default_key': 1,
            'WEPSelect': 1,
            'wep_key_1': '',
            'wep_key_2': '',
            'wep_key_3': '',
            'wep_key_4': '',
            'cipher': 1,
            'passphrase': config["wifi_password"],
            'wlsSlt': 'radiobutton'
            }
    # print(data)
    print("As configurações foram atualizadas!")
    r = requests.post(url=urlpost, data=data, auth=(config["http_username"], config["http_password"]))
    # print(r.text)


def router_reboot():
    print("Reiniciando roteador com novas configurações...")
    try:
        requests.get(urlreboot, auth=(config["http_username"], config["http_password"]))
    except ConnectionError as e:
        pass


def ping(host):
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """

    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower() == 'windows' else '-c'

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '1', host]

    return subprocess.call(command) == 0


def reconnect_wifi_reboot():
    if ping(config["router_IP"]):
        print("Procurando " + config["ssid"] + " ...")
        dado = get_wifi_data()
        print(dado)
        upload_wifi_data(dado)
        router_reboot()
        while not ping(config["router_IP"]):
            print("Esperando o roteador ficar online...")
            sleep(5)
        print("Testando se a wifi conectou...")
        if test_wifi_is_conected():
            print("Tudo pronto! :)")
        else:
            print("A conexão com wifi não esta funcionando como o esperado... verifique manualmente...")
    else:
        print("Roteador está offline! :(")


def test_wifi_is_conected():
    return ping(config["wan_IP"])


if __name__ == "__main__":
    if not test_wifi_is_conected():
        reconnect_wifi_reboot()
    else:
        print("Wifi está conectada! :>")
