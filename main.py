import sys
import json
from time import sleep
import requests
import platform  # For getting the operating system name
import subprocess  # For executing a shell command

# declara variaveis globais
config = dict()
urlwds = ""
urlpost = ""
urlreboot = ""


def set_urlwds(ip):
    global urlwds
    urlwds = "http://" + ip + "/goform/WDSScan"


def set_urlpost(ip):
    global urlpost
    urlpost = "http://" + ip + "/goform/wirelessMode"


def set_urlreboot(ip):
    global urlreboot
    urlreboot = "http://" + ip + "/goform/SysToolReboot"


def set_config(conf):
    global config
    config.update(conf)


# carrega configuração do arquivo
def load_json_config_dict(filename='config.json'):
    try:
        f = open(filename)
        return json.load(f)
    except IOError:
        raise IOError('Arquivo de configuração não existe!')


# funcao que faz um request pra url do roteador e retorna lista de APs no formato [ssid, mac, canal,
# encriptação, sinal]
def query_aps():
    global config
    r = "<Response [401]>"
    # o loop é necessário pois o roteador aparentemente responde 401 na primeira tentativa por algum motivo.
    while str(r) == "<Response [401]>":
        try:
            # na primeira vez as vezes retorna "<Response [401]>" e executa sem erros, se isso ocorrer o loop é
            # executado novamente.
            # se falhar com http 401 r recebe o valor "<Response [401]>" como resultado
            r = str(requests.get(urlwds, auth=(config["http_username"], config["http_password"])))
            if r == "<Response [401]>":
                print("Recebeu <Response [401]> do roteador... tentando novamente...")
        except requests.exceptions.ConnectionError as ce:
            # garante que o loop so seria executado se a resposta fosse "<Response [401]>", o que não houve.
            r = str(ce)
            # se chegou aqui, das duas uma: ou ja temos a resposta em r ou não foi possivel se conectar ao roteador
            # o que tambem gera um ConnectionError, mas nesse caso em r é exposto a seguinte frase "Max retries exceeded
            # with url:", usaremos isso para diferenciar esses dois casos.
            if "Max retries exceeded with url:" in r:
                # nao foi possivel se conectar ao servidor, avisa e sai.
                print("Erro não foi possivel se conectar ao roteador... por favor verifique se o ip esta correto.")
                sys.exit(1)
            # enfim, se o request nao falha com 401 o roteador responde mas por alguma não conformidade com o protocolo
            # http a resposta acaba causando uma exceção ConnectionError como vimos, felizmente a resposta que o
            # roteador forneceu é exposta tornando possível capturar o erro e extrair a resposta a partir da variavel r.
    # r = "('Connection aborted.', BadStatusLine('SSID1,ab:bc:cd:de:ef:ff,1,AES  ,100  ;
    # SSID2,00:11:22:33:44:55,11,TKIP ,34   ;SSID3,ff:fe:ed:dc:cb:ba,13,NONE ,0    \r\n'))"
    # remove a porção inicial ate o segundo parentesis como tambem os parentesis e caracteres de escape ao final da
    # string, fazendo uma conversão para lista separando no ";"
    lista_crua = r[39:-6].split(";")
    # print(lista_crua)
    # quebra a lista em uma nova lista de listas, com todos os caracteres de espaco ao fim de cada item removidos
    saida = list(map(lambda x: list(map(lambda y: y.strip(), x.split(","))), lista_crua))
    return saida


def get_wifi_data():
    # faz a pesquisa dos APs proximos e filtra os resultados para apenas mostrar do ssid fornecido
    dados = query_aps()
    wifi_data = list(filter(lambda x: x[0] == config["ssid"], dados))[0]
    return wifi_data


def upload_wifi_data(wifi_data):
    # wifi_data = ['ssid1', 'ab:bc:cd:de:ef:ff', '1', 'AES', '100']
    # postdata - wlMode=1&sta_ssid=ssid1&sta_mac=ab%3Abc%3Acd%3Ade%3Aef%3Aff&sta_channel=11&sta_security_mode=3&wep_mode=0&
    # wep_default_key=1&WEPSelect=1&wep_key_1=&wep_key_2=&wep_key_3=&wep_key_4=&cipher=1&passphrase=changeme&
    # wlsSlt=radiobutton
    # codigo de encriptacao e numeros - 0:close 1;wep 2:wpa 3:wpa2
    sec_mode = {'NONE': 0,
                'WEP': 1,
                'TKIP': 2,
                'AES': 3
                }
    data = {'wlMode': 1,
            'sta_ssid': wifi_data[0],
            'sta_mac': wifi_data[1],
            'sta_channel': int(wifi_data[2]),
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
    try:
        # realiza o post para a url do roteador para salvar os dados da rede wifi no modo cliente
        requests.post(url=urlpost, data=data, auth=(config["http_username"], config["http_password"]))
        print("As configurações foram atualizadas!")
    except Exception as e:
        print("Error! Não foi possível salvar as configurações... " + str(e))
        sys.exit(1)


def router_reboot():
    # reinicia roteador. Como o roteador reinicia antes de responder ao GET ocorre uma ConnectionError exception
    # antes do codigo poder prosseguir...
    print("Reiniciando roteador com novas configurações... Isso pode demorar alguns instantes...")
    try:
        requests.get(urlreboot, auth=(config["http_username"], config["http_password"]))
    except requests.exceptions.ConnectionError:
        print("Conexão com o roteador finalizada por timeout...")
        pass


def ping(host):
    # metodo utilizado para monitorar a conectividade de rede, o host tem que responder a pacotes ICMP para isso
    # funcionar.
    # reference - https://stackoverflow.com/questions/2953462/pinging-servers-in-python
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """

    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower() == 'windows' else '-c'

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '1', host]

    return subprocess.call(command) == 0


def test_wifi_is_conected():
    # testa se a rede ip da rede wifi esta acessivel
    return ping(config["wan_IP"])


def test_reconnect_reboot():
    # testa conectividade com o roteador e reenvia os dados corretos coletados do AP para apos o
    # reboot o roteador se conectar na rede wifi corretamente no modo cliente.
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
            print("Tudo ok! :)")
        else:
            print("A conexão com wifi não esta funcionando como o esperado... verifique manualmente...")
    else:
        print("Roteador está offline! :(")


def main():
    global config
    # carrega configuracoes do json
    try:
        config = load_json_config_dict()
    except Exception as e:
        print(str(e) + " - Copie o arquivo config.json.dummy para config.json e ajuste as opções para seu caso.")
        sys.exit(1)
    set_urlwds(config["router_IP"])
    set_urlpost(config["router_IP"])
    set_urlreboot(config["router_IP"])
    # testa a conectividade com a rede wifi, se nao houver conectividade tenta reconectar
    if not test_wifi_is_conected():
        test_reconnect_reboot()
    else:
        print("Wifi está conectada! :>")


if __name__ == "__main__":
    main()
