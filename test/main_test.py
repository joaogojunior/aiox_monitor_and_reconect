import mock
import unittest
import requests
import main


class TestMain(unittest.TestCase):

    def test_if_urlwds_exists(self):
        self.assertIsInstance(main.urlwds, str)

    def test_if_config_dict_exists(self):
        self.assertIsInstance(main.config, dict)

    def test_cannot_load_missing_config(self):
        with self.assertRaises(IOError) as context:
            main.load_json_config_dict(filename='arquivo_inexistente')
        self.assertEqual('Arquivo de configuração não existe!', str(context.exception))

    def test_can_load_config(self):
        read_data = '{"wan_IP": "xxx.xxx.xxx.xxx", "router_IP": "zzz.zzz.zzz.zzz", "http_username": "admin",\
         "http_password": "admin", "ssid": "ssid1", "wifi_password": "changeme"}'
        d = {"wan_IP": "xxx.xxx.xxx.xxx", "router_IP": "zzz.zzz.zzz.zzz", "http_username": "admin",
             "http_password": "admin", "ssid": "ssid1", "wifi_password": "changeme"}
        mock_open = mock.mock_open(read_data=read_data)
        with mock.patch('builtins.open', mock_open):
            self.assertEqual(main.load_json_config_dict(), d)

    def test_if_config_can_be_updated(self):
        d = {"wan_IP": "xxx.xxx.xxx.xxx", "router_IP": "zzz.zzz.zzz.zzz", "http_username": "admin",
             "http_password": "admin", "ssid": "ssid1", "wifi_password": "changeme"}
        main.set_config(d)
        self.assertEqual(main.config, d)

    def test_if_urlwds_can_be_updated(self):
        main.set_urlwds("zzz.zzz.zzz.zzz")
        self.assertEqual(main.urlwds, "http://zzz.zzz.zzz.zzz/goform/WDSScan")

    def test_if_urlpost_exists(self):
        self.assertIsInstance(main.urlpost, str)

    def test_if_urlpost_can_be_updated(self):
        main.set_urlpost("zzz.zzz.zzz.zzz")
        self.assertEqual(main.urlpost, "http://zzz.zzz.zzz.zzz/goform/wirelessMode")

    def test_if_urlreboot_exists(self):
        self.assertIsInstance(main.urlreboot, str)

    def test_if_urlreboot_can_be_updated(self):
        main.set_urlreboot("zzz.zzz.zzz.zzz")
        self.assertEqual(main.urlreboot, "http://zzz.zzz.zzz.zzz/goform/SysToolReboot")

    @mock.patch('main.requests.get')
    def test_cannot_connect_to_router_and_exit_with_error(self, mock_http_get):
        mock_http_get.side_effect = requests.exceptions.ConnectionError("Max retries exceeded with url: teste")
        with mock.patch('main.sys.exit') as mock_exit:
            main.query_aps()
            self.assertTrue(mock_exit.called)

    @mock.patch('main.requests.get')
    def test_can_get_wds_response_from_router(self, mock_http_get):
        s = [['SSID1', 'ab:bc:cd:de:ef:ff', '1', 'AES', '100'], ['SSID2', '00:11:22:33:44:55', '11', 'TKIP', '34'],
             ['SSID3', 'ff:fe:ed:dc:cb:ba', '13', 'NONE', '0']]
        # simula comportamento do roteador: primeiro responde com 401 e apos isso responde com um exception customizado
        mock_http_get.side_effect = ["<Response [401]>", requests.exceptions.ConnectionError(
            "('Connection aborted.', BadStatusLine('SSID1,ab:bc:cd:de:ef:ff,1,AES  ,100  ;SSID2,00:11:22:33:44:55,11,"
            "TKIP ,34   ;SSID3,ff:fe:ed:dc:cb:ba,13,NONE ,0    \r\n'))")]
        with mock.patch('main.sys.exit') as mock_exit:
            dados = main.query_aps()
            # testa se nao atingiu o exit e se dados retornou corretamente
            self.assertFalse(mock_exit.called)
            self.assertEqual(dados, s)

    @mock.patch('main.requests.get')
    def test_can_get_filtered_wds_response(self, mock_http_get):
        d = {"wan_IP": "xxx.xxx.xxx.xxx", "router_IP": "zzz.zzz.zzz.zzz", "http_username": "admin",
             "http_password": "admin", "ssid": "SSID1", "wifi_password": "changeme"}
        main.set_config(d)
        s = ['SSID1', 'ab:bc:cd:de:ef:ff', '1', 'AES', '100']
        mock_http_get.side_effect = ["<Response [401]>", requests.exceptions.ConnectionError(
            "('Connection aborted.', BadStatusLine('SSID1,ab:bc:cd:de:ef:ff,1,AES  ,100  ;SSID2,00:11:22:33:44:55,11,"
            "TKIP ,34   ;SSID3,ff:fe:ed:dc:cb:ba,13,NONE ,0    \r\n'))")]
        dados = main.get_wifi_data()
        self.assertEqual(dados, s)

    @mock.patch('main.requests.post')
    def test_if_can_post_config_to_router(self, mock_http_post):
        # postdata - wlMode=1&sta_ssid=ssid1&sta_mac=ab%3Abc%3Acd%3Ade%3Aef%3Aff&sta_channel=11&sta_security_mode=3&
        # wep_mode=0&wep_default_key=1&WEPSelect=1&wep_key_1=&wep_key_2=&wep_key_3=&wep_key_4=&cipher=1&
        # passphrase=changeme&wlsSlt=radiobutton
        d = {"wan_IP": "xxx.xxx.xxx.xxx", "router_IP": "zzz.zzz.zzz.zzz", "http_username": "admin",
             "http_password": "admin", "ssid": "SSID1", "wifi_password": "changeme"}
        main.set_config(d)
        main.set_urlpost("zzz.zzz.zzz.zzz")
        wifi_data = ['SSID1', 'ab:bc:cd:de:ef:ff', '1', 'AES', '100']
        mock_http_post.status_code = 200
        mock_http_post.return_value = {}
        main.upload_wifi_data(wifi_data)
        r = {'url': 'http://zzz.zzz.zzz.zzz/goform/wirelessMode', 'data': {'wlMode': 1, 'sta_ssid': 'SSID1',
                                                                           'sta_mac': 'ab:bc:cd:de:ef:ff',
                                                                           'sta_channel': 1, 'sta_security_mode': 3,
                                                                           'wep_mode': 0, 'wep_default_key': 1,
                                                                           'WEPSelect': 1, 'wep_key_1': '',
                                                                           'wep_key_2': '', 'wep_key_3': '',
                                                                           'wep_key_4': '', 'cipher': 1,
                                                                           'passphrase': 'changeme',
                                                                           'wlsSlt': 'radiobutton'},
             'auth': ('admin', 'admin')
             }
        self.assertEqual(mock_http_post.call_args.kwargs, r)

    @mock.patch('main.requests.post')
    def test_cannot_post_to_router_network_error(self, mock_http_post):
        mock_http_post.side_effect = requests.exceptions.ConnectionError("Sem internet :(")
        wifi_data = ['SSID1', 'ab:bc:cd:de:ef:ff', '1', 'AES', '100']
        with mock.patch('main.sys.exit') as mock_exit:
            main.upload_wifi_data(wifi_data)
            self.assertTrue(mock_exit.called)

    @mock.patch('main.requests.get')
    def test_if_router_reboot_request_works(self, mock_http_get):
        main.set_urlreboot("zzz.zzz.zzz.zzz")
        r = {'auth': ('admin', 'admin')}
        mock_http_get.side_effect = requests.exceptions.ConnectionError()
        # router reinicia antes de responder ao request
        main.router_reboot()
        self.assertEqual(mock_http_get.call_args.kwargs, r)
        self.assertEqual(mock_http_get.call_args.args, ("http://zzz.zzz.zzz.zzz/goform/SysToolReboot",))

    @mock.patch('main.platform.system')
    @mock.patch('main.subprocess.call')
    def test_if_ping_on_windows_with_dead_host_returns_false(self, mock_subprocess_call, mock_platform_system):
        mock_platform_system.return_value = "windows"
        mock_subprocess_call.return_value = 1
        r = main.ping("xxx.xxx.xxx.xxx")
        self.assertEqual(mock_subprocess_call.call_args.args, (["ping", "-n", "1", "xxx.xxx.xxx.xxx"],))
        self.assertFalse(r)

    @mock.patch('main.platform.system')
    @mock.patch('main.subprocess.call')
    def test_if_ping_on_windows_with_alive_host_returns_true(self, mock_subprocess_call, mock_platform_system):
        mock_platform_system.return_value = "windows"
        mock_subprocess_call.return_value = 0
        r = main.ping("xxx.xxx.xxx.xxx")
        self.assertEqual(mock_subprocess_call.call_args.args, (["ping", "-n", "1", "xxx.xxx.xxx.xxx"],))
        self.assertTrue(r)

    @mock.patch('main.platform.system')
    @mock.patch('main.subprocess.call')
    def test_if_ping_on_linux_with_dead_host_returns_false(self, mock_subprocess_call, mock_platform_system):
        mock_platform_system.return_value = "linux"
        mock_subprocess_call.return_value = 1
        r = main.ping("xxx.xxx.xxx.xxx")
        self.assertEqual(mock_subprocess_call.call_args.args, (["ping", "-c", "1", "xxx.xxx.xxx.xxx"],))
        self.assertFalse(r)

    @mock.patch('main.platform.system')
    @mock.patch('main.subprocess.call')
    def test_if_ping_on_linux_with_alive_host_returns_true(self, mock_subprocess_call, mock_platform_system):
        mock_platform_system.return_value = "linux"
        mock_subprocess_call.return_value = 0
        r = main.ping("xxx.xxx.xxx.xxx")
        self.assertEqual(mock_subprocess_call.call_args.args, (["ping", "-c", "1", "xxx.xxx.xxx.xxx"],))
        self.assertTrue(r)

    @mock.patch('main.platform.system')
    @mock.patch('main.subprocess.call')
    def test_if_test_wifi_is_connected_returns_true(self, mock_subprocess_call, mock_platform_system):
        d = {"wan_IP": "xxx.xxx.xxx.xxx", "router_IP": "zzz.zzz.zzz.zzz", "http_username": "admin",
             "http_password": "admin", "ssid": "SSID1", "wifi_password": "changeme"}
        main.set_config(d)
        mock_platform_system.return_value = "windows"
        mock_subprocess_call.return_value = 0
        r = main.test_wifi_is_conected()
        self.assertEqual(mock_subprocess_call.call_args.args, (["ping", "-n", "1", "xxx.xxx.xxx.xxx"],))
        self.assertTrue(r)

    @mock.patch('main.platform.system')
    @mock.patch('main.subprocess.call')
    def test_if_test_wifi_is_connected_returns_false(self, mock_subprocess_call, mock_platform_system):
        d = {"wan_IP": "xxx.xxx.xxx.xxx", "router_IP": "zzz.zzz.zzz.zzz", "http_username": "admin",
             "http_password": "admin", "ssid": "SSID1", "wifi_password": "changeme"}
        main.set_config(d)
        mock_platform_system.return_value = "windows"
        mock_subprocess_call.return_value = 1
        r = main.test_wifi_is_conected()
        self.assertEqual(mock_subprocess_call.call_args.args, (["ping", "-n", "1", "xxx.xxx.xxx.xxx"],))
        self.assertFalse(r)

    @mock.patch('main.platform.system')
    @mock.patch('main.subprocess.call')
    @mock.patch('builtins.print')
    def test_if_test_reconnect_reboot_prints_offline_when_cannot_reach_router(self, mock_print, mock_subprocess_call,
                                                                              mock_platform_system):
        mock_platform_system.return_value = "windows"
        mock_subprocess_call.return_value = 1
        main.test_reconnect_reboot()
        mock_print.assert_called_with("Roteador está offline! :(")

    @mock.patch('builtins.print')
    @mock.patch('main.requests.post')
    @mock.patch('main.requests.get')
    @mock.patch('main.platform.system')
    @mock.patch('main.subprocess.call')
    def test_if_test_reconnect_reboot_prints_manualmente_when_cannot_recover_router(self, mock_subprocess_call,
                                                                                    mock_platform_system,
                                                                                    mock_http_get,
                                                                                    mock_http_post,
                                                                                    mock_print
                                                                                    ):
        d = {"wan_IP": "xxx.xxx.xxx.xxx", "router_IP": "zzz.zzz.zzz.zzz", "http_username": "admin",
             "http_password": "admin", "ssid": "SSID1", "wifi_password": "changeme"}
        main.set_config(d)
        main.set_urlpost("zzz.zzz.zzz.zzz")
        mock_http_get.side_effect = ["<Response [401]>", requests.exceptions.ConnectionError(
            "('Connection aborted.', BadStatusLine('SSID1,ab:bc:cd:de:ef:ff,1,AES  ,100  ;SSID2,00:11:22:33:44:55,11,"
            "TKIP ,34   ;SSID3,ff:fe:ed:dc:cb:ba,13,NONE ,0    \r\n'))"), requests.exceptions.ConnectionError()]
        r = {'url': 'http://zzz.zzz.zzz.zzz/goform/wirelessMode', 'data': {'wlMode': 1, 'sta_ssid': 'SSID1',
                                                                           'sta_mac': 'ab:bc:cd:de:ef:ff',
                                                                           'sta_channel': 1, 'sta_security_mode': 3,
                                                                           'wep_mode': 0, 'wep_default_key': 1,
                                                                           'WEPSelect': 1, 'wep_key_1': '',
                                                                           'wep_key_2': '', 'wep_key_3': '',
                                                                           'wep_key_4': '', 'cipher': 1,
                                                                           'passphrase': 'changeme',
                                                                           'wlsSlt': 'radiobutton'},
             'auth': ('admin', 'admin')
             }
        mock_http_post.status_code = 200
        mock_http_post.return_value = {}
        mock_platform_system.return_value = "windows"
        mock_subprocess_call.side_effect = [0, 1, 0, 1]
        with mock.patch('main.sleep') as mock_sleep:
            main.test_reconnect_reboot()
            # testando se o post funcionou...
            self.assertEqual(mock_http_post.call_args.kwargs, r)
            # testando se o print foi com manualmente
            mock_print.assert_called_with("A conexão com wifi não esta funcionando como o esperado... verifique "
                                          "manualmente...")

    @mock.patch('builtins.print')
    @mock.patch('main.requests.post')
    @mock.patch('main.requests.get')
    @mock.patch('main.platform.system')
    @mock.patch('main.subprocess.call')
    def test_if_test_reconnect_reboot_prints_ok_when_recover_router(self, mock_subprocess_call,
                                                                    mock_platform_system,
                                                                    mock_http_get,
                                                                    mock_http_post,
                                                                    mock_print
                                                                    ):
        d = {"wan_IP": "xxx.xxx.xxx.xxx", "router_IP": "zzz.zzz.zzz.zzz", "http_username": "admin",
             "http_password": "admin", "ssid": "SSID1", "wifi_password": "changeme"}
        main.set_config(d)
        main.set_urlpost("zzz.zzz.zzz.zzz")
        mock_http_get.side_effect = ["<Response [401]>", requests.exceptions.ConnectionError(
            "('Connection aborted.', BadStatusLine('SSID1,ab:bc:cd:de:ef:ff,1,AES  ,100  ;SSID2,00:11:22:33:44:55,11,"
            "TKIP ,34   ;SSID3,ff:fe:ed:dc:cb:ba,13,NONE ,0    \r\n'))"), requests.exceptions.ConnectionError()]
        r = {'url': 'http://zzz.zzz.zzz.zzz/goform/wirelessMode', 'data': {'wlMode': 1, 'sta_ssid': 'SSID1',
                                                                           'sta_mac': 'ab:bc:cd:de:ef:ff',
                                                                           'sta_channel': 1, 'sta_security_mode': 3,
                                                                           'wep_mode': 0, 'wep_default_key': 1,
                                                                           'WEPSelect': 1, 'wep_key_1': '',
                                                                           'wep_key_2': '', 'wep_key_3': '',
                                                                           'wep_key_4': '', 'cipher': 1,
                                                                           'passphrase': 'changeme',
                                                                           'wlsSlt': 'radiobutton'},
             'auth': ('admin', 'admin')
             }
        mock_http_post.status_code = 200
        mock_http_post.return_value = {}
        mock_platform_system.return_value = "windows"
        mock_subprocess_call.side_effect = [0, 1, 0, 0]
        with mock.patch('main.sleep') as mock_sleep:
            main.test_reconnect_reboot()
            # testando se o post funcionou...
            self.assertEqual(mock_http_post.call_args.kwargs, r)
            # testando se o print foi com ok!
            mock_print.assert_called_with("Tudo ok! :)")
