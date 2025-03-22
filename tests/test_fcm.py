import os
import socket
import unittest

from fcm import parse_args


class TestFCMParserAddServer(unittest.TestCase):
    def test_addserver(self):
        args = ["addserver", "testfrp.net"]
        except_result = {
            "opcode": "addserver",
            "server_pos": "testfrp.net",
            "bind_port": 7000,
            "token": "",
            "name": "testfrp.net",
            "user": socket.gethostname() + "." + os.getlogin(),
            "set_default": False,
        }
        output = parse_args(args)
        self.assertEqual(output, except_result)

    def test_addserver_with_options(self):
        args = [
            "addserver",
            "testfrp.net",
            "-p",
            "15678",
            "--token",
            "test_token",
            "--name",
            "test_name",
            "--user",
            "test_name",
            "--set-default",
        ]
        except_result = {
            "opcode": "addserver",
            "server_pos": "testfrp.net",
            "bind_port": 15678,
            "token": "test_token",
            "name": "test_name",
            "user": "test_name",
            "set_default": True,
        }
        output = parse_args(args)
        self.assertEqual(output, except_result)


class TestFCMParserAddTunnel(unittest.TestCase):
    def test_addtunnel_1(self):
        args = ["addtunnel", "8080"]
        except_result = {
            "opcode": "addtunnel",
            "local_ip": "127.0.0.1",
            "local_port": 8080,
            "remote_port": 8080,
            "remote_name": "default",
            "protocol": "tcp",
            "name": "",
        }
        output = parse_args(args)
        # print(output)
        self.assertEqual(output, except_result)

    def test_addtunnel_1_with_options(self):
        args = [
            "addtunnel",
            "8080",
            "-p",
            "udp",
            "-r",
            "test_server",
            "-n",
            "test_tunnel",
        ]
        except_result = {
            "opcode": "addtunnel",
            "local_ip": "127.0.0.1",
            "local_port": 8080,
            "remote_port": 8080,
            "remote_name": "test_server",
            "protocol": "udp",
            "name": "test_tunnel",
        }
        output = parse_args(args)
        self.assertEqual(output, except_result)

    def test_addtunnel_2(self):
        args = ["addtunnel", "8080", "8081"]
        except_result = {
            "opcode": "addtunnel",
            "local_ip": "127.0.0.1",
            "local_port": 8080,
            "remote_port": 8081,
            "remote_name": "default",
            "protocol": "tcp",
            "name": "",
        }
        output = parse_args(args)
        self.assertEqual(output, except_result)
    
    def test_addtunnel_2_with_options(self):
        args = [
            "addtunnel",
            "8080",
            "8081",
            "-p",
            "udp",
            "-r",
            "test_server",
            "-n",
            "test_tunnel",
        ]
        except_result = {
            "opcode": "addtunnel",
            "local_ip": "127.0.0.1",
            "local_port": 8080,
            "remote_port": 8081,
            "remote_name": "test_server",
            "protocol": "udp",
            "name": "test_tunnel",
        }
        output=parse_args(args)
        self.assertEqual(output, except_result)

    def test_addtunnel_3(self):
        args = ["addtunnel", "192.168.2.123:8080"]
        except_result = {
            "opcode": "addtunnel",
            "local_ip": "192.168.2.123",
            "local_port": 8080,
            "remote_port": 8080,
            "remote_name": "default",
            "protocol": "tcp",
            "name": "",
        }
        output = parse_args(args)
        # print(output)
        self.assertEqual(output, except_result)
        
    def test_addtunnel_3_with_options(self):
        args = [
            "addtunnel",
            "192.168.2.123:8080",
            "-p",
            "udp",
            "-r",
            "test_server",
            "-n",
            "test_tunnel",
        ]
        except_result = {
            "opcode": "addtunnel",
            "local_ip": "192.168.2.123",
            "local_port": 8080,
            "remote_port": 8080,
            "remote_name": "test_server",
            "protocol": "udp",
            "name": "test_tunnel",
        }

    def test_addtunnel_4(self):
        args = ["addtunnel", "192.168.2.123:8080", "8081"]
        except_result = {
            "opcode": "addtunnel",
            "local_ip": "192.168.2.123",
            "local_port": 8080,
            "remote_port": 8081,
            "remote_name": "default",
            "protocol": "tcp",
            "name": "",
        }
        output = parse_args(args)
        self.assertEqual(output, except_result)
    
    def test_addtunnel_4_with_options(self):
        args = [
            "addtunnel",
            "192.168.2.123:8080",
            "8081",
            "-p",
            "udp",
            "-r",
            "test_server",
            "-n",
            "test_tunnel",
        ]
        except_result = {
            "opcode": "addtunnel",
            "local_ip": "192.168.2.123",
            "local_port": 8080,
            "remote_port": 8081,
            "remote_name": "test_server",
            "protocol": "udp",
            "name": "test_tunnel",
        }
        output=parse_args(args)
        self.assertEqual(output, except_result)


if __name__ == "__main__":
    unittest.main()
