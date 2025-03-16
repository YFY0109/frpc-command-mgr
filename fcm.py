import os
import re
import socket


class Verifier:
    """
    所有验证器的逻辑分类（无实际功能）
    """
    @staticmethod
    def verify_ip(ip: str) -> bool:
        """
        校验传入的ip字符串是否符合规范
        :param ip: ip字符串
        :return: 是否符合规范
        """
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip):
            return True
        return False

    @staticmethod
    def verify_domain(domain: str) -> bool:
        """
        校验传入的域名字符串是否符合规范
        :param domain: 域名字符串
        :return: 是否符合规范
        """
        if re.match(
            r"[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+(:[0-9]{1,5})?[-a-zA-Z0-9()@:%_\+\.~#?&//=]*$",
            domain,
        ):
            return True
        return False

    @staticmethod
    def verify_port(port: str) -> bool:
        """
        校验传入的端口字符串是否符合规范
        :param port: 端口字符串
        :return: 是否符合规范
        """
        try:
            port = int(port)
        except ValueError:
            return False
        if 1 <= port <= 65535:
            return True
        return False

    @staticmethod
    def verify_pos(server_pos: str) -> bool:
        """
        校验传入的服务器地址（ip或域名）是否符合规范
        :param server_pos: 服务器地址
        :return: 是否符合规范
        """
        if Verifier.verify_ip(server_pos):
            return True
        if Verifier.verify_domain(server_pos):
            return True
        return False

    @staticmethod
    def verify_ip_with_port(ip_with_port: str) -> bool:
        """
        校验传入的带有端口的ip地址是否符合标准（形似"192.168.2.2:12345"）
        :param ip_with_port: 带有端口的ip地址字符串
        :return: 是否符合规范
        """
        try:
            ip, port = ip_with_port.split(":")
        except ValueError:
            return False
        if Verifier.verify_ip(ip) and Verifier.verify_port(port):
            return True
        return False


class InterfaceOP:
    """
    所有通过CLI交互式获取数据函数的逻辑分类
    """
    @staticmethod
    def addserver() -> dict:
        """
        addserver的交互式输入
        :return: 结果
        """
        pass

    @staticmethod
    def addtunnel() -> dict:
        """
        addtunnel的交互式输入
        :return: 结果
        """
        pass

    @staticmethod
    def mossfrp(code: str) -> dict:
        """
        mossfrp的交互式输入
        :param code: mossfrp穿透码（形似"3qd217893567136012195"）
        :return: 结果
        """
        pass


def mossfrp_code_parser(code: str) -> dict:
    """
    解析mossfrp穿透码的逻辑，参考"https://github.com/MossFrp/MossFrpClient-WindowsBat/blob/main/Build/MossFrp_Client.bat"
    :param code: mossfrp穿透码
    :return: 解码结果
    """
    pass


def parse_args(args: list[str]) -> dict:
    """
    fcm主程序解析传入参数主函数
    :param args: 传入参数，一般通过sys.argv[1:]获取
    :return: 向daemon进程发送的json数据字典
    """
    if len(args) == 0:
        raise ValueError("No opcode provided")
    if args[0] == "addserver" or args[0] == "as":
        result = {"opcode": "addserver"}
        if len(args) == 1:
            result.update(InterfaceOP.addserver())
            return result
        else:
            if Verifier.verify_pos(args[1]):
                result.update({"server_pos": args[1]})
            else:
                raise ValueError("Invalid server position")
            result.update(
                {
                    "bind_port": 7000,
                    "token": "",
                    "name": result["server_pos"],
                    "user": socket.gethostname() + "." + os.getlogin(),
                    "set_default": False,
                }
            )
            args = args[2:]
            while not len(args) == 0:
                this_option_is_valid = False
                if args[0] == "-p" or args[0] == "--port" or args[0] == "--bind-port":
                    result["bind_port"] = int(args[1])
                    args = args[2:]
                    this_option_is_valid = True
                if args[0] == "-t" or args[0] == "--token":
                    result["token"] = args[1]
                    args = args[2:]
                    this_option_is_valid = True
                if args[0] == "-n" or args[0] == "--name":
                    result["name"] = args[1]
                    args = args[2:]
                    this_option_is_valid = True
                if args[0] == "-u" or args[0] == "--user":
                    result["user"] = args[1]
                    args = args[2:]
                    this_option_is_valid = True
                if args[0] == "--set-default":
                    result["set_default"] = True
                    args = args[1:]
                    this_option_is_valid = True
                if not this_option_is_valid:
                    raise ValueError("Invalid option: " + args[0])
            return result
    if args[0] == "addtunnel" or args[0] == "at":
        pre_args_count = 0
        result = {"opcode": "addtunnel"}
        if len(args) == 1:
            result.update(InterfaceOP.addtunnel())
            return result
        else:
            if Verifier.verify_port(args[1]):
                if len(args) > 2:
                    if Verifier.verify_port(args[2]):
                        pre_args_count = 3
                        result.update(
                            {
                                "local_ip": "127.0.0.1",
                                "local_port": int(args[1]),
                                "remote_port": int(args[2]),
                            }
                        )
                    else:
                        pre_args_count = 2
                        result.update(
                            {
                                "local_ip": "127.0.0.1",
                                "local_port": int(args[1]),
                                "remote_port": int(args[1]),
                            }
                        )
                else:
                    pre_args_count = 2
                    result.update(
                        {
                            "local_port": int(args[1]),
                            "remote_port": int(args[1]),
                            "local_ip": "127.0.0.1",
                        }
                    )
            elif Verifier.verify_ip_with_port(args[1]):
                if len(args) > 2:
                    if Verifier.verify_port(args[2]):
                        pre_args_count = 3
                        result.update(
                            {
                                "local_ip": args[1].split(":")[0],
                                "local_port": int(args[1].split(":")[1]),
                                "remote_port": int(args[2]),
                            }
                        )
                    elif not Verifier.verify_port(args[2]):
                        pre_args_count = 2
                        result.update(
                            {
                                "local_ip": args[1].split(":")[0],
                                "local_port": int(args[1].split(":")[1]),
                                "remote_port": int(args[1].split(":")[1]),
                            }
                        )
                else:
                    pre_args_count = 2
                    result.update(
                        {
                            "local_ip": args[1].split(":")[0],
                            "local_port": int(args[1].split(":")[1]),
                            "remote_port": int(args[1].split(":")[1]),
                        }
                    )
            else:
                raise ValueError("Invalid local or remote position")
            result.update({"remote_name": "default", "protocol": "tcp", "name": ""})
            args = args[pre_args_count:]
            while not len(args) == 0:
                this_option_is_valid = False
                if (
                    args[0] == "-r"
                    or args[0] == "--remote"
                    or args[0] == "--remote-name"
                ):
                    result["remote_name"] = args[1]
                    args = args[2:]
                    this_option_is_valid = True
                if args[0] == "-p" or args[0] == "--protocol":
                    result["protocol"] = args[1]
                    args = args[2:]
                    this_option_is_valid = True
                if args[0] == "-n" or args[0] == "--name":
                    result["name"] = args[1]
                    args = args[2:]
                    this_option_is_valid = True
                if not this_option_is_valid:
                    raise ValueError("Invalid option: " + args[0])
            return result
    if args[0] == "mossfrp" or args[0] == "mf":
        pre_args_count = 0
        result = {"opcode": "mossfrp"}
        if len(args) == 1:
            raise ValueError("No mossfrp code provided")
        if len(args) == 2:
            result.update({"token": args[1]})
            result.update(InterfaceOP.mossfrp(args[1]))
            return result
        if Verifier.verify_port(args[2]):
            result.update(
                {
                    "local_port": args[2],
                    "bind_port": mossfrp_code_parser(args[1])["bind_port"],
                    "token": args[1],
                    "protocol": "tcp",
                }
            )
            if 1 <= int(args[3]) <= 10:
                pre_args_count = 4
                result.update(
                    {
                        "remote_port": mossfrp_code_parser(args[1])["remote_ports"][
                            int(args[3]) - 1
                        ]
                    }
                )
            else:
                pre_args_count = 3
                result.update(
                    {"remote_port": mossfrp_code_parser(args[1])["remote_ports"][0]}
                )
        elif Verifier.verify_ip_with_port(args[2]):
            result.update(
                {
                    "local_port": args[2].split(":")[1],
                    "bind_port": mossfrp_code_parser(args[1])["bind_port"],
                    "token": args[1],
                    "protocol": "tcp",
                }
            )
            if 1 <= int(args[3]) <= 10:
                pre_args_count = 4
                result.update(
                    {
                        "remote_port": mossfrp_code_parser(args[1])["remote_ports"][
                            int(args[3]) - 1
                        ]
                    }
                )
            else:
                pre_args_count = 3
                result.update(
                    {"remote_port": mossfrp_code_parser(args[1])["remote_ports"][0]}
                )
        result.update({"remote_name": "default", "name": ""})
        args = args[pre_args_count:]
        while not len(args) == 0:
            this_option_is_valid = False
            if args[0] == "-p" or args[0] == "--protocol":
                result["protocol"] = args[1]
                args = args[2:]
                this_option_is_valid = True
            if args[0] == "-n" or args[0] == "--name":
                result["name"] = args[1]
                args = args[2:]
                this_option_is_valid = True
            if not this_option_is_valid:
                raise ValueError("Invalid option: " + args[0])
        return result
    if args[0] == "listservers" or args[0] == "ls":
        result = {"opcode": "listservers"}
        return result
    if args[0] == "listtunnels" or args[0] == "lt":
        result = {"opcode": "listtunnels"}
        return result
    if args[0] == "delserver" or args[0] == "ds":
        result = {"opcode": "delserver"}
        if len(args) == 1:
            raise ValueError("No server name provided")
        result.update({"name": args[1]})
        return result
    if args[0] == "deltunnel" or args[0] == "dt":
        result = {"opcode": "deltunnel"}
        if len(args) == 1:
            raise ValueError("No tunnel name provided")
        result.update({"name": args[1]})
        return result


if __name__ == "__main__":
    # main_args = sys.argv[1:]
    main_args = [
        "addserver",
        "sh5.mossfrp.cn",
        "-p",
        "15366",
        "-u",
        "123",
        "-n",
        "test_server",
        "-t",
        "test_token",
        "--set-default",
    ]
    print(parse_args(main_args))
