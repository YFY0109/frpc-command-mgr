"""
frpc命令管理工具 (frpc Command Manager)

这是一个用于管理frp客户端的命令行工具，支持以下功能：
1. 添加/删除/列出frp服务端
2. 添加/删除/列出frp隧道
3. 支持mossfrp穿透码快速创建隧道
4. 支持交互式配置和命令行参数配置

作者: [您的名字]
版本: 1.0.0
"""

import os
import re
import socket
import argparse
import sys


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
        result = {"opcode": "addserver"}
        
        while True:
            server_pos = input("请输入服务器地址(IP或域名): ").strip()
            if Verifier.verify_pos(server_pos):
                result["server_pos"] = server_pos
                break
            print("无效的服务器地址，请重新输入")
        
        while True:
            try:
                bind_port = input("请输入服务端口 [7000]: ").strip()
                if not bind_port:
                    bind_port = "7000"
                if Verifier.verify_port(bind_port):
                    result["bind_port"] = int(bind_port)
                    break
                raise ValueError()
            except ValueError:
                print("无效的端口号，请输入1-65535之间的数字")
        
        token = input("请输入服务端token []: ").strip()
        result["token"] = token

        name = input(f"请输入服务端名称 [{server_pos}]: ").strip()
        result["name"] = name if name else server_pos

        user = input(
            f"请输入用户标识 [{socket.gethostname()}.{os.getlogin()}]: "
        ).strip()
        result["user"] = user if user else f"{socket.gethostname()}.{os.getlogin()}"

        set_default = input("是否设置为默认服务端? (y/N): ").strip().lower()
        result["set_default"] = set_default in ["y", "yes"]

        return result

    @staticmethod
    def addtunnel() -> dict:
        """
        addtunnel的交互式输入
        :return: 结果
        """
        result = {"opcode": "addtunnel"}

        # 获取本地地址和端口
        while True:
            local = input(
                "请输入本地端口或IP:端口 (如: 8080 或 192.168.1.1:8080): "
            ).strip()
            if Verifier.verify_port(local):
                result["local_ip"] = "127.0.0.1"
                result["local_port"] = int(local)
                break
            elif Verifier.verify_ip_with_port(local):
                ip, port = local.split(":")
                result["local_ip"] = ip
                result["local_port"] = int(port)
                break
            print("无效的本地地址或端口，请重新输入")

        # 获取远程端口
        while True:
            remote_port = input(f"请输入远程端口 [{result['local_port']}]: ").strip()
            if not remote_port:
                result["remote_port"] = result["local_port"]
                break
            if Verifier.verify_port(remote_port):
                result["remote_port"] = int(remote_port)
                break
            print("无效的端口号，请输入1-65535之间的数字")
        
        # 获取远程服务器名称
        remote_name = input("请输入远程服务器名称 [default]: ").strip()
        result["remote_name"] = remote_name if remote_name else "default"

        # 获取协议类型
        while True:
            protocol = input("请输入协议类型 (tcp/udp) [tcp]: ").strip().lower()
            if not protocol:
                protocol = "tcp"
            if protocol in ["tcp", "udp"]:
                result["protocol"] = protocol
                break
            print("无效的协议类型，请输入tcp或udp")

        # 获取隧道名称
        name = input("请输入隧道名称 []: ").strip()
        result["name"] = name

        return result

    @staticmethod
    def mossfrp(code: str) -> dict:
        """
        mossfrp的交互式输入
        :param code: mossfrp穿透码
        :return: 包含隧道配置信息的字典
        """
        result = {"opcode": "mossfrp", "token": code}
        
        # 解析穿透码
        mossfrp_info = mossfrp_code_parser(code)
        print("\n穿透码信息:")
        print(f"服务器号: {mossfrp_info['服务器号']}")
        print(f"域名地址: {mossfrp_info['域名地址']}")
        print(f"服务端口: {mossfrp_info['服务端口']}")
        print(f"可用端口范围: {mossfrp_info['开放端口']}\n")

        # 获取本地地址和端口
        while True:
            local = input(
                "请输入本地端口或IP:端口 (如: 8080 或 192.168.1.1:8080): "
            ).strip()
            if Verifier.verify_port(local):
                result["local_ip"] = "127.0.0.1"
                result["local_port"] = int(local)
                break
            elif Verifier.verify_ip_with_port(local):
                ip, port = local.split(":")
                result["local_ip"] = ip
                result["local_port"] = int(port)
                break
            print("无效的本地地址或端口，请重新输入")

        # 获取远程端口号
        remote_ports = [int(p) for p in mossfrp_info["开放端口"].split("-")]
        while True:
            port_num = input(f"请选择远程端口号 (1-10) [1]: ").strip()
            if not port_num:
                result["remote_port"] = remote_ports[0]
                break
            try:
                port_num = int(port_num)
                if 1 <= port_num <= 10:
                    result["remote_port"] = remote_ports[port_num - 1]
                    break
            except ValueError:
                pass
            print("无效的端口号，请输入1-10之间的数字")

        # 获取协议类型
        while True:
            protocol = input("请输入协议类型 (tcp/udp) [tcp]: ").strip().lower()
            if not protocol:
                protocol = "tcp"
            if protocol in ["tcp", "udp"]:
                result["protocol"] = protocol
                break
            print("无效的协议类型，请输入tcp或udp")
        
        # 获取隧道名称
        name = input("请输入隧道名称 []: ").strip()
        result["name"] = name
        
        result.update({
            'bind_port': mossfrp_info['服务端口'],
            'remote_name': 'default'
        })
        
        return result


def mossfrp_code_parser(code: str) -> dict:
    """
    解析mossfrp穿透码的逻辑，参考"https://github.com/MossFrp/MossFrpClient-WindowsBat/blob/main/Build/MossFrp_Client.bat"
    :param code: mossfrp穿透码
    :return: 解码结果字典
    """
    prefix_length = code[0]
    result = {"token": code}

    if prefix_length == "3":
        # 3位前缀解析
        prefix = code[1:4]  # 取第2-4字符
        auth_key = int(code[4:9])  # 取第5-9字符
        port_server = int(code[9:14]) - auth_key  # 取第10-14字符并解密
        number = int(code[14:21]) - auth_key  # 取第15-21字符并解密
    elif prefix_length == "4":
        # 4位前缀解析
        prefix = code[1:5]  # 取第2-5字符
        auth_key = int(code[5:10])  # 取第6-10字符
        port_server = int(code[10:15]) - auth_key  # 取第11-15字符并解密
        number = int(code[15:22]) - auth_key  # 取第16-22字符并解密
    else:
        raise ValueError("无效的穿透码前缀")

    # 计算开放端口范围
    port_start = port_server + 1
    port_end = port_server + 9

    return {
        "服务器号": number,
        "域名地址": f"{prefix}.mossfrp.cn",
        "服务端口": port_server,
        "开放端口": f"{port_start}-{port_end}",
        "链接密钥": code,
    }


def parse_args(args: list) -> dict:
    """
    fcm主程序解析传入参数主函数
    :param args: 传入参数，一般通过sys.argv[1:]获取
    :return: 向daemon进程发送的json数据字典
    """
    parser = argparse.ArgumentParser(description="frpc命令管理工具")
    subparsers = parser.add_subparsers(dest="opcode", help="可用的子命令")

    # 配置各个子命令的参数
    # addserver 子命令
    parser_as = subparsers.add_parser(
        "addserver", aliases=["as"], help="添加一个frps服务端"
    )
    parser_as.add_argument("server_pos", nargs="?", help="服务器地址(IP或域名)")
    parser_as.add_argument(
        "-p", "--bind-port", type=int, default=7000, help="frp服务端绑定端口"
    )
    parser_as.add_argument("-t", "--token", default="", help="frp服务端token")
    parser_as.add_argument("-n", "--name", help="frp服务端名称")
    parser_as.add_argument("-u", "--user", help="frp服务端标识用户名")
    parser_as.add_argument(
        "--set-default", action="store_true", help="设置为默认服务端"
    )

    # addtunnel 子命令
    parser_at = subparsers.add_parser(
        "addtunnel", aliases=["at"], help="添加一个穿透隧道"
    )
    parser_at.add_argument("local", help="本地端口或IP:端口")
    parser_at.add_argument("remote_port", nargs="?", help="远程端口")
    parser_at.add_argument(
        "-r", "--remote-name", default="default", help="远程服务端名称"
    )
    parser_at.add_argument(
        "-p", "--protocol", default="tcp", choices=["tcp", "udp"], help="协议类型"
    )
    parser_at.add_argument("-n", "--name", default="", help="隧道名称")

    # mossfrp 子命令
    parser_mf = subparsers.add_parser(
        "mossfrp", aliases=["mf"], help="使用mossfrp穿透码创建隧道"
    )
    parser_mf.add_argument("code", help="mossfrp穿透码")
    parser_mf.add_argument("local", nargs="?", help="本地端口或IP:端口")
    parser_mf.add_argument(
        "remote_port_num", nargs="?", type=int, help="远程端口号(1-10)"
    )
    parser_mf.add_argument(
        "-p", "--protocol", default="tcp", choices=["tcp", "udp"], help="协议类型"
    )
    parser_mf.add_argument("-n", "--name", default="", help="隧道名称")

    # listservers 子命令
    subparsers.add_parser("listservers", aliases=["ls"], help="列出所有服务端")

    # listtunnels 子命令
    subparsers.add_parser("listtunnels", aliases=["lt"], help="列出所有隧道")

    # delserver 子命令
    parser_ds = subparsers.add_parser(
        "delserver", aliases=["ds"], help="删除一个服务端"
    )
    parser_ds.add_argument("name", help="要删除的服务端名称")

    # deltunnel 子命令
    parser_dt = subparsers.add_parser("deltunnel", aliases=["dt"], help="删除一个隧道")
    parser_dt.add_argument("name", help="要删除的隧道名称")

    # 解析参数
    if not args:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args(args)
    result = {"opcode": args.opcode}

    # 处理各个子命令
    # 处理 addserver 命令
    if args.opcode in ["addserver", "as"]:
        if not args.server_pos:
            return InterfaceOP.addserver()

        if not Verifier.verify_pos(args.server_pos):
            raise ValueError("Invalid server position")

        result.update(
            {
                "server_pos": args.server_pos,
                "bind_port": args.bind_port,
                "token": args.token,
                "name": args.name if args.name else args.server_pos,
                "user": (
                    args.user
                    if args.user
                    else f"{socket.gethostname()}.{os.getlogin()}"
                ),
                "set_default": args.set_default,
            }
        )

    # 处理 addtunnel 命令
    elif args.opcode in ["addtunnel", "at"]:
        if not args.local:
            return InterfaceOP.addtunnel()

        if Verifier.verify_port(args.local):
            local_ip = "127.0.0.1"
            local_port = int(args.local)
        elif Verifier.verify_ip_with_port(args.local):
            local_ip, local_port = args.local.split(":")
            local_port = int(local_port)
        else:
            raise ValueError("Invalid local position")

        remote_port = int(args.remote_port) if args.remote_port else local_port

        result.update(
            {
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "remote_name": args.remote_name,
                "protocol": args.protocol,
                "name": args.name,
            }
        )

    # 处理 mossfrp 命令
    elif args.opcode in ["mossfrp", "mf"]:
        if not args.local:
            result.update({"token": args.code})
            result.update(InterfaceOP.mossfrp(args.code))
            return result

        mossfrp_info = mossfrp_code_parser(args.code)

        if Verifier.verify_port(args.local):
            local_port = args.local
            local_ip = "127.0.0.1"
        elif Verifier.verify_ip_with_port(args.local):
            local_ip, local_port = args.local.split(":")
        else:
            raise ValueError("Invalid local position")

        result.update(
            {
                "local_port": local_port,
                "bind_port": mossfrp_info["服务端口"],
                "token": args.code,
                "protocol": args.protocol,
                "remote_name": "default",
                "name": args.name,
            }
        )

        if args.remote_port_num and 1 <= args.remote_port_num <= 10:
            remote_ports = [int(p) for p in mossfrp_info["开放端口"].split("-")]
            result["remote_port"] = remote_ports[args.remote_port_num - 1]
        else:
            remote_ports = [int(p) for p in mossfrp_info["开放端口"].split("-")]
            result["remote_port"] = remote_ports[0]

    # 处理 listservers 命令
    elif args.opcode in ["listservers", "ls"]:
        pass  # 已经设置了opcode，无需其他操作

    # 处理 listtunnels 命令
    elif args.opcode in ["listtunnels", "lt"]:
        pass  # 已经设置了opcode，无需其他操作

    # 处理 delserver 命令
    elif args.opcode in ["delserver", "ds"]:
        result.update({"name": args.name})

    # 处理 deltunnel 命令
    elif args.opcode in ["deltunnel", "dt"]:
        result.update({"name": args.name})

    return result


if __name__ == "__main__":
    main_args = sys.argv[1:]
    # main_args = [
    #     "addserver",
    #     "sh5.mossfrp.cn",
    #     "-p",
    #     "15366",
    #     "-u",
    #     "123",
    #     "-n",
    #     "test_server",
    #     "-t",
    #     "test_token",
    #     "--set-default",
    # ]
    print(parse_args(main_args))
