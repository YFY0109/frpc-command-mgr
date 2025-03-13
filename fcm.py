import os
import re
import socket


class Verifier:
    @staticmethod
    def verify_ip(ip: str) -> bool:
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip):
            return True
        return False

    @staticmethod
    def verify_domain(domain: str) -> bool:
        if re.match(
            r"[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+(:[0-9]{1,5})?[-a-zA-Z0-9()@:%_\+\.~#?&//=]*$",
            domain,
        ):
            return True
        return False

    @staticmethod
    def verify_port(port: str) -> bool:
        port = int(port)
        if 1 <= port <= 65535:
            return True
        return False

    @staticmethod
    def verify_pos(server_pos: str) -> bool:
        if Verifier.verify_ip(server_pos):
            return True
        if Verifier.verify_domain(server_pos):
            return True
        return False

    @staticmethod
    def verify_ip_with_port(ip_with_port: str) -> bool:
        try:
            ip, port = ip_with_port.split(":")
        except ValueError:
            return False
        if Verifier.verify_ip(ip) and Verifier.verify_port(port):
            return True
        return False


class InterfaceOP:
    @staticmethod
    def addserver() -> dict:
        pass

    @staticmethod
    def addtunnel() -> dict:
        pass

    @staticmethod
    def mossfrp(code: str) -> dict:
        pass


def mossfrp_code_parser(code: str) -> dict:
    pass


def parse_args(args: list):
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
            if Verifier.verify_pos(args[1]):
                if Verifier.verify_port(args[2]):
                    pre_args_count = 3
                    result.update({"local_port": args[1], "remote_port": args[2]})
                elif not Verifier.verify_port(args[2]):
                    pre_args_count = 2
                    result.update(
                        {
                            "local_port": args[1],
                            "remote_port": args[1],
                        }
                    )
            elif Verifier.verify_ip_with_port(args[1]):
                if Verifier.verify_port(args[2]):
                    pre_args_count = 3
                    result.update(
                        {"local_port": args[1].split(":")[1], "remote_port": args[2]}
                    )
                elif not Verifier.verify_port(args[2]):
                    pre_args_count = 2
                    result.update(
                        {
                            "local_port": args[1].split(":")[1],
                            "remote_port": args[1].split(":")[1],
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
        "--set_default",
    ]
    print(parse_args(main_args))
