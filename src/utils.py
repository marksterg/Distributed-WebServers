#!/python3
from colorama import Fore, Back, Style
from config import *
import socket
import re

def find_avail_port(ip: str = INIT_IP, port: int = INIT_PORT, mode: int = +1) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex((ip, port)) == 0:
            return find_avail_port(port=port + mode * 1)
        else:
            return port


def valid_ip(ip_address: str) -> bool:
    pattern = IP_REGEX
    if re.match(pattern, ip_address):
        return True
    return False

class LogUtil:
    def __init__(self) -> None:
        self.verbose = True

    def set_verbose(self, verbose: bool) -> None:
        self.verbose = verbose

    def get_verbose(self) -> bool:
        return self.verbose

    def INFO(self, *args):
        # if self.get_verbose():
        print(INFO_COLOR + "[INFO] " + RESET_COLOR + " ".join(map(str, args)))

    def SEND(self, *args):
        # if self.get_verbose():
        print(SEND_COLOR + "[SEND] " + RESET_COLOR + " ".join(map(str, args)))

    def RECV(self, *args):
        # if self.get_verbose():
        print(
            RECV_COLOR + "[RECV] " + RESET_COLOR + " ".join(map(str, args))
        )

    def ERROR(self, *args):
        # if self.get_verbose():
        print(
            ERROR_COLOR + "[ERROR] " + RESET_COLOR + " ".join(map(str, args))
        )

    def WARN(self, *args):
        # if self.get_verbose():
        print(
            WARN_COLOR + "[WARN] " + RESET_COLOR + " ".join(map(str, args))
        )


log = LogUtil()
