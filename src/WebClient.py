#!/python3
import socket, sys, argparse, os
import json
from config import *
from ServerList import HostAddress


def main(arguments):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-get",
        "--get-file",
        help="GET Request: file name",
        type=str
    )
    parser.add_argument(
        "-put",
        "--put-file",
        help="PUT Request: file",
        type=argparse.FileType("r")
    )
    parser.add_argument(
        "-i", "--ip", help="Server's listening IP address", type=str, required=False
    )
    parser.add_argument(
        "-p", "--port", help="Server's listening PORT number", type=int, required=False
    )
    args = parser.parse_args(arguments)

    if (not args.get_file or not args.put_file) and not args.ip and not args.port:
        sys.exit("No parameters were given")

    server_addr = HostAddress(args.ip, args.port)
    (server_ip, server_port) = server_addr

    if args.get_file:
        file = args.get_file
        msg = {MSG_TYPE: GET_MSG, DATA: file}
    elif args.put_file:
        file_content = args.put_file.read()
        file_name = os.path.basename(args.put_file.name)
        msg = {
            MSG_TYPE: PUT_MSG,
            DATA: {
                ITEM: file_name,
                CONTENT: file_content,
            },
        }

    message = json.dumps(msg)

    # connect to server's socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.connect((server_ip, server_port))

    sender_ip, sender_port = sock.getsockname()
    sender_addr = HostAddress(sender_ip, sender_port)
    print(f"Send to server {server_addr} from {sender_addr} =>", msg)

    # send once the request to server
    sock.sendall(message.encode(ENC_DATA_FORMAT))

    # recieve a response from the server
    data = sock.recv(MAX_RECV_DATA).decode(ENC_DATA_FORMAT)

    # close the connection
    sock.close()

    # convert to JSON document
    try:
        data_json = json.loads(data)
    except json.JSONDecodeError:
        sys.exit("json load error")

    print("\nResponse from server:")
    print(data_json)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        exit()
