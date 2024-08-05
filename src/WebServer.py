import sys, os
import argparse
import socket
import threading
from ServerList import ServerList, HostAddress
from colorama import Fore, Style
from config import *
import time
import utils
import json
import signal


class WebServer:
    def __init__(self, port: int = INIT_PORT, verbose: bool = True) -> None:
        utils.log.set_verbose(verbose)

        self.HOSTNAME: str = socket.gethostname()
        self.IP: str = socket.gethostbyname(self.HOSTNAME)
        self.PORT: int = utils.find_avail_port(self.IP, port)
        self.SERVER_ADDR: HostAddress = HostAddress(self.IP, self.PORT)
        self.PID: int = os.getppid()

        # self.MSG: str = self.serialize_outcom_msg()

        self.DB = dict()
        self.CLIENTS_QUEUE: list[socket.socket] = []
        # initialize list adding itself into the linked list
        self.SERVERS_LIST: ServerList = ServerList(self.SERVER_ADDR)

        self.SERVER_SOCK: socket.socket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        self.SERVER_SOCK.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.SERVER_SOCK.bind((self.IP, self.PORT))

        self.MSG_HANDLER = {
            INSERT_MSG: {
                FN: self.handle_insert_request,
                MSG_STRUCT: {MSG_TYPE: INSERT_MSG, DATA: f"{self.IP}:{str(self.PORT)}"},
            },
            UPDATE_MSG: {
                FN: self.handle_update_request,
                MSG_STRUCT: {CREATOR: "", MSG_TYPE: UPDATE_MSG, DATA: ""},
            },
            CHECK_MSG: {
                FN: self.handle_check_request,
                MSG_STRUCT: {MSG_TYPE: CHECK_MSG},
            },
            GET_MSG: {
                FN: self.handle_get_request,
                MSG_STRUCT: {MSG_TYPE: GET_MSG, DATA: {ITEM: "", CONTENT: ""}},
            },
            PUT_MSG: {
                FN: self.handle_put_request,
                MSG_STRUCT: {MSG_TYPE: PUT_MSG, DATA: {ITEM: "", CONTENT: ""}},
            },
            FORWARD_GET_MSG: {
                FN: self.handle_fwrd_get_request,
                MSG_STRUCT: {
                    CREATOR: "",
                    MSG_TYPE: FORWARD_GET_MSG,
                    DATA: {ITEM: "", CONTENT: ""},
                },
            },
            FORWARD_PUT_MSG: {
                FN: self.handle_fwrd_put_request,
                MSG_STRUCT: {
                    CREATOR: "",
                    MSG_TYPE: FORWARD_PUT_MSG,
                    DATA: {ITEM: "", CONTENT: ""},
                },
            },
        }

    def serialize_outcom_msg(
        self,
        msg_type: str = None,
        creator_host: HostAddress = None,
        extra_info: tuple = None,
    ) -> str:
        if msg_type not in MSG_TYPES:
            raise ValueError("wrong msg type")

        # creates a shallow copy of the original to avoid conflicts between threads
        tmp_handler = self.MSG_HANDLER.copy()

        if msg_type == INSERT_MSG:
            pass
        elif msg_type == UPDATE_MSG:
            tmp_handler[msg_type][MSG_STRUCT][CREATOR] = (
                repr(creator_host).replace("[", "").replace("]", "")
            )

            tmp_handler[msg_type][MSG_STRUCT][DATA] = []
            for addr in self.SERVERS_LIST:
                tmp_handler[msg_type][MSG_STRUCT][DATA].append(f"{addr.ip}:{addr.port}")
        elif msg_type == CHECK_MSG:
            pass
        elif msg_type == GET_MSG or msg_type == RESPONSE_GET_MSG:
            if not isinstance(extra_info, tuple):
                raise ValueError("'extra_info' must be of type 'tuple'")

            tmp_handler[GET_MSG][MSG_STRUCT][DATA][ITEM] = extra_info[0]
            tmp_handler[GET_MSG][MSG_STRUCT][DATA][CONTENT] = extra_info[1]
            msg_type = GET_MSG
        elif msg_type == PUT_MSG:
            if not isinstance(extra_info, tuple):
                raise ValueError("'extra_info' must be of type 'tuple'")

            tmp_handler[msg_type][MSG_STRUCT][DATA][ITEM] = extra_info[0]
            tmp_handler[msg_type][MSG_STRUCT][DATA][CONTENT] = extra_info[1]
        elif msg_type == RESPONSE_PUT_MSG:
            if not isinstance(extra_info, tuple):
                raise ValueError("'extra_info' must be of type 'tuple'")

            tmp_handler[PUT_MSG][MSG_STRUCT][DATA][ITEM] = extra_info[0]
            tmp_handler[PUT_MSG][MSG_STRUCT][DATA].pop(
                CONTENT
            )  # remove 'content' key and add 'status'
            tmp_handler[PUT_MSG][MSG_STRUCT][DATA][STATUS] = (
                str(extra_info[1]) + " " + str(extra_info[2])
            )
            msg_type = PUT_MSG
        elif msg_type == FORWARD_GET_MSG or msg_type == FORWARD_PUT_MSG:
            if not isinstance(extra_info, tuple):
                raise ValueError("'extra_info' must be of type 'tuple'")

            tmp_handler[msg_type][MSG_STRUCT][CREATOR] = (
                repr(creator_host).replace("[", "").replace("]", "")
            )
            tmp_handler[msg_type][MSG_STRUCT][DATA][ITEM] = extra_info[0]
            tmp_handler[msg_type][MSG_STRUCT][DATA][CONTENT] = extra_info[1]

        return json.dumps(tmp_handler[msg_type][MSG_STRUCT])

    def deserialize_incom_msg(self, json_data: json):
        if json_data[MSG_TYPE] not in MSG_TYPES:
            raise ValueError("wrong msg type")

        if INSERT_MSG == json_data[MSG_TYPE]:
            new_addr: str = json_data[DATA]
            new_ip, new_port = new_addr.split(":")

            return HostAddress(new_ip, int(new_port))
        elif UPDATE_MSG == json_data[MSG_TYPE]:
            creator_ip, creator_port = json_data[CREATOR].split(":")
            server_list = json_data[DATA]

            # copy the recieved list into a temporary one
            update_list = ServerList()
            for s in server_list:
                ip, port = s.split(":")
                update_list.add_last(HostAddress(ip, int(port)))

            return (HostAddress(creator_ip, int(creator_port)), update_list)
        elif CHECK_MSG == json_data[MSG_TYPE]:
            pass
        elif GET_MSG == json_data[MSG_TYPE]:
            item = json_data[DATA]
            return item
        elif PUT_MSG == json_data[MSG_TYPE]:
            data = json_data[DATA]
            item = data[ITEM]
            content = data[CONTENT]

            return (item, content)
        elif FORWARD_GET_MSG == json_data[MSG_TYPE]:
            creator_ip, creator_port = json_data[CREATOR].split(":")
            data = json_data[DATA]
            item = data[ITEM]
            content = data[CONTENT]

            return (HostAddress(creator_ip, int(creator_port)), item, content)
        elif FORWARD_PUT_MSG == json_data[MSG_TYPE]:
            creator_ip, creator_port = json_data[CREATOR].split(":")
            data = json_data[DATA]
            item = data[ITEM]
            content = data[CONTENT]

            return (HostAddress(creator_ip, int(creator_port)), item, content)

    def is_creator(self, creator_host: HostAddress) -> bool:
        if self.SERVER_ADDR.equal(creator_host):
            utils.log.INFO("Stop the circular message: a complete cycle was performed!")
            return True
        return False

    def print_servers_list(self):
        utils.log.INFO("Connected servers:", self.SERVERS_LIST.__repr__(color=True))

    def listen(self, handler, interrupt_event: threading.Event = None):
        self.SERVER_SOCK.listen()
        self.SERVER_SOCK.setblocking(False)

        while not interrupt_event.is_set():
            try:
                # waiting for a connection
                conn_socket, address = self.SERVER_SOCK.accept()

                # create a new thread to handle the connection
                conn_thread = threading.Thread(
                    target=handler, args=(conn_socket, address)
                )
                # conn_thread.name = f"ConnHandlerThread#{count_conn}"
                conn_thread.start()
            except socket.error:
                pass

    def check_next_server(self, interrupt_event: threading.Event = None):
        while not interrupt_event.is_set():
            if self.SERVERS_LIST.get_size() != 1:
                next_server: HostAddress = self.SERVERS_LIST.get(self.SERVER_ADDR).next
                self.notify_server(msg_type=CHECK_MSG, dest_host=next_server)

            time.sleep(CHECK_MSG_INTERVAL)

    def notify_server(
        self,
        msg_type: str,
        creator_host: HostAddress = None,
        dest_host: HostAddress = None,
        extra_info: any = None,
    ):
        while True:
            # if the destination host is not specified
            if dest_host is None:
                # get the next server from the list
                dest_host: HostAddress = self.SERVERS_LIST.get(self.SERVER_ADDR).next

            # if the destination host is the same as the current one then return
            if self.SERVER_ADDR.equal(dest_host):
                utils.log.WARN("Destination host same as the current.")
                return

            # set the notification message structure
            msg = self.serialize_outcom_msg(
                msg_type=msg_type, creator_host=creator_host, extra_info=extra_info
            )

            def send_data(dest_host: HostAddress, data: bytes = None) -> bool:
                """
                core function for sending messages to the next server in the list
                Socket connection
                """
                dest_ip, dest_port = dest_host

                # create the socket connection
                conn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                # try connect with the desired host
                try:
                    conn_socket.connect((dest_ip, dest_port))
                except ConnectionRefusedError:
                    utils.log.ERROR(
                        f"Failed to connect with host: {dest_host.__repr__(True)}"
                    )
                    return False

                plain_data = data.decode(ENC_DATA_FORMAT)
                if CHECK_MSG in plain_data and utils.log.get_verbose() == False:
                    pass
                else:
                    sender_addr = HostAddress(
                        conn_socket.getsockname()[0], conn_socket.getsockname()[1]
                    )
                    utils.log.SEND(
                        f"To {dest_host.__repr__(True)} from {sender_addr.__repr__(True)} => {plain_data}"
                    )

                # send data
                conn_socket.sendall(data)
                conn_socket.close()

                return True

            """
            try sending data to the next server in the list
            if does not respond move to the next available, forwarding an UPDATE message
            """
            if not send_data(dest_host, msg.encode(ENC_DATA_FORMAT)):
                # first, remove the disconnected server from the list and proceed to the next available
                if not self.SERVERS_LIST.remove(dest_host):
                    utils.log.WARN("Server not found in the list")
                    return

                if self.SERVERS_LIST.get_size() == 1:
                    utils.log.WARN("Only one server in the list")
                    return

                # print the updated list
                self.print_servers_list()

                # set the message type to UPDATE to noTify the next server in the list for the removal
                msg_type = UPDATE_MSG
                # update also the creator host to be this server because he's responsible to send the UPDATE message
                creator_host = self.SERVER_ADDR

                # get next one available
                dest_host: HostAddress = self.SERVERS_LIST.get(self.SERVER_ADDR).next
            else:
                # Successfull connection, break...
                break

    def handle_request(self, conn_socket: socket.socket, address):
        conn_ip, conn_port = address

        # recv = ""
        # while True:
        #     # recieved data
        #     data = conn_socket.recv(MAX_RECV_DATA).decode(ENC_DATA_FORMAT)
        #     if not data:
        #         break
        #     recv += data
        recv = conn_socket.recv(MAX_RECV_DATA).decode(ENC_DATA_FORMAT)

        if recv == "":
            return

        recv_json = json.loads(recv)

        # if not any(m_type in recv_json for m_type in MSG_TYPES):
        if MSG_TYPE not in recv_json:
            raise ValueError("wrong message structure")

        conn_host = HostAddress(conn_ip, int(conn_port))
        if recv_json[MSG_TYPE] == CHECK_MSG and utils.log.get_verbose() == False:
            pass
        else:
            utils.log.RECV(f"From {conn_host.__repr__(True)} => {recv_json}")

        self.MSG_HANDLER[recv_json[MSG_TYPE]][FN](conn_socket, conn_host, recv_json)

    def handle_insert_request(self, conn_socket=None, conn_host=None, recv_json=None):
        new_host: HostAddress = self.deserialize_incom_msg(recv_json)

        # add the new host into the list
        utils.log.INFO("Updating server's list...")
        self.SERVERS_LIST.add_after(new_host, self.SERVER_ADDR)

        # print the updated list
        self.print_servers_list()

        # send update notification to the next server
        self.notify_server(msg_type=UPDATE_MSG, creator_host=self.SERVER_ADDR)

    def handle_update_request(self, conn_socket=None, conn_host=None, recv_json=None):
        creator_host, update_list = self.deserialize_incom_msg(recv_json)

        # if the two lists does not match then proceed to changes in the local list
        if not self.SERVERS_LIST.equal(update_list):
            utils.log.INFO("Updating server's list...")
            self.SERVERS_LIST.clear()
            self.SERVERS_LIST.copy_from(update_list)
        else:
            utils.log.INFO("No current updates.")

        self.print_servers_list()

        # if the current server is the creator of the UPDATE message (and a complete circle performed) then return
        if self.is_creator(creator_host):
            return

        # else, continue the circular message
        self.notify_server(
            msg_type=UPDATE_MSG,
            creator_host=creator_host,
        )

    def handle_check_request(self, conn_socket=None, conn_host=None, recv_json=None):
        pass

    def handle_get_request(self, conn_socket=None, conn_host=None, recv_json=None):
        self.CLIENTS_QUEUE.append(conn_socket)
        item = self.deserialize_incom_msg(recv_json)

        utils.log.INFO(f"Server's DB: {self.DB}")

        # check if the current server contains the requested item
        if self.DB.__contains__(item):
            # response to client immediately
            content = self.DB.get(item)
            response = self.serialize_outcom_msg(
                msg_type=RESPONSE_GET_MSG, extra_info=(item, content)
            )

            utils.log.SEND(f"Send to client {conn_host.__repr__(True)} => {response}")

            client_sock: socket.socket = self.CLIENTS_QUEUE.pop(0)
            # send data to client and closes the connection
            client_sock.send(response.encode(ENC_DATA_FORMAT))
            client_sock.close()
        else:
            # if the current server does not have the requested item then forwards the request to the next server from the list
            if self.SERVERS_LIST.get_size() == 1:
                # if there is only one connected server in the list then send the response immediately to client
                response = self.serialize_outcom_msg(
                    msg_type=RESPONSE_GET_MSG, extra_info=(item, NOT_FOUND_MSG)
                )

                utils.log.SEND(
                    f"Send to client {conn_host.__repr__(True)} => {response}"
                )

                client_sock: socket.socket = self.CLIENTS_QUEUE.pop(0)
                # send data to client and closes the connection
                client_sock.send(response.encode(ENC_DATA_FORMAT))
                client_sock.close()
            else:
                """
                forwards the request to the next server
                and sets itself as the creator host
                for the circular message
                """
                self.notify_server(
                    msg_type=FORWARD_GET_MSG,
                    creator_host=self.SERVER_ADDR,
                    extra_info=(item, NOT_FOUND_MSG),
                )

    def handle_put_request(self, conn_socket=None, conn_host=None, recv_json=None):
        self.CLIENTS_QUEUE.append(conn_socket)
        item, content = self.deserialize_incom_msg(recv_json)

        utils.log.INFO(f"Updating item: {item}...")
        self.DB[item] = content

        utils.log.INFO(f"Server's (updated) DB: {self.DB}")

        # only one server in the list: send back to client
        if self.SERVERS_LIST.get_size() == 1:
            response = self.serialize_outcom_msg(
                msg_type=RESPONSE_PUT_MSG, extra_info=(item, 200, OK_MSG)
            )

            utils.log.SEND(f"Send to client {conn_host.__repr__(True)} => {response}")

            client_sock: socket.socket = self.CLIENTS_QUEUE.pop(0)
            # send data to client and closes the connection
            client_sock.send(response.encode(ENC_DATA_FORMAT))
            client_sock.close()
        else:
            """
            forwards the request to the next server
            and sets itself as the creator host
            for the circular message
            """
            self.notify_server(
                msg_type=FORWARD_PUT_MSG,
                creator_host=self.SERVER_ADDR,
                extra_info=(item, content),
            )

    def handle_fwrd_get_request(self, conn_socket=None, conn_host=None, recv_json=None):
        creator_host, item, content = self.deserialize_incom_msg(recv_json)

        # if the current server does not have the specific item then adds it
        if not self.DB.__contains__(item) or self.DB[item] == NOT_FOUND_MSG:
            self.DB[item] = content
            utils.log.INFO(f"Server's (updated) DB: {self.DB}")
        else:
            content = self.DB[item]
            utils.log.INFO(f"Server's DB: {self.DB}")

        # if the current server is the creator then stop the forwarding
        if self.is_creator(creator_host):
            client_sock: socket.socket = self.CLIENTS_QUEUE.pop(0)

            cont = self.DB[item]
            if cont is NOT_FOUND_MSG:
                response = self.serialize_outcom_msg(
                    msg_type=RESPONSE_GET_MSG, extra_info=(item, NOT_FOUND_MSG)
                )
            else:
                response = self.serialize_outcom_msg(
                    msg_type=RESPONSE_GET_MSG, extra_info=(item, cont)
                )

            utils.log.SEND(f"Send to client {conn_host.__repr__(True)} => {response}")

            # send data to client and closes the connection
            client_sock.send(response.encode(ENC_DATA_FORMAT))
            client_sock.close()
        else:
            """
            forwards the request to the next server
            and sets itself as the creator host
            for the circular message
            """
            self.notify_server(
                msg_type=FORWARD_GET_MSG,
                creator_host=creator_host,
                extra_info=(item, content),
            )

    def handle_fwrd_put_request(self, conn_socket=None, conn_host=None, recv_json=None):
        creator_host, item, content = self.deserialize_incom_msg(recv_json)

        # update the DB
        self.DB[item] = content
        utils.log.INFO(f"Server's (updated) DB: {self.DB}")

        if self.is_creator(creator_host):
            client_sock: socket.socket = self.CLIENTS_QUEUE.pop(0)

            response = self.serialize_outcom_msg(
                msg_type=RESPONSE_PUT_MSG, extra_info=(item, 200, OK_MSG)
            )

            utils.log.SEND(f"Send to client {creator_host} => {response}")

            # send data to client and closes the connection
            client_sock.send(response.encode(ENC_DATA_FORMAT))
            client_sock.close()
        else:
            """
            forwards the request to the next server
            and sets itself as the creator host
            for the circular message
            """
            self.notify_server(
                msg_type=FORWARD_PUT_MSG,
                creator_host=creator_host,
                extra_info=(item, content),
            )


def main(arguments):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-ip",
        "--prev-ip",
        help="Previous server's IP address in the list",
        type=str,
        required=False,
    )
    parser.add_argument(
        "-port",
        "--prev-port",
        help="Previous server's PORT number in the list",
        type=int,
        required=False,
    )
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args(arguments)

    if args.prev_ip and not utils.valid_ip(args.prev_ip):
        parser.error("Wrong IP format.")

    # server initialization
    ws = WebServer(verbose=args.verbose)

    print(
        "This Server listens on "
        + HostAddress(ws.IP, ws.PORT).__repr__(color=True)
        + " ["
        + Fore.RED
        + "PID:"
        + str(ws.PID)
        + Style.RESET_ALL
        + "]"
    )

    send_ip: str = args.prev_ip
    send_port: int = args.prev_port

    # interrupt event
    interrupt_event = threading.Event()

    # listen to connections...
    listen_thread = threading.Thread(
        target=ws.listen,
        args=(ws.handle_request, interrupt_event),
    )
    listen_thread.name = "Listen_Conn_Thread"
    listen_thread.start()

    ws.print_servers_list()

    if send_ip and send_port:
        # send notification to previous server to update the server list
        ws.notify_server(
            msg_type=INSERT_MSG, dest_host=HostAddress(send_ip, int(send_port))
        )

    # send repeatedly (every N seconds) a check message to the next server if is alive
    server_check_thread = threading.Thread(
        target=ws.check_next_server, args=(interrupt_event,)
    )
    server_check_thread.name = "Server_Check_Thread"
    server_check_thread.start()

    # a signal handler to gracefully terminate the program
    def signal_handler(sig, frame):
        # print("Received signal {}, terminating...".format(sig))
        print("Terminating Server...")
        # Set the interrupt event to stop the listen thread
        interrupt_event.set()
        # Close the server socket to unblock the accept call in the listen thread
        ws.SERVER_SOCK.close()
        # Wait for the listen thread to finish
        listen_thread.join()
        server_check_thread.join()
        # Get a list of all active threads (excluding the main thread)
        threads = threading.enumerate()
        client_sockets = []
        for t in threads:
            if t is not threading.current_thread() and hasattr(t, "conn"):
                client_sockets.append(t.conn)
                # Interrupt any running threads
                t.interrupt()
        # Wait for all threads to finish
        for t in threads:
            if t is not threading.current_thread():
                t.join()

        for conn in client_sockets:
            conn.close()
        # Exit the program
        exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    listen_thread.join()
    server_check_thread.join()


if __name__ == "__main__":
    main(sys.argv[1:])
