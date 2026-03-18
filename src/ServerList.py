#!/python3
import utils
from config import DELIM_SERVERS_LIST, IP_COLOR, PORT_COLOR, RESET_COLOR


class HostAddress:
    """
    Class object containing information about host's IP address and PORT number
    """

    def __init__(self, ip: str, port: int) -> None:

        if not utils.valid_ip(ip):
            raise ValueError(f"IP '{ip}' has wrong format.")

        self.ip: str = str(ip)
        self.port: int = int(port)
        self.next: HostAddress = None

    def __repr__(self, color=False) -> str:
        if color:
            iter = [str(IP_COLOR + self.ip + RESET_COLOR),str(PORT_COLOR + str(self.port) + RESET_COLOR)]
        else:
            iter = [self.ip, str(self.port)]
        
        return "[" + ":".join(iter) + "]"

    def equal(self, n2) -> bool:
        assert isinstance(
            n2, HostAddress
        ), "'n2' list node parameter must be type of 'HostAddress'"

        if self.ip == n2.ip and self.port == n2.port:
            return True
        return False

    def __iter__(self) -> None:
        yield self.ip
        yield self.port


class ServerList:
    """
    A circular linked list
    """

    size = 0

    def __init__(self, first_node: HostAddress = None) -> None:
        self.head: HostAddress = None
        if first_node:
            self.add_last(first_node)

    def __repr__(self, color=False) -> str:
        node = self.head
        nodes = []

        while node:
            nodes.append(node.__repr__(color))
            node = node.next
            # stop when find the head again
            if node == self.head:
                break

        if self.is_empty():
            return "(Empty)"
        return DELIM_SERVERS_LIST.join(nodes)

    def __iter__(self):
        node: HostAddress = self.head
        while node:
            yield node
            node = node.next
            # stop when find the head again
            if node == self.head:
                return

    def get_size(self) -> int:
        return self.size

    def is_empty(self) -> bool:
        return self.size == 0

    def add_after(self, new_host: HostAddress, prev_host: HostAddress) -> HostAddress:
        prev_node: HostAddress = self.get(prev_host)

        if not prev_node:
            return None

        existed_node = self.get(new_host)
        if existed_node:
            # if already exists in the list just return
            return existed_node

        ip, port = new_host
        node = HostAddress(ip, int(port))
        node.next = prev_node.next
        prev_node.next = node

        self.size += 1
        return node

    def add_last(self, new_host: HostAddress) -> HostAddress:
        existed_node = self.get(new_host)
        if existed_node:
            # if already exists in the list just return
            return existed_node

        ip, port = new_host
        node = HostAddress(ip, int(port))

        if self.head is None:
            self.head = node
            node.next = self.head
        else:
            for curr_node in self:
                pass
            curr_node.next = node
            node.next = self.head

        self.size += 1
        return node

    def get(self, host: HostAddress) -> HostAddress:
        for curr_node in self:
            if curr_node.equal(host):
                return curr_node
        return None

    def remove(self, host: HostAddress) -> bool:
        if self.is_empty():
            return False

        if self.head.equal(host):
            # find last server node in the list
            for curr_node in self:
                pass
            curr_node.next = self.head.next

            if self.get_size() == 1:
                self.head = None
            else:
                self.head = self.head.next
        else:
            for curr_node in self:
                if curr_node.equal(host):
                    break
                prev = curr_node

            if curr_node == self.head:
                return False

            prev.next = curr_node.next

        self.size -= 1
        return True

    def clear(self) -> None:
        self.head = None
        self.size = 0

    def equal(self, l2) -> None:
        assert isinstance(
            l2, ServerList
        ), "'l2' list parameter must be type of 'ServerList'"

        n1: HostAddress = self.head
        n2: HostAddress = l2.head

        # Traverse both lists and compare each node
        while n1 and n2:
            if not n1.equal(n2):
                return False
            n1 = n1.next
            n2 = n2.next
            # if found again the head
            if n1 is self.head or n2 is l2.head:
                break

        # If both lists have same number of nodes and
        # all corresponding nodes are same, then they are identical
        if n1 is self.head and n2 is l2.head:
            return True
        else:
            return False

    def copy_from(self, sourceList) -> None:
        curr_node: HostAddress = sourceList.head

        while curr_node:
            self.add_last(curr_node)
            curr_node = curr_node.next

            if curr_node is sourceList.head:
                break


# list = ServerList()
# list.add_last(HostAddress("127.0.1.1", 4043))
# list.add_last(HostAddress("127.0.1.1", 4044))
# list.add_last(HostAddress("127.0.1.1", 4045))

# print("list:")
# print(list.__repr__(True))

# list.add_after(HostAddress("127.0.1.1", 4046), HostAddress("127.0.1.1", 4043))

# print("new list:")
# print(list)

# print("get (list)", list.get(HostAddress("127.0.1.1", 4046)))

# list2 = ServerList()
# list2.copy_from(list)

# print("list2 (copy):")
# print(list2)

# print("list == list2:", list.equal(list2))

# print("get (list2)", list2.get(HostAddress("127.0.1.1", 4046)))

# list2.remove(HostAddress("127.0.1.1", 4044))

# print("new list2:")
# print(list2)

# ----- ERROR CHECKING -----
# HostAddress(".1.1.1", 890)
# HostAddress("1.1.1.1", "ASD")
# HostAddress("1.1.1.1", "")
