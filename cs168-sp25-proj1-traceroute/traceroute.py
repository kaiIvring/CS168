import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  
# The unit tests assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  
# PROBE_ATTEMPT_COUNT is the maximum number of times 
# your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    # Each member below is a field from the IPv4 packet header.  
    # They are listed below in the order they appear in the packet.  
    # All fields should be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.version = int(b[0:4], 2)
        self.header_len = int(b[4:8], 2) * 4 # length in bytes
        self.tos = int(b[8:16], 2)
        self.length = int(b[16:32], 2)
        self.id = int(b[32:48], 2)
        self.flags = int(b[48:51], 2)
        self.frag_offset = int(b[51:64], 2)
        self.ttl = int(b[64:72], 2)
        self.proto = int(b[72:80], 2)
        self.cksum = int(b[80:96], 2)
        self.src = '.'.join(str(int(b[i:i+8], 2)) for i in range(96, 128, 8))
        self.dst = '.'.join(str(int(b[i:i+8], 2)) for i in range(128, 160, 8))

    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header. 
    # They are listed below in the order they appear in the packet. 
    # All fields should be stored in host byte order.
    #
    # You should only modify the __init__() function of this class.

    # type3: destination unreachable; type11: Time-to-live exceeded
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.type = int(b[0:8], 2)
        self.code = int(b[8:16], 2)
        self.cksum = int(b[16:32], 2)

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header. 
    # They are listed below in the order they appear in the packet.  
    # All fields should be stored in host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        b = ''.join(format(byte, '08b') for byte in [*buffer])
        self.src_port = int(b[0:16], 2)
        self.dst_port = int(b[16:32], 2)
        self.len = int(b[32:48], 2)
        self.cksum = int(b[48:64], 2)

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

def parse_packet(buf: bytes, expected_src_port: int, target_ip: str) -> tuple[str | None, bool]:
    # Test B5: Unparseable Response
    try:
        # check min length
        # Test B6: Truncated Buffer
        if len(buf) < 20:
            return None, False
        
        # try to parse IPV4
        ip_header = IPv4(buf[:20])

        # header_len larger than buf means invalid packet
        # Test B8: IP Options
        if ip_header.header_len > len(buf):
            return None, False
        
        # only deal with ICMP protocol(proto = 1)
        # Test B4: Invalid IP Protocol
        # Test B7: Irrelevant UDP Respose
        if ip_header.proto != 1:
            return None, False
        
        # try to parse ICMP
        icmp_start = ip_header.header_len
        if len(buf) < icmp_start + 8:
            return None, False
        
        icmp = ICMP(buf[icmp_start:icmp_start + 8])

        # only accept type 3(destination unreachable)
        # or type 11(TTL exceeded)
        # Test B2: Invalid ICMP Type
        if icmp.type not in (3, 11):
            return None, False

        # error type is "time exceeded", but the error code is 
        # not "TTL exceeded in transit", ignore the packet
        # Test B3: Invalid ICMP Code
        if icmp.type == 3 and icmp.code != 0:
            return None, False
        
        inner_ip_start = icmp_start + 8
        inner_ip = IPv4(buf[inner_ip_start:inner_ip_start + 20])
        inner_udp_start = inner_ip_start + inner_ip.header_len
        inner_udp = UDP(buf[inner_udp_start:inner_udp_start + 8])

        # Test B15: Delayed Duplicates
        # check if the inner UDP src port matches expected src port
        # avoid delayed packets from previous probes
        if inner_udp.src_port != expected_src_port:
            return None, False
        
        # Test B16: Irrelevant TTL Response
        # If the inner IP destination doesn't match the current traceroute target,
        # this ICMP packet is from another destination, ignore it.
        if inner_ip.dst != target_ip:
            return None, False

        return ip_header.src, True

    except Exception:
        return None, False


def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was probed.  
    The ith list contains all of the routers found with TTL probe of i+1.   
    The routers discovered in the ith list can be in any order.  
    If no routers were found, the ith list can be empty.  
    If `ip` is discovered, it should be included as the final element in the list.
    """
    result = [[] for _ in range(TRACEROUTE_MAX_TTL)]
    done = False
    BASE_SRC_PORT = 33434

    for ttl in range(1, TRACEROUTE_MAX_TTL + 1):
        valid_count = 0
        invalid_count = 0

        for attempt in range(PROBE_ATTEMPT_COUNT):
            # for every TTL outgoing packet, use a unique source port
            # so that we can detect delayed packets from previous probes
            src_port = BASE_SRC_PORT + ttl
            sendsock = util.Socket.make_udp()
            sendsock._Socket__sock.bind(('0.0.0.0', src_port))

            sendsock.set_ttl(ttl)
            sendsock.sendto("whatsup?".encode(), (ip, TRACEROUTE_PORT_NUMBER))

            if recvsock.recv_select():
                buf, _ = recvsock.recvfrom()
                
                # print raw bytes of the packet
                # print(f"Packet bytes: {buf.hex()}")

                route_ip, valid = parse_packet(buf, expected_src_port = src_port, target_ip = ip) 

                if not valid:
                    invalid_count += 1
                    continue

                valid_count += 1

                # avoid duplicate intermediate router ip
                if route_ip not in result[ttl - 1]:
                    result[ttl - 1].append(route_ip)

                # reach destination
                if route_ip == ip:
                    done = True
                    break
        
        # three attempts all receive invalid packet
        if valid_count == 0:
            result[ttl - 1] = []

        util.print_result(result[ttl - 1], ttl)
        
        if done:
            break

    return result[:ttl]


if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)