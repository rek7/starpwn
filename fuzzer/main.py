import random
import multiprocessing
import argparse
from pathlib import Path
from scapy.all import *

from apids import APID_NAMES

class UnixStreamSourceSink(Source):
    """Use a Unix socket as source and sink
    TODO: upstream this to https://github.com/secdev/scapy/blob/master/scapy/scapypipes.py ?
    """
    def __init__(self, unix_path, name=None):
        Source.__init__(self, name=name)
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(unix_path)
        self.last_recv_time = time.monotonic()

    def push(self, msg):
        # Wait a little bit since the last time some data was received, in order to prevent comm desync
        elapsed_since_recv = time.monotonic() - self.last_recv_time
        while elapsed_since_recv < 1.:
            print(f"\033[35mWaiting before sending {len(msg)} bytes (last recv was {elapsed_since_recv} second ago)\033[m")  # noqa
            time.sleep(1. - elapsed_since_recv)
            elapsed_since_recv = time.monotonic() - self.last_recv_time

        print(f"\033[35mSending {len(msg)} bytes: {msg.hex()}\033[m")
        sent = self.sock.send(msg)
        if sent != len(msg):
            print(f"\033[33;1mWARNING: only {sent}/{len(msg)} bytes were sent to the socket. Sending the remaining...\033[m")  # noqa
            # self.sock.sendall(msg[sent:])
            self.push(msg[sent:])

    def fileno(self):
        return self.sock.fileno()

    def deliver(self):
        # Improve stability by waiting a little bit before receiving data
        # (merge small packets together)
        self.last_recv_time = time.monotonic()
        time.sleep(.005)
        data = self.sock.recv(4096)
        self.last_recv_time = time.monotonic()
        self._send(data)

class CCSDSPacket(Packet):
    """CCSDS Space packet
    Structures from https://github.com/nasa/cFE/blob/6.7.3-bv/fsw/cfe-core/src/inc/ccsds.h:
        struct CCSDS_PriHdr_t {
            uint16be StreamId;
            uint16be Sequence;
            uint16be Length;
        }
        struct CCSDS_CmdSecHdr_t { // Secondary header for commands
            uint16be Command
        }
        struct CCSDS_TlmSecHdr_t { // Secondary header for telemetry
            uint8  Time[CCSDS_TIME_SIZE];
        }
    """
    name = "CCSDS"
    fields_desc = [
        # CCSDS version = StreamId & 0xe000
        # Version number from https://sanaregistry.org/r/packet_version_number
        # value 0 means "version 1"
        BitEnumField("version", 0, 3, {0: "#1"}),

        # packet type = StreamId & 0x1000
        BitEnumField("pkttype", 1, 1, {0: "TLM", 1: "CMD"}),

        # secondary header present = StreamId & 0x0800
        # Always present of command packets
        BitField("has_sec_header", 1, 1),

        # APID (CCSDS Application ID) = StreamId & 0x07ff
        # https://sanaregistry.org/r/space_packet_protocol_application_process_id
        BitMultiEnumField("apid", 0, 11, APID_NAMES, depends_on=lambda pkt: pkt.pkttype),

        # segmentation flags = Sequence & 0xc000
        # 3 means complete packet (0=continuation, 1=first, 2=last)
        BitField("segm_flags", 3, 2),

        # sequence count = Sequence & 0x3fff
        XBitField("seq_count", 0, 14),

        # packet length word
        ShortField("pkt_length", None),

        # Skip CCSDS_APIDqualifiers_t if MESSAGE_FORMAT_IS_CCSDS_VER_2

        # command function code (high bit is reserved) = Command & 0xff00
        ConditionalField(ByteField("cmd_func_code", 0),
                         lambda pkt: pkt.pkttype == 1 and pkt.has_sec_header),
        # XOR-to-0xff checksum = Command & 0x00ff
        ConditionalField(ByteField("cmd_checksum", 0),
                         lambda pkt: pkt.pkttype == 1 and pkt.has_sec_header),

        # Telemetry time: 32 bits seconds
        ConditionalField(IntField("tlm_time_secs", 0),
                         lambda pkt: pkt.pkttype == 0 and pkt.has_sec_header),
        # Telemetry time: 16 bits subseconds
        ConditionalField(ShortField("tlm_time_subsecs", 0),
                         lambda pkt: pkt.pkttype == 0 and pkt.has_sec_header),
    ]

    def post_build(self, pkt, payload):
        if payload:
            pkt += payload
        # Update length
        if self.pkt_length is None:
            pkt_length = len(pkt) - 7
            pkt = pkt[:4] + pkt_length.to_bytes(2, 'big') + pkt[6:]
        # Update checksum
        if self.pkttype == 1 and self.has_sec_header:
            cksum = 0xff
            for idx, x in enumerate(pkt):
                if idx != 7:
                    cksum ^= x
            pkt = pkt[:7] + cksum.to_bytes(1, 'big') + pkt[8:]
        return pkt

class mutateCCSDSHeader(object):
    def __init__(self):
        return

    def generate(self):
        packet = CCSDSPacket()

class fuzzer(object):
    def __init__(self, conn, mutationSteps):
        self.conn = conn
        self.mutationSteps = mutationSteps
        self.modifiableHeaderFields = [
            "version", 
            "pkttype",
            "has_sec_header",
            "apid",
            "segm_flags",
            "seq_count",
        ]

    def random_with_N_digits(self, n):
        range_start = 10**(n-1)
        range_end = (10**n)-1
        return random.randint(range_start, range_end)

    def begin(self):
        for step in range(self.mutationSteps):
            packet = CCSDSPacket()
            for header in self.modifiableHeaderFields:
                packet[header] = self.random_with_N_digits(step)
                client.push(CCSDSPacket())


parser = argparse.ArgumentParser()
parser.add_argument('-x', '--unix', type=Path,
                       help='Communicate to a UNIX socket to communicate', required=True)
args = parser.parse_args()
client = UnixStreamSourceSink(str(args.unix), name="client")
f = fuzzer(client, 5000)
f.begin()