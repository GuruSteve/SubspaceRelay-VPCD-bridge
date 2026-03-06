"""
Subspace Relay → BixVReader Bridge
====================================
Connects to your MQTT broker, discovers a Subspace Relay phone (reader mode),
and bridges APDU exchange to BixVReader's virtual PC/SC reader on localhost:35963.
GlobalPlatformPro (or any PC/SC tool) can then talk to the remote JavaCard as if
it were a locally connected card.

Install dependencies (run once):
    pip install paho-mqtt protobuf cryptography

Usage:
    # First run — generate a keypair and print the public key to enter in the app:
    python subspace_bridge.py --broker mqtt://192.168.1.x:1883 --genkey

    # Subsequent runs — use the saved private key:
    python subspace_bridge.py --broker mqtt://192.168.1.x:1883

    # Or pass a private key directly (hex):
    python subspace_bridge.py --broker mqtt://192.168.1.x:1883 --privkey <hex>

    # Then in GlobalPlatformPro:
    gp -reader "Virtual PCD 0" <your usual flags>
"""

import argparse
import hashlib
import logging
import os
import secrets
import socket
import struct
import sys
import threading
import time
import uuid

# ── third-party ──────────────────────────────────────────────────────────────
try:
    import paho.mqtt.client as mqtt
except ImportError:
    sys.exit("Missing dependency: pip install paho-mqtt")

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")

try:
    import qrcode
    _have_qrcode = True
except ImportError:
    _have_qrcode = False

try:
    from google.protobuf import descriptor_pool, descriptor_pb2, symbol_database
    from google.protobuf import descriptor as _descriptor
    from google.protobuf import message as _message
    from google.protobuf.internal import encoder as _encoder
    from google.protobuf import reflection as _reflection
    from google.protobuf.runtime_version import ValidateProtobufRuntimeVersion
    import google.protobuf
except ImportError:
    sys.exit("Missing dependency: pip install protobuf")

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("bridge")

# ── protobuf (hand-written, matches the schema exactly) ──────────────────────
# Rather than generating Python protobuf classes (which requires protoc),
# we implement minimal hand-coded serialisation that exactly matches the
# wire format observed in the Go implementation.
#
# Protobuf field tags used (field_number << 3 | wire_type):
#   wire_type 0 = varint, 1 = 64-bit, 2 = length-delimited, 5 = 32-bit
#
# Message oneof field numbers:
#   1  = payload          (Payload message)
#   2  = request_relay_info  (Empty)
#   3  = relay_info       (RelayInfo message)
#   4  = log              (Log message)
#   6  = disconnect       (Empty)
#   8  = request_relay_discovery (RequestRelayDiscovery)
#   9  = relay_discovery_plaintext (RelayDiscovery)
#   10 = relay_discovery_encrypted (RelayDiscoveryEncrypted)
#
# Payload fields:
#   1 = payload (bytes)
#   2 = payload_type (varint): PCSC_READER=3, PCSC_CARD=4
#   3 = sequence (varint)
#
# RelayInfo fields (we only need to read these):
#   1 = supported_payload_types (repeated varint)
#   5 = connection_type (varint)
#   9 = user_agent (string)
#   10 = uid (bytes)
#   11 = atqa (bytes)
#   12 = sak (bytes)
#
# RequestRelayDiscovery fields:
#   1 = controller_public_key (bytes)
#   2 = payload_types (repeated varint)
#
# RelayDiscovery fields:
#   1 = relay_id (string)
#   2 = relay_info (RelayInfo)
#
# RelayDiscoveryEncrypted fields:
#   1 = controller_public_key (bytes)
#   2 = relay_public_key (bytes)
#   3 = encrypted_relay_discovery (bytes)


def _encode_varint(value):
    bits = value & 0x7F
    value >>= 7
    result = b""
    while value:
        result += bytes([0x80 | bits])
        bits = value & 0x7F
        value >>= 7
    result += bytes([bits])
    return result


def _encode_field_len(field_number, data: bytes) -> bytes:
    tag = _encode_varint((field_number << 3) | 2)
    return tag + _encode_varint(len(data)) + data


def _encode_field_varint(field_number, value: int) -> bytes:
    tag = _encode_varint((field_number << 3) | 0)
    return tag + _encode_varint(value)


def _read_varint(data: bytes, pos: int):
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def _parse_message(data: bytes) -> dict:
    """Parse a protobuf message into a dict of {field_number: [values]}."""
    fields = {}
    pos = 0
    while pos < len(data):
        tag, pos = _read_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:  # varint
            value, pos = _read_varint(data, pos)
            fields.setdefault(field_number, []).append(value)
        elif wire_type == 2:  # length-delimited
            length, pos = _read_varint(data, pos)
            value = data[pos:pos + length]
            pos += length
            fields.setdefault(field_number, []).append(value)
        elif wire_type == 1:  # 64-bit
            value = data[pos:pos + 8]
            pos += 8
            fields.setdefault(field_number, []).append(value)
        elif wire_type == 5:  # 32-bit
            value = data[pos:pos + 4]
            pos += 4
            fields.setdefault(field_number, []).append(value)
        else:
            raise ValueError(f"Unknown wire type {wire_type} at pos {pos}")
    return fields


# ── Message builders ──────────────────────────────────────────────────────────

def build_request_relay_info() -> bytes:
    """Message { request_relay_info: Empty{} } — field 2, empty bytes"""
    inner = b""  # Empty proto
    return _encode_field_len(2, inner)


def build_request_relay_discovery(controller_pub_key: bytes) -> bytes:
    """Message { request_relay_discovery: RequestRelayDiscovery { controller_public_key, payload_types=[PCSC_READER=3] } }"""
    rrd = _encode_field_len(1, controller_pub_key)
    rrd += _encode_field_varint(2, 3)  # PAYLOAD_TYPE_PCSC_READER
    return _encode_field_len(8, rrd)


def build_payload_message(apdu: bytes, sequence: int = 0) -> bytes:
    """Message { payload: Payload { payload=apdu, payload_type=PCSC_READER=3, sequence } }"""
    payload = _encode_field_len(1, apdu)
    payload += _encode_field_varint(2, 3)  # PAYLOAD_TYPE_PCSC_READER
    payload += _encode_field_varint(3, sequence)
    return _encode_field_len(1, payload)


def build_disconnect() -> bytes:
    """Message { disconnect: Empty{} } — field 6"""
    return _encode_field_len(6, b"")


def parse_outer_message(data: bytes) -> dict:
    """Returns the outer Message as a dict."""
    return _parse_message(data)


def parse_relay_info(data: bytes) -> dict:
    fields = _parse_message(data)
    result = {}
    if 1 in fields:
        result["supported_payload_types"] = fields[1]
    if 5 in fields:
        result["connection_type"] = fields[5][0]
    if 9 in fields:
        result["user_agent"] = fields[9][0].decode("utf-8", errors="replace")
    if 10 in fields:
        result["uid"] = fields[10][0].hex().upper()
    if 11 in fields:
        result["atqa"] = fields[11][0].hex().upper()
    if 12 in fields:
        result["sak"] = fields[12][0].hex().upper()
    return result


def parse_relay_discovery(data: bytes) -> dict:
    fields = _parse_message(data)
    result = {}
    if 1 in fields:
        result["relay_id"] = fields[1][0].decode("utf-8")
    if 2 in fields:
        result["relay_info"] = parse_relay_info(fields[2][0])
    return result


def parse_relay_discovery_encrypted(data: bytes) -> dict:
    fields = _parse_message(data)
    result = {}
    if 1 in fields:
        result["controller_public_key"] = fields[1][0]
    if 2 in fields:
        result["relay_public_key"] = fields[2][0]
    if 3 in fields:
        result["encrypted_relay_discovery"] = fields[3][0]
    return result


def parse_payload(data: bytes) -> dict:
    fields = _parse_message(data)
    result = {}
    if 1 in fields:
        result["payload"] = fields[1][0]
    if 2 in fields:
        result["payload_type"] = fields[2][0]
    if 3 in fields:
        result["sequence"] = fields[3][0]
    return result


# ── Crypto (matches Go implementation exactly) ────────────────────────────────

def _derive_key(relay_id: str, salt: str, length: int = 16) -> bytes:
    """PBKDF2-SHA256 with 20 iterations, matching Go's pbkdf2.Key(sha256.New, relayID, salt, 20, 16)"""
    return hashlib.pbkdf2_hmac(
        "sha256",
        relay_id.encode("utf-8"),
        salt.encode("utf-8"),
        20,
        dklen=length,
    )


def _make_aead(relay_id: str) -> AESGCM:
    key = _derive_key(relay_id, "aead-crypto-key", 16)
    return AESGCM(key)


def encrypt_message(relay_id: str, plaintext: bytes) -> bytes:
    """Encrypt with AES-128-GCM, random nonce prepended (GCMWithRandomNonce)."""
    aead = _make_aead(relay_id)
    nonce = secrets.token_bytes(12)
    ciphertext = aead.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_message(relay_id: str, data: bytes) -> bytes:
    """Decrypt AES-128-GCM with 12-byte prepended nonce."""
    aead = _make_aead(relay_id)
    nonce = data[:12]
    ciphertext = data[12:]
    return aead.decrypt(nonce, ciphertext, None)


def mqtt_client_id(relay_id: str) -> str:
    """PBKDF2-SHA256 with salt 'mqtt-id', 20 iterations, 16 bytes → lowercase hex."""
    raw = _derive_key(relay_id, "mqtt-id", 16)
    return raw.hex()


def ecdh_aes_gcm(priv_key: X25519PrivateKey, pub_key_bytes: bytes) -> AESGCM:
    """Perform X25519 ECDH and return AES-128-GCM using first 16 bytes of shared secret."""
    pub_key = X25519PublicKey.from_public_bytes(pub_key_bytes)
    shared = priv_key.exchange(pub_key)
    return AESGCM(shared[:16])


def decrypt_discovery(priv_key: X25519PrivateKey, relay_pub_bytes: bytes,
                      encrypted: bytes) -> bytes:
    """Decrypt an encrypted RelayDiscovery payload."""
    aead = ecdh_aes_gcm(priv_key, relay_pub_bytes)
    nonce = encrypted[:12]
    ct = encrypted[12:]
    return aead.decrypt(nonce, ct, None)


# ── MQTT topic helpers ────────────────────────────────────────────────────────

TOPIC_BROADCAST_FROM_RELAY = "subspace/broadcast/from-relay"
TOPIC_BROADCAST_TO_RELAY = "subspace/broadcast/to-relay"


def topic_from_relay(client_id: str) -> str:
    return f"subspace/endpoint/{client_id}/from-relay"


def topic_to_relay(client_id: str) -> str:
    return f"subspace/endpoint/{client_id}/to-relay"


# ── vpcd (BixVReader) protocol ────────────────────────────────────────────────
# BixVReader connects TO us on the port we listen on.
# Protocol: each message is prefixed with a 2-byte big-endian length.
# Special length values:
#   0x00 0x00 = power down / disconnect
#   0x00 0x01 = power up (ATR request) — we respond with our fake ATR
#   0x00 0x02 = reset

VPCD_CTRL_LEN = 1
VPCD_CTRL_OFF = 0
VPCD_CTRL_ON = 1
VPCD_CTRL_RESET = 2
VPCD_CTRL_ATR = 4  # BixVReader extension: ATR request

# A generic T=1 ATR for a JavaCard (ISO 7816-3 compliant)
FAKE_ATR = bytes.fromhex("3B8F8001804F0CA000000306030001000000006A")  # Standard PC/SC contactless ISO 14443-4 Type A ATR


def vpcd_recv(sock: socket.socket) -> bytes | None:
    """Receive one vpcd message. Returns None on disconnect."""
    header = _recv_exact(sock, 2)
    if header is None:
        return None
    length = struct.unpack("!H", header)[0]
    if length == 0:
        return b""  # power off
    data = _recv_exact(sock, length)
    return data


def vpcd_send(sock: socket.socket, data: bytes):
    """Send one vpcd message."""
    sock.sendall(struct.pack("!H", len(data)) + data)


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (ConnectionResetError, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


# ── Bridge state machine ──────────────────────────────────────────────────────

class Bridge:
    def __init__(self, broker_url: str, priv_key: X25519PrivateKey,
                 vpcd_host: str = "127.0.0.1", vpcd_port: int = 35963,
                 mode: str = "reader"):
        self.broker_url = broker_url
        self.priv_key = priv_key
        self.pub_key_bytes = priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.vpcd_host = vpcd_host
        self.vpcd_port = vpcd_port
        self._mode = mode

        self._relay_id: str | None = None
        self._relay_client_id: str | None = None
        self._vpcd_sock: socket.socket | None = None
        self._pending_rapdu: bytes | None = None
        self._pending_event = threading.Event()
        self._session_active = False
        self._relay_info_received = False
        self._apdu_lock = threading.Lock()
        self._sequence = 0
        self._correlation_map: dict[bytes, threading.Event] = {}
        self._correlation_rapdu: dict[bytes, bytes] = {}
        self._lock = threading.Lock()

        # Discovery MQTT connection (uses dummy relay_id "discovery")
        self._disc_client = self._make_mqtt_client("discovery", is_discovery=True)
        self._relay_client: mqtt.Client | None = None

    # ── MQTT helpers ──────────────────────────────────────────────────────────

    def _parse_broker_url(self):
        """Return (host, port, username, password)."""
        url = self.broker_url
        scheme = "mqtt"
        if "://" in url:
            scheme, url = url.split("://", 1)
        user, password = None, None
        if "@" in url:
            creds, url = url.rsplit("@", 1)
            if ":" in creds:
                user, password = creds.split(":", 1)
            else:
                user = creds
        host, port_str = (url.split(":", 1) if ":" in url else (url, "1883"))
        port = int(port_str)
        return host, port, user, password

    def _make_mqtt_client(self, relay_id: str, is_discovery: bool = False) -> mqtt.Client:
        base_id = mqtt_client_id(relay_id)
        unique = uuid.uuid4().hex
        if is_discovery:
            client_id = base_id + "-controller-" + unique
        else:
            client_id = base_id + "-controller-" + unique

        client = mqtt.Client(
            client_id=client_id,
            protocol=mqtt.MQTTv5,
        )
        host, port, user, password = self._parse_broker_url()
        if user:
            client.username_pw_set(user, password)

        if is_discovery:
            client.on_connect = self._disc_on_connect
            client.on_message = self._disc_on_message
        else:
            client.on_connect = self._relay_on_connect
            client.on_message = self._relay_on_message

        client.connect(host, port, keepalive=30)
        return client

    # ── Discovery phase ───────────────────────────────────────────────────────

    def _disc_on_connect(self, client, userdata, flags, rc, properties=None):
        log.info("Discovery MQTT connected")
        client.subscribe(TOPIC_BROADCAST_FROM_RELAY, qos=1)
        # Broadcast messages are raw protobuf — NO encryption
        msg_bytes = build_request_relay_discovery(self.pub_key_bytes)
        props = mqtt.Properties(mqtt.PacketTypes.PUBLISH)
        props.ContentType = "application/proto"
        client.publish(TOPIC_BROADCAST_TO_RELAY, msg_bytes, qos=1, properties=props)
        log.info("Sent discovery request — tap your card to the phone now")

    def _disc_on_message(self, client, userdata, msg):
        log.debug(f"Broadcast received on {msg.topic}, {len(msg.payload)} bytes")
        # Broadcast messages are raw protobuf — no decryption needed
        try:
            outer = parse_outer_message(msg.payload)
        except Exception as e:
            log.debug(f"Failed to parse broadcast message: {e}")
            return
        log.debug(f"Broadcast outer fields: {list(outer.keys())}")

        # field 10 = relay_discovery_encrypted
        if 10 in outer:
            enc_fields = parse_relay_discovery_encrypted(outer[10][0])
            ctrl_key = enc_fields.get("controller_public_key", b"")
            if ctrl_key != self.pub_key_bytes:
                return  # not for us
            try:
                relay_pub = enc_fields["relay_public_key"]
                encrypted_disc = enc_fields["encrypted_relay_discovery"]
                decrypted = decrypt_discovery(self.priv_key, relay_pub, encrypted_disc)
                disc = parse_relay_discovery(decrypted)
            except Exception as e:
                log.warning(f"Failed to decrypt discovery: {e}")
                return
            self._handle_discovery(disc, client)

        # field 9 = relay_discovery_plaintext (we don't use plaintext but handle anyway)
        elif 9 in outer:
            disc = parse_relay_discovery(outer[9][0])
            self._handle_discovery(disc, client)

    def _handle_discovery(self, disc: dict, disc_client: mqtt.Client):
        relay_id = disc.get("relay_id", "")
        relay_info = disc.get("relay_info", {})
        if not relay_id:
            return

        log.info(f"Discovered relay: {relay_id}")
        uid = relay_info.get("uid", "unknown")
        ua = relay_info.get("user_agent", "unknown")
        atqa = relay_info.get("atqa", "")
        sak = relay_info.get("sak", "")
        log.info(f"  Card UID={uid}  ATQA={atqa}  SAK={sak}  app={ua}")

        # Stop discovery loop, start relay session
        disc_client.loop_stop()
        disc_client.disconnect()

        self._relay_id = relay_id
        self._relay_client_id = mqtt_client_id(relay_id)
        self._start_relay_session()

    # ── Relay session ─────────────────────────────────────────────────────────

    def _start_relay_session(self):
        log.info("Starting relay session")
        self._relay_client = self._make_mqtt_client(self._relay_id, is_discovery=False)
        self._relay_client.loop_start()
        # Wait for connection
        time.sleep(1)
        # Request relay info to confirm
        self._send_rpc(build_request_relay_info(), callback=self._handle_relay_info)

    def _relay_on_connect(self, client, userdata, flags, rc, properties=None):
        log.info("Relay MQTT connected")
        read_topic = topic_from_relay(self._relay_client_id)
        client.subscribe(read_topic, qos=2)

    def _relay_on_message(self, client, userdata, msg):
        log.debug(f"Relay msg topic={msg.topic} payload_len={len(msg.payload)}")

        try:
            plaintext = decrypt_message(self._relay_id, msg.payload)
        except Exception as e:
            log.warning(f"Decrypt failed: {e}")
            return

        # Extract correlation data from MQTTv5 properties
        corr = None
        if hasattr(msg, "properties") and msg.properties is not None:
            corr = getattr(msg.properties, "CorrelationData", None)
            if corr is not None:
                corr = bytes(corr)

        log.debug(f"Relay message received, corr={corr.hex() if corr else None}, pending_keys={[k.hex() for k in self._correlation_map.keys()]}")

        if corr is not None and corr in self._correlation_map:
            with self._lock:
                self._correlation_rapdu[corr] = plaintext
            self._correlation_map[corr].set()
            return

        log.debug("No correlation match — unsolicited message")
        # Unsolicited message — parse and handle
        outer = parse_outer_message(plaintext)
        if 4 in outer:  # Log
            log_fields = _parse_message(outer[4][0])
            if 1 in log_fields:
                log.info(f"Remote: {log_fields[1][0].decode('utf-8', errors='replace')}")
        elif 6 in outer:  # Disconnect
            log.info("Remote disconnected")
            self._session_active = False

    def _send_rpc(self, msg_bytes: bytes, callback=None) -> bytes | None:
        """Encrypt and publish an RPC message, wait for reply."""
        encrypted = encrypt_message(self._relay_id, msg_bytes)
        corr_id = secrets.token_bytes(16)
        event = threading.Event()

        with self._lock:
            self._correlation_map[corr_id] = event

        write_topic = topic_to_relay(self._relay_client_id)
        read_topic = topic_from_relay(self._relay_client_id)

        props = mqtt.Properties(mqtt.PacketTypes.PUBLISH)
        props.CorrelationData = corr_id
        props.ResponseTopic = read_topic
        props.ContentType = "application/proto"

        self._relay_client.publish(write_topic, encrypted, qos=2, properties=props)

        if not event.wait(timeout=30):
            log.warning("RPC timeout (30s)")
            with self._lock:
                del self._correlation_map[corr_id]
            return None

        with self._lock:
            reply = self._correlation_rapdu.pop(corr_id)
            del self._correlation_map[corr_id]

        if callback:
            callback(reply)
            return None
        return reply

    def _handle_relay_info(self, data: bytes):
        outer = parse_outer_message(data)
        if 3 not in outer:
            log.warning("Expected relay_info response")
            return
        info = parse_relay_info(outer[3][0])
        log.info(f"Relay info confirmed: {info}")
        self._relay_info_received = True
        self._session_active = True
        # Now start the vpcd bridge
        threading.Thread(target=self._vpcd_loop, daemon=True).start()

    def _send_apdu_raw(self, capdu: bytes) -> bytes | None:
        """Send a single APDU and return the raw response bytes including SW."""
        # Go reference implementation does not use sequence numbers for PCSC exchange
        msg = build_payload_message(capdu, 0)
        reply = self._send_rpc(msg)
        if reply is None:
            log.warning("exchange_apdu: RPC returned None (timeout?)")
            return None
        log.debug(f"exchange_apdu: raw reply hex={reply.hex()}")
        outer = parse_outer_message(reply)
        log.debug(f"exchange_apdu: outer fields={list(outer.keys())}")
        if 1 not in outer:
            log.warning(f"Unexpected reply type, fields: {list(outer.keys())}")
            return None
        payload = parse_payload(outer[1][0])
        rapdu = payload.get("payload")
        log.debug(f"exchange_apdu: rapdu={rapdu.hex() if rapdu else None}")
        return rapdu

    def exchange_apdu(self, capdu: bytes) -> bytes | None:
        """Send a cAPDU and return the raw response (including SW) transparently.

        We do NOT handle 61xx/6Cxx here — the PC/SC application (e.g. GPP)
        knows the correct CLA for GET RESPONSE under secure channel and will
        issue its own GET RESPONSE commands through the normal APDU path."""
        return self._send_apdu_raw(capdu)

    def disconnect(self):
        if self._relay_client and self._session_active:
            try:
                msg = build_disconnect()
                encrypted = encrypt_message(self._relay_id, msg)
                write_topic = topic_to_relay(self._relay_client_id)
                props = mqtt.Properties(mqtt.PacketTypes.PUBLISH)
                props.ContentType = "application/proto"
                self._relay_client.publish(write_topic, encrypted, qos=1, properties=props)
                time.sleep(0.2)
            except Exception:
                pass
        if self._relay_client:
            self._relay_client.loop_stop()
            self._relay_client.disconnect()

    # ── vpcd loop ─────────────────────────────────────────────────────────────

    def _vpcd_loop(self):
        """
        Connect TO BixVReader (RPC_TYPE=2 mode).
        BixVReader.ini must have RPC_TYPE=2, TCP_PORT=35963
        """
        log.info(f"Connecting to BixVReader on {self.vpcd_host}:{self.vpcd_port}")
        log.info("Then run GlobalPlatformPro: gp -reader \"Virtual PCD 0\" <flags>")

        while self._session_active:
            try:
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                conn.connect((self.vpcd_host, self.vpcd_port))
                log.info("Connected to BixVReader successfully")
                log.info("CARD READY — run GPP now:")
                log.info("  gp -r Vir --list -F")
                self._handle_vpcd_connection(conn)
                log.info("BixVReader session ended")
            except ConnectionRefusedError:
                log.warning("BixVReader not ready on port %d, retrying in 1s...", self.vpcd_port)
                time.sleep(1)
            except OSError as e:
                log.warning(f"vpcd connection error: {e}, retrying in 1s...")
                time.sleep(1)

    def _handle_vpcd_connection(self, conn: socket.socket):
        """
        Handle vpcd connection using two threads:
        - Reader thread: reads ALL bytes from socket continuously
          * ATR/control messages → answered immediately via write_lock
          * APDU messages → placed on apdu_queue
        - Main thread: takes APDUs from queue, calls relay, sends response via write_lock

        The write_lock ensures ATR responses and APDU responses never interleave.
        The reader thread always answers 0x04 immediately so BixVReader stays happy.
        """
        import queue as _queue
        conn.settimeout(None)
        write_lock = threading.Lock()
        apdu_queue = _queue.Queue()
        done = threading.Event()

        def locked_send(data):
            with write_lock:
                vpcd_send(conn, data)

        def reader():
            try:
                while not done.is_set():
                    data = vpcd_recv(conn)
                    if data is None:
                        break
                    if len(data) == 0:
                        log.debug("vpcd: power off")
                        break
                    if len(data) == 1:
                        ctrl = data[0]
                        if ctrl == VPCD_CTRL_OFF:
                            log.debug("vpcd: power off")
                            break
                        elif ctrl == VPCD_CTRL_ATR:
                            log.debug("vpcd: ATR request — sending ATR")
                            locked_send(FAKE_ATR)
                        elif ctrl == VPCD_CTRL_ON:
                            log.debug("vpcd: power on (no response)")
                        elif ctrl == VPCD_CTRL_RESET:
                            log.debug("vpcd: reset (no response)")
                        else:
                            log.debug(f"vpcd: unknown ctrl 0x{ctrl:02X}")
                        continue
                    # APDU
                    apdu_queue.put(data)
            except OSError:
                pass
            finally:
                apdu_queue.put(None)  # sentinel

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        try:
            with conn:
                while self._session_active:
                    try:
                        capdu = apdu_queue.get(timeout=1.0)
                    except _queue.Empty:
                        continue
                    if capdu is None:
                        break
                    log.info(f"C-APDU → {capdu.hex().upper()}")
                    t0 = time.monotonic()
                    rapdu = self.exchange_apdu(capdu)
                    t1 = time.monotonic()
                    log.info(f"R-APDU ← {rapdu.hex().upper() if rapdu else 'None'} ({(t1-t0)*1000:.0f}ms)")
                    locked_send(rapdu if rapdu else bytes([0x6F, 0x00]))
        finally:
            done.set()
            t.join(timeout=3)

    # ── Main entry point ──────────────────────────────────────────────────────

    # ── Deep-link / QR helpers ────────────────────────────────────────────────

    def build_deep_link(self, mode: str = "reader") -> str:
        """Build a subspace-relay:// deep link that opens the app with the
        correct broker URL, public key, and screen already filled in.

        Supported modes: reader, reader-dynamic, card
        """
        url = self.broker_url
        scheme = "mqtt"
        if "://" in url:
            scheme, rest = url.split("://", 1)
        else:
            rest = url

        # Strip scheme from rest so we can use host/port/creds directly
        # Format: [user:pass@]host[:port]
        host, port, user, password = self._parse_broker_url()

        # Map MQTT scheme to app deep-link query parameters
        params = {}
        if scheme in ("mqtt", "ws"):
            params["tls"] = "false"
        if scheme in ("ws", "wss"):
            params["websocket"] = "true"

        params["discovery"] = self.pub_key_bytes.hex().upper()

        userinfo = ""
        if user:
            userinfo = f"{user}:{password}@" if password else f"{user}@"

        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"subspace-relay://{userinfo}{host}:{port}/{mode}?{query}"

    def print_qr(self, mode: str = "reader"):
        """Print the deep-link QR code and URL to the terminal."""
        link = self.build_deep_link(mode)
        print()
        print("Scan with the Subspace Relay app (opens reader mode):")
        print(f"  {link}")
        if _have_qrcode:
            qr = qrcode.QRCode(border=1)
            qr.add_data(link)
            qr.make(fit=True)
            qr.print_ascii(invert=True)
        else:
            print("  (install 'qrcode' for a terminal QR code: pip install qrcode)")
        print()

    def run(self):
        log.info(f"Public key for app discovery field: {self.pub_key_bytes.hex().upper()}")
        self.print_qr(self._mode)
        self._disc_client.loop_start()
        try:
            while True:
                time.sleep(1.0)
                # Only restart discovery if we had an active session that has now ended
                # Use a flag that is only set True after relay_info is confirmed
                if self._relay_id and self._relay_info_received and not self._session_active:
                    log.info("Session ended. Restarting discovery in 3s...")
                    time.sleep(3)
                    self._relay_id = None
                    self._relay_client_id = None
                    self._relay_info_received = False
                    self._sequence = 0
                    self._disc_client = self._make_mqtt_client("discovery", is_discovery=True)
                    self._disc_client.loop_start()
        except KeyboardInterrupt:
            log.info("Shutting down")
            self.disconnect()


# ── Key persistence ───────────────────────────────────────────────────────────

KEY_FILE = "subspace_bridge_key.hex"


def load_or_generate_key() -> X25519PrivateKey:
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            hex_str = f.read().strip()
        raw = bytes.fromhex(hex_str)
        key = X25519PrivateKey.from_private_bytes(raw)
        pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        log.info(f"Loaded existing key from {KEY_FILE}")
        log.info(f"Public key (enter this in the app): {pub.hex().upper()}")
        return key
    else:
        key = X25519PrivateKey.generate()
        raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        with open(KEY_FILE, "w") as f:
            f.write(raw.hex())
        pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        log.info(f"Generated new key, saved to {KEY_FILE}")
        log.info(f"Public key (enter this in the app): {pub.hex().upper()}")
        return key


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Subspace Relay → BixVReader bridge")
    parser.add_argument("--broker", required=True,
                        help="MQTT broker URL, e.g. mqtt://192.168.1.x:1883")
    parser.add_argument("--privkey",
                        help="X25519 private key as hex (overrides saved key)")
    parser.add_argument("--genkey", action="store_true",
                        help="Generate a new key, print the public key, and exit")
    parser.add_argument("--vpcd-port", type=int, default=35963,
                        help="BixVReader TCP port (default: 35963)")
    parser.add_argument("--mode", default="reader",
                        choices=["reader", "reader-dynamic", "card"],
                        help="App screen to launch (default: reader)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.genkey:
        key = X25519PrivateKey.generate()
        raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        print(f"Private key: {raw.hex()}")
        print(f"Public key:  {pub.hex().upper()}")
        # Show QR code for the generated key
        tmp = Bridge(broker_url=args.broker, priv_key=key, mode=args.mode)
        tmp.print_qr(args.mode)
        print(f"Run the bridge with: --privkey {raw.hex()}")
        return

    if args.privkey:
        raw = bytes.fromhex(args.privkey)
        priv_key = X25519PrivateKey.from_private_bytes(raw)
        pub = priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        log.info(f"Using provided key, public: {pub.hex().upper()}")
    else:
        priv_key = load_or_generate_key()

    bridge = Bridge(
        broker_url=args.broker,
        priv_key=priv_key,
        vpcd_port=args.vpcd_port,
        mode=args.mode,
    )
    bridge.run()


if __name__ == "__main__":
    main()
