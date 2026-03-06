# Subspace Relay → VPCD Bridge

Bridges the [Subspace Relay](https://github.com/bitsettle/subspace) Android app (acting as a contactless card reader) to a virtual PC/SC reader via [BixVReader](https://github.com/bitsxbytes/BixVReader) (a VPCD implementation).

This lets any PC/SC tool — such as [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) — talk to a remote JavaCard held against an Android phone as if it were a locally connected smart card.

## How it works

1. The bridge connects to your MQTT broker and broadcasts a discovery request.
2. The Subspace Relay app on your phone (in reader mode) responds with an encrypted relay advertisement.
3. The bridge performs an X25519 ECDH key exchange to authenticate and establish a session.
4. It then connects to BixVReader's virtual PC/SC socket (`localhost:35963`) and transparently forwards APDU commands from the PC/SC layer to the phone, and responses back.

```
PC/SC tool (e.g. GPP)
        ↕  PC/SC
  BixVReader (VPCD)
        ↕  TCP :35963
  subspace-relay-vpcd-bridge.py
        ↕  MQTT (encrypted)
  Subspace Relay app (Android)
        ↕  NFC
     JavaCard / contactless card
```

## Dependencies

Install required dependencies:

```bash
pip install paho-mqtt cryptography protobuf
```

| Package | Required | Purpose |
|---------|----------|---------|
| `paho-mqtt` | Yes | MQTT transport |
| `cryptography` | Yes | X25519 ECDH + AES-128-GCM encryption |
| `protobuf` | Yes | Subspace Relay wire format |
| `qrcode` | No | Print a QR code for the deep-link in your terminal |

Optional:

```bash
pip install qrcode
```

## Setup

### Prerequisites

- MQTT broker running on your network (e.g. [Mosquitto](https://mosquitto.org/))
- [BixVReader](https://github.com/bitsxbytes/BixVReader) installed and configured with `RPC_TYPE=2`, `TCP_PORT=35963`
- [Subspace Relay](https://github.com/bitsettle/subspace) app installed on Android

### First run — generate a keypair

```bash
python subspace-relay-vpcd-bridge.py --broker mqtt://192.168.1.x:1883 --genkey
```

This prints your public key and a QR code (if `qrcode` is installed). Enter the public key in the Subspace Relay app's discovery / controller field, or scan the QR code directly.

### Subsequent runs

```bash
python subspace-relay-vpcd-bridge.py --broker mqtt://192.168.1.x:1883
```

The private key is saved to `subspace_bridge_key.hex` and reloaded automatically.

### Pass a key explicitly

```bash
python subspace-relay-vpcd-bridge.py --broker mqtt://192.168.1.x:1883 --privkey <hex>
```

### Use with GlobalPlatformPro

Once the bridge is running and a card is discovered:

```bash
gp -reader "Virtual PCD 0" --list
```

## CLI reference

```
usage: subspace-relay-vpcd-bridge.py [-h] --broker BROKER [--privkey PRIVKEY]
                                     [--genkey] [--vpcd-port VPCD_PORT]
                                     [--mode {reader,reader-dynamic,card}] [-v]

options:
  --broker       MQTT broker URL (e.g. mqtt://192.168.1.x:1883)
  --privkey      X25519 private key as hex (overrides saved key file)
  --genkey       Generate a new keypair, print public key + QR, and exit
  --vpcd-port    BixVReader TCP port (default: 35963)
  --mode         App screen to deep-link to: reader, reader-dynamic, card (default: reader)
  -v, --verbose  Enable debug logging
```

## Security notes

- All MQTT payloads are encrypted with AES-128-GCM.
- Discovery uses X25519 ECDH so only your controller key can decrypt relay advertisements.
- The private key is stored in plaintext in `subspace_bridge_key.hex` — keep this file private.
