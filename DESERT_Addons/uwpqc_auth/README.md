# uwpqc_auth

`Module/UW/PQCAuth` is a DESERT/Miracle module that performs a **post-quantum mutual
authentication handshake** between two nodes over an underwater acoustic link, using
[liboqs](https://github.com/open-quantum-safe/liboqs) for the KEM and signature
primitives and OpenSSL for HMAC/HKDF key confirmation.

## What it does

The module runs a 4-message handshake carried inside `PacketHeader/UWPQC_AUTH` packets:

1. **ClientHello** – initiator sends a fresh KEM public key, a nonce, and a signature
   over the message (signed with its long-term identity key).
2. **ServerKey** – responder encapsulates a shared secret against the initiator's KEM
   key, replies with the KEM ciphertext plus its own nonce, and signs the message.
3. **ClientFinish** / **ServerFinish** – both sides derive a confirmation key from the
   shared secret and an HMAC transcript, and exchange signed confirmation tags to prove
   both parties hold the same derived key.

Each signed message is verified against a `trustPeer`-pinned public key before being
accepted, and a per-peer `session_id_` cache rejects replayed/duplicate `ClientHello`s.

Because acoustic PHYs only offer a few hundred bytes per packet, the module transparently
fragments/reassembles each logical handshake message into `UWPQC_AUTH_FRAGMENT_SIZE`
(96-byte) chunks with sequence numbers and fragment counts, and drives its own
retransmission timer (`retransmitTimeout_` / `maxRetries_`) independent of the underlying
MAC's ARQ. On failure (bad signature, malformed reassembly, retry exhaustion) the module
moves to a terminal `FAILED` state rather than retrying indefinitely.

The KEM and signature primitives are pluggable at runtime: `setKemAlgorithm` accepts any
`ML-KEM-*`, `HQC-*`, or `NTRU-*` liboqs identifier, and `setSignatureAlgorithm` accepts
any `ML-DSA-*`, `SLH-DSA*`/`SLH_DSA*`, or `Falcon-*` identifier. Switching algorithms
invalidates any previously created identity/trusted keys (they're cleansed automatically)
since a signature keypair is only valid for the algorithm it was generated with.

## How to use it

Build the addon (against a DESERT install with liboqs and OpenSSL headers available):

```bash
cd DESERT_Addons/uwpqc_auth
./autogen.sh   # only needed after a fresh clone
./configure --with-oqs=/path/to/liboqs/prefix
make
```

In a Tcl scenario, load `libuwpqc_auth.so`, register the packet header, create one
`Module/UW/PQCAuth` instance per node, and stitch it above a UDP/IP stack like any other
DESERT application module. The module exposes these Tcl commands (on top of the usual
bound variables `destAddr_`, `destPort_`, `localAddr_`, `debug_`, `maxFragmentPayload_`,
`retransmitTimeout_`, `maxRetries_`):

| Command | Purpose |
|---|---|
| `createIdentity` | Generates a signature keypair for the current signature algorithm and returns the base64-encoded public key (the secret key stays inside the module). |
| `trustPeer <addr> <base64-pubkey>` | Pins a peer's public key so its handshake messages can be verified. |
| `setKemAlgorithm <name>` / `setSignatureAlgorithm <name>` | Switch liboqs algorithms while the module is `IDLE`; call before `createIdentity`/`trustPeer`. |
| `getAlgorithms` | Returns the active `kem`/`signature` algorithm names as a Tcl dict-like string. |
| `startHandshake <peerAddr>` | Initiates the handshake as the client toward `peerAddr` (the peer responds automatically once it receives a valid `ClientHello`). |
| `getState` | Returns the current state machine state (`IDLE`, `WAIT_SERVER_KEY`, `WAIT_CLIENT_FINISH`, `WAIT_SERVER_FINISH`, `AUTHENTICATED`, `FAILED`). |
| `getStats` | Returns a dict of counters (`handshake_attempts`, `handshake_successes`, `handshake_elapsed_s`, `tx_packets`, `rx_packets`, `tx_bytes`, `rx_bytes`, `tx_fragments`, `rx_fragments`, `retransmissions`, `signature_failures`, `malformed_packets`, ...). |

Typical provisioning/bring-up sequence for a two-node scenario, mirroring
[samples/test_uwpqc_ntru_falcon_handshake.tcl](samples/test_uwpqc_ntru_falcon_handshake.tcl):

```tcl
set pub0 [$auth(0) createIdentity]
set pub1 [$auth(1) createIdentity]
$auth(0) trustPeer [$ipif(1) addr] $pub1
$auth(1) trustPeer [$ipif(0) addr] $pub0

$ns at $opt(starttime) "$auth(0) startHandshake [$ipif(1) addr]"
```

Two sample scripts are provided:

- `samples/test_uwpqc_ntru_falcon_handshake.tcl` – fixed NTRU-HPS-2048-509 +
  Falcon-512 scenario.
- `samples/test_uwpqc_algo_matrix.tcl` – the same scenario parameterized by
  `<kem> <sig>` argv, printing a single `RESULT|...` line with timing/traffic stats;
  driven by `samples/run_algo_matrix.sh`, which sweeps a 3x3 KEM x signature matrix
  (`ML-KEM-512`/`HQC-1`/`NTRU-HPS-2048-509` x `ML-DSA-44`/`SLH_DSA_PURE_SHA2_128S`/
  `Falcon-512`) and prints a comparison table.

## KEM and signature algorithm choice

The module's default KEM is **NTRU-HPS-2048-509** and
default signature scheme is **Falcon-512**. The main reason for this choice is very small key and signature size, which is most important consideration in bandwidth limited acoustic networks. Both algorithms are at NIST level 1 i.e. about as hard to break as AES-128. If higher security is needed the liboqs library provides variants of these algorithms up to NIST level 5 corresponding to AES-256, but these have bigger key and signature sizes.

Note that these algorithms were selected quite conservatively. New algorithms that are curently evaluated for NIST standartization like HAWK and SQIsign might offer better performance, but are too new and untested to be used in this project.

## Benchmark results

This benchmark compare different KEM and signature schemes. The following table is simplified result of `samples/run_algo_matrix.sh`, which runs `samples/test_uwpqc_algo_matrix.tcl`
for every combination of the 3 supported KEM families and 3 supported signature families
over the two-node acoustic scenario (4800 bps channel, default `retransmitTimeout_`). All
9 combinations completed with 0 retransmissions. Packet/byte counts are totals across
both nodes, sorted by handshake time:

| KEM | Signature | Handshake Time (s) | Total Packets | Total Bytes |
|---|---|---|---|---|
| **NTRU-HPS-2048-509** | **Falcon-512** | **19.71** | **39** | **3470** |
| ML-KEM-512 | Falcon-512 | 20.21 | 40 | 3643 |
| NTRU-HPS-2048-509 | ML-DSA-44 | 46.71 | 93 | 8764 |
| HQC-1 | Falcon-512 | 47.21 | 94 | 8753 |
| ML-KEM-512 | ML-DSA-44 | 47.71 | 95 | 8934 |
| HQC-1 | ML-DSA-44 | 74.21 | 148 | 14040 |
| NTRU-HPS-2048-509 | SLH_DSA_PURE_SHA2_128S | 132.21 | 264 | 25072 |
| ML-KEM-512 | SLH_DSA_PURE_SHA2_128S | 132.71 | 265 | 25242 |
| HQC-1 | SLH_DSA_PURE_SHA2_128S | 159.71 | 319 | 30348 |

The default pair (top row) is both the fastest to complete and require the least ammout of packets. So our selected default algorithms are the most efficient both in theory and in practice.
