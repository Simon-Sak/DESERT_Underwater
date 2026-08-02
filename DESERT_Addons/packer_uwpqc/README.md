# packer_uwpqc

`packer_uwpqc` is a DESERT Underwater packer module that adds post-quantum cryptography support. It integrates the liboqs library that provides the implementation of the post-quantum algorithms.

## What it does

This module provides two main features:

- KEM support for encapsulation and decapsulation
- Signature support for signing and verification

The module also serializes a compact PQC header containing:

- `version_` - 8 bits
- `flags_` - 8 bits
- `ct_len_` - 16 bits
- `sig_len_` - 16 bits

The flags field uses:

- bit 0 for KEM enablement
- bit 1 for signature enablement

## How it works

At startup, the C++ class registers itself with Tcl as `UW/PQC/Packer`.
When a Tcl script creates an object of that class, the constructor:

1. sets the header field widths
2. reads the Tcl configuration flags
3. initializes the default PQC algorithms
4. generates a KEM keypair if KEM is enabled
5. generates a signature keypair if signatures are enabled

The Tcl initialization file `packer-uwpqc-init.tcl` sets the default configuration:

- `debug_ = 0`
- `use_kem_ = 1`
- `use_sig_ = 1`
- `version_bits_ = 8`
- `flags_bits_ = 8`
- `ct_len_bits_ = 16`
- `sig_len_bits_ = 16`

When a packet is packed, the module writes the header fields into the bitstream through the parent `packer` helpers. The `packMyHdr()` method also performs the requested KEM and/or signature operation and records the resulting lengths in the header.

When a packet is unpacked, `unpackMyHdr()` reads back the same header fields and prints them when debugging is enabled.

## Tcl commands

The module exposes the following Tcl commands on a `UW/PQC/Packer` object.

### `kemEncapsulate <plaintext>`
Encapsulates the provided plaintext and returns the ciphertext as a hex string.

### `kemDecapsulate <ciphertext-hex>`
Decapsulates the provided ciphertext hex string and returns the shared secret as a hex string.

### `sigSign <message>`
Signs the provided message and returns the signature as a hex string.

### `sigVerify <message> <signature-hex>`
Verifies a signature and returns `1` for success or `0` for failure.

### `setKemAlgorithm <name>`
Selects a KEM algorithm dynamically.

### `setSigAlgorithm <name>`
Selects a signature algorithm dynamically.

The signature selector accepts common aliases and resolves them to an enabled liboqs algorithm when possible.

## Default algorithm selection

The module tries to pick an enabled algorithm at runtime.

For KEM, it prefers:

1. `NTRU-HRSS-701`
2. `ML-KEM-768`
3. `Kyber768`
4. `Kyber1024`
5. `NTRU-HPS-2048-509`

For signatures, it prefers:

1. `Falcon-1024`
2. `ML-DSA-65`
3. `SLH_DSA_PURE_SHA2_128S`
4. `Falcon-512`
5. `Dilithium3`

## Example usage

A minimal Tcl setup looks like this:

```tcl
load libpackeruwpqc.so
set pqcPacker [new UW/PQC/Packer]

catch {$pqcPacker setKemAlgorithm NTRU-HRSS-701} kemErr
catch {$pqcPacker setSigAlgorithm Falcon-1024} sigErr

set ct [$pqcPacker kemEncapsulate "hello"]
set sig [$pqcPacker sigSign "hello"]
puts "ciphertext = $ct"
puts "signature  = $sig"
puts "verify     = [$pqcPacker sigVerify "hello" $sig]"
```

## Sample application

The sample contains full post-quantum authentication workflow using NTRU and Falcon between two nodes. It can be found in this filder:

- `DESERT_Underwater/DESERT_Framework/DESERT/samples/desert_samples/PQC`

More detailed description of the sample is provided at the top of the sample file.