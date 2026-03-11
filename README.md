# cl-schnorr

BIP340 Schnorr signatures for secp256k1 in pure Common Lisp.

## Features

- **Zero external dependencies** - completely self-contained
- **BIP340 compliant** - passes all official test vectors
- **BIP341 (Taproot) support** - key tweaking for Taproot addresses
- **Batch verification** - efficient verification of multiple signatures
- **Constant-time operations** - resistant to timing side-channel attacks
- **Pure Common Lisp** - portable across implementations (SBCL, CCL, etc.)

## Installation

Clone the repository and load with ASDF:

```lisp
(asdf:load-system :cl-schnorr)
```

Or add to your system's dependencies:

```lisp
:depends-on (#:cl-schnorr)
```

## Usage

### Key Generation

```lisp
(use-package :cl-schnorr)

;; Generate a new keypair
(multiple-value-bind (secret-key public-key) (schnorr-keygen)
  ;; secret-key: 32-byte private key
  ;; public-key: 32-byte x-only public key (BIP340)
  ...)

;; Derive public key from existing private key
(schnorr-pubkey-from-privkey secret-key)
```

### Signing and Verification

```lisp
;; Sign a message (typically a 32-byte hash)
(let ((message (sha256 (string-to-octets "Hello, World!"))))
  (schnorr-sign message secret-key))
;; => 64-byte signature

;; Verify a signature
(schnorr-verify message public-key signature)
;; => T or NIL
```

### Batch Verification

```lisp
;; Verify multiple signatures efficiently
(schnorr-batch-verify
  (list (list message1 pubkey1 sig1)
        (list message2 pubkey2 sig2)
        (list message3 pubkey3 sig3)))
;; => T if all valid, NIL if any invalid
```

### Taproot Key Tweaking (BIP341)

```lisp
;; Compute Taproot output key
(compute-taproot-output-key internal-pubkey)  ; key-path only
(compute-taproot-output-key internal-pubkey script-root)  ; with scripts

;; Tweak keys for signing
(pubkey-tweak-add pubkey tweak)
(privkey-tweak-add privkey tweak)
```

### Tagged Hashes

```lisp
;; BIP340 tagged hash
(tagged-hash "MyApp/context" message-bytes)

;; Pre-optimized BIP340 hashes
(bip340-challenge-hash r-bytes p-bytes message)
(bip340-aux-hash aux-rand)
(bip340-nonce-hash masked-key p-bytes message)

;; BIP341 Taproot hashes
(taptweak-hash pubkey-bytes)
(taptweak-hash pubkey-bytes script-root)
(tapleaf-hash leaf-version script)
(tapbranch-hash left-hash right-hash)
```

## API Reference

### Core Functions

| Function | Description |
|----------|-------------|
| `schnorr-sign` | Sign message with BIP340 Schnorr |
| `schnorr-verify` | Verify BIP340 signature |
| `schnorr-batch-verify` | Batch verify multiple signatures |
| `schnorr-keygen` | Generate new keypair |
| `schnorr-pubkey-from-privkey` | Derive public key |

### Taproot (BIP341)

| Function | Description |
|----------|-------------|
| `pubkey-tweak-add` | Add tweak to public key |
| `privkey-tweak-add` | Add tweak to private key |
| `compute-taproot-tweak` | Compute tweak value |
| `compute-taproot-output-key` | Compute output key Q |

### Utilities

| Function | Description |
|----------|-------------|
| `sha256` | Compute SHA-256 hash |
| `tagged-hash` | BIP340 tagged hash |
| `bytes-to-hex` / `hex-to-bytes` | Hex encoding |
| `bytes-to-integer` / `integer-to-bytes` | Integer encoding |
| `constant-time-bytes=` | Constant-time comparison |

## Testing

```lisp
(asdf:test-system :cl-schnorr)
```

Or run the BIP340 test vectors directly:

```lisp
(cl-schnorr:run-bip340-test-vectors)
```

## Security Considerations

- Private keys are handled with `secure-zero-array` to clear memory
- Signature verification uses constant-time comparison
- Montgomery ladder used for scalar multiplication (timing resistant)
- Nonce generation follows BIP340 spec (deterministic + aux randomness)

## Standards Compliance

- [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) - Schnorr Signatures
- [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) - Taproot
- [SEC 2](https://www.secg.org/sec2-v2.pdf) - secp256k1 curve parameters
- [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) - SHA-256

## License

BSD-3-Clause. See [LICENSE](LICENSE) for details.

## Author

Parkian Company LLC
