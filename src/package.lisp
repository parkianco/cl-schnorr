;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; package.lisp - cl-schnorr package definition
;;;; BIP340 Schnorr signatures for secp256k1

(defpackage #:cl-schnorr
  (:use #:cl)
  (:documentation
   "BIP340 Schnorr signatures for secp256k1.

    A pure Common Lisp implementation with zero external dependencies.
    Suitable for production use in Bitcoin/cryptocurrency applications.

    Main exports:
    - SCHNORR-SIGN: Sign a message with a secret key
    - SCHNORR-VERIFY: Verify a signature
    - SCHNORR-BATCH-VERIFY: Efficiently verify multiple signatures
    - SCHNORR-KEYGEN: Generate a new keypair
    - SCHNORR-PUBKEY-FROM-PRIVKEY: Derive public key from private key

    Taproot (BIP341) support:
    - PUBKEY-TWEAK-ADD: Add tweak to public key
    - PRIVKEY-TWEAK-ADD: Add tweak to private key
    - COMPUTE-TAPROOT-OUTPUT-KEY: Compute Taproot output key

    All operations use constant-time algorithms where security-critical.")

  ;; Main API
  (:export
   #:with-schnorr-timing
   #:schnorr-batch-process
   #:schnorr-health-check;; Signing and verification
   #:schnorr-sign
   #:schnorr-verify
   #:schnorr-batch-verify

   ;; Key generation and derivation
   #:schnorr-keygen
   #:schnorr-pubkey-from-privkey

   ;; Key tweaking (Taproot/BIP341)
   #:pubkey-tweak-add
   #:privkey-tweak-add
   #:compute-taproot-tweak
   #:compute-taproot-output-key

   ;; Tagged hashes (BIP340/BIP341)
   #:tagged-hash
   #:bip340-challenge-hash
   #:bip340-aux-hash
   #:bip340-nonce-hash
   #:taptweak-hash
   #:tapleaf-hash
   #:tapbranch-hash

   ;; Point operations (for advanced use)
   #:lift-x
   #:has-even-y
   #:point-on-curve-p
   #:serialize-point-compressed
   #:serialize-point-xonly
   #:deserialize-point-compressed

   ;; Utilities
   #:sha256
   #:bytes-to-integer
   #:integer-to-bytes
   #:bytes-to-hex
   #:hex-to-bytes
   #:concat-bytes
   #:get-random-bytes
   #:constant-time-bytes=
   #:secure-zero-array
   #:with-secure-array

   ;; Field/curve constants (for advanced use)
   #:+secp256k1-p+
   #:+secp256k1-n+
   #:+secp256k1-gx+
   #:+secp256k1-gy+

   ;; Curve internals (for testing/advanced use)
   #:*secp256k1-generator*
   #:*secp256k1-generator-jacobian*
   #:affine-to-jacobian
   #:jacobian-double
   #:jacobian-to-affine
   #:jacobian-infinity-p
   #:scalar-multiply
   #:ap-x
   #:ap-y

   ;; Testing
   #:run-bip340-test-vectors
   #:*test-mode-prng*
   #:*test-prng-state*))
