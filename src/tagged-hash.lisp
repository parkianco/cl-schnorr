;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; tagged-hash.lisp - BIP340/BIP341 tagged hash functions
;;;; Domain separation for Schnorr signatures and Taproot

(in-package #:cl-schnorr)

;;; ============================================================================
;;; Tagged Hash (BIP340)
;;; ============================================================================
;;; BIP340 defines tagged hashes as:
;;; tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
;;;
;;; This provides domain separation, preventing signatures from one
;;; context being valid in another.

(defun tagged-hash (tag message)
  "Compute BIP340 tagged hash.
   tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)

   TAG is a string, MESSAGE is a byte vector."
  (declare (type string tag)
           (type (simple-array (unsigned-byte 8) (*)) message))
  (let ((tag-hash (sha256 (string-to-octets tag))))
    (sha256 (concat-bytes tag-hash tag-hash message))))

;;; ============================================================================
;;; Pre-computed Tag Hashes
;;; ============================================================================
;;; Computing SHA256 of tag strings is constant, so we pre-compute them.
;;; Each tag hash is 32 bytes.

(defparameter +bip340-challenge-tag-hash+
  (sha256 (string-to-octets "BIP0340/challenge"))
  "Pre-computed SHA256 of 'BIP0340/challenge' tag.")

(defparameter +bip340-aux-tag-hash+
  (sha256 (string-to-octets "BIP0340/aux"))
  "Pre-computed SHA256 of 'BIP0340/aux' tag.")

(defparameter +bip340-nonce-tag-hash+
  (sha256 (string-to-octets "BIP0340/nonce"))
  "Pre-computed SHA256 of 'BIP0340/nonce' tag.")

;;; BIP341 (Taproot) tag hashes
(defparameter +taptweak-tag-hash+
  (sha256 (string-to-octets "TapTweak"))
  "Pre-computed SHA256 of 'TapTweak' tag for Taproot key tweaking.")

(defparameter +tapleaf-tag-hash+
  (sha256 (string-to-octets "TapLeaf"))
  "Pre-computed SHA256 of 'TapLeaf' tag for Taproot script leaves.")

(defparameter +tapbranch-tag-hash+
  (sha256 (string-to-octets "TapBranch"))
  "Pre-computed SHA256 of 'TapBranch' tag for Taproot branch hashing.")

(defparameter +tapsighash-tag-hash+
  (sha256 (string-to-octets "TapSighash"))
  "Pre-computed SHA256 of 'TapSighash' tag for Taproot signature hashing.")

;;; ============================================================================
;;; Optimized BIP340 Hash Functions
;;; ============================================================================

(defun bip340-challenge-hash (r-bytes p-bytes message)
  "Compute BIP340 challenge hash: hash(R || P || m).
   Used in signature verification to compute challenge e.

   R-BYTES: 32-byte x-coordinate of R
   P-BYTES: 32-byte x-coordinate of public key
   MESSAGE: message being signed"
  (declare (type (simple-array (unsigned-byte 8) (32)) r-bytes p-bytes)
           (type (simple-array (unsigned-byte 8) (*)) message))
  (sha256 (concat-bytes +bip340-challenge-tag-hash+
                        +bip340-challenge-tag-hash+
                        r-bytes
                        p-bytes
                        message)))

(defun bip340-aux-hash (aux-rand)
  "Compute BIP340 auxiliary randomness hash.
   Used to mask the secret key during nonce generation.

   AUX-RAND: 32 bytes of auxiliary randomness"
  (declare (type (simple-array (unsigned-byte 8) (32)) aux-rand))
  (sha256 (concat-bytes +bip340-aux-tag-hash+
                        +bip340-aux-tag-hash+
                        aux-rand)))

(defun bip340-nonce-hash (masked-key p-bytes message)
  "Compute BIP340 nonce hash.
   Used to derive the nonce k from masked secret key.

   MASKED-KEY: 32-byte masked secret key (d XOR aux_hash)
   P-BYTES: 32-byte x-coordinate of public key
   MESSAGE: message being signed"
  (declare (type (simple-array (unsigned-byte 8) (32)) masked-key p-bytes)
           (type (simple-array (unsigned-byte 8) (*)) message))
  (sha256 (concat-bytes +bip340-nonce-tag-hash+
                        +bip340-nonce-tag-hash+
                        masked-key
                        p-bytes
                        message)))

;;; ============================================================================
;;; BIP341 (Taproot) Hash Functions
;;; ============================================================================

(defun taptweak-hash (pubkey-bytes &optional script-root)
  "Compute Taproot tweak hash.

   PUBKEY-BYTES: 32-byte internal public key x-coordinate
   SCRIPT-ROOT: Optional 32-byte Merkle root of script tree"
  (declare (type (simple-array (unsigned-byte 8) (32)) pubkey-bytes))
  (if script-root
      (sha256 (concat-bytes +taptweak-tag-hash+
                            +taptweak-tag-hash+
                            pubkey-bytes
                            script-root))
      (sha256 (concat-bytes +taptweak-tag-hash+
                            +taptweak-tag-hash+
                            pubkey-bytes))))

(defun tapleaf-hash (leaf-version script)
  "Compute Taproot leaf hash for a script.

   LEAF-VERSION: leaf version byte (usually 0xc0)
   SCRIPT: script bytes"
  (declare (type (unsigned-byte 8) leaf-version)
           (type (simple-array (unsigned-byte 8) (*)) script))
  (sha256 (concat-bytes +tapleaf-tag-hash+
                        +tapleaf-tag-hash+
                        (make-array 1 :element-type '(unsigned-byte 8)
                                      :initial-element leaf-version)
                        script)))

(defun tapbranch-hash (left-hash right-hash)
  "Compute Taproot branch hash from two child hashes.
   Children are sorted lexicographically before hashing.

   LEFT-HASH, RIGHT-HASH: 32-byte child hashes"
  (declare (type (simple-array (unsigned-byte 8) (32)) left-hash right-hash))
  ;; Sort lexicographically
  (let ((sorted (if (bytes-less-p left-hash right-hash)
                    (concat-bytes left-hash right-hash)
                    (concat-bytes right-hash left-hash))))
    (sha256 (concat-bytes +tapbranch-tag-hash+
                          +tapbranch-tag-hash+
                          sorted))))

(defun bytes-less-p (a b)
  "Lexicographic comparison of byte arrays."
  (declare (type (simple-array (unsigned-byte 8) (*)) a b))
  (loop for i from 0 below (min (length a) (length b))
        do (cond
             ((< (aref a i) (aref b i)) (return t))
             ((> (aref a i) (aref b i)) (return nil))))
  (< (length a) (length b)))
