;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; schnorr.lisp - BIP340 Schnorr signatures for secp256k1
;;;; Sign, verify, batch verify, key tweaking

(in-package #:cl-schnorr)

;;; ============================================================================
;;; Key Generation
;;; ============================================================================

(defun schnorr-keygen ()
  "Generate a new Schnorr keypair.
   Returns (VALUES secret-key public-key) where:
   - secret-key: 32-byte private key
   - public-key: 32-byte x-only public key (BIP340 format)"
  (let* ((sk-int (random-scalar))
         (sk-bytes (integer-to-bytes sk-int 32))
         (pk (jacobian-to-affine (fast-generator-multiply sk-int))))
    ;; BIP340: negate secret key if public key has odd y
    (unless (has-even-y pk)
      (setf sk-int (scalar-neg sk-int))
      (setf sk-bytes (integer-to-bytes sk-int 32))
      (setf pk (make-affine-point :x (ap-x pk)
                                  :y (field-neg (ap-y pk)))))
    (values sk-bytes (serialize-point-xonly pk))))

(defun schnorr-pubkey-from-privkey (secret-key)
  "Derive BIP340 x-only public key from secret key.

   SECRET-KEY: 32-byte private key
   Returns: 32-byte x-only public key"
  (declare (type (simple-array (unsigned-byte 8) (32)) secret-key))
  (let* ((sk-int (bytes-to-integer secret-key))
         (pk (jacobian-to-affine (fast-generator-multiply sk-int))))
    (unless pk
      (error "Invalid secret key"))
    (serialize-point-xonly pk)))

;;; ============================================================================
;;; BIP340 Signing
;;; ============================================================================

(defun schnorr-sign (message secret-key &optional aux-rand)
  "Sign a message using BIP340 Schnorr signature scheme.

   MESSAGE: byte vector to sign (typically 32-byte hash)
   SECRET-KEY: 32-byte private key
   AUX-RAND: Optional 32-byte auxiliary randomness (random if not provided)

   Returns: 64-byte signature (r || s)"
  (declare (type (simple-array (unsigned-byte 8) (*)) message)
           (type (simple-array (unsigned-byte 8) (32)) secret-key))
  ;; Get auxiliary randomness
  (let ((aux (if aux-rand
                 aux-rand
                 (get-random-bytes 32))))
    (declare (type (simple-array (unsigned-byte 8) (32)) aux))

    (let* ((d (bytes-to-integer secret-key))
           ;; Compute public key
           (p-point (jacobian-to-affine (fast-generator-multiply d))))

      (unless p-point
        (error "Invalid secret key"))

      ;; BIP340: negate d if P has odd y
      (unless (has-even-y p-point)
        (setf d (scalar-neg d)))

      (let* ((p-bytes (serialize-point-xonly p-point))
             ;; Compute t = d XOR hash(aux)
             (aux-hash (bip340-aux-hash aux))
             (d-bytes (integer-to-bytes d 32))
             (t-bytes (make-array 32 :element-type '(unsigned-byte 8))))

        ;; XOR d with aux_hash
        (loop for i from 0 below 32
              do (setf (aref t-bytes i)
                       (logxor (aref d-bytes i) (aref aux-hash i))))

        ;; Compute nonce k = hash(t || P || m) mod n
        (let* ((k-hash (bip340-nonce-hash t-bytes p-bytes message))
               (k (mod (bytes-to-integer k-hash) +secp256k1-n+)))

          (when (zerop k)
            (error "Nonce is zero - retry with different aux"))

          ;; Compute R = k*G
          (let ((r-point (jacobian-to-affine (fast-generator-multiply k))))

            ;; BIP340: negate k if R has odd y
            (unless (has-even-y r-point)
              (setf k (scalar-neg k)))

            (let* ((r-bytes (serialize-point-xonly r-point))
                   ;; Compute challenge e = hash(R || P || m) mod n
                   (e-hash (bip340-challenge-hash r-bytes p-bytes message))
                   (e (mod (bytes-to-integer e-hash) +secp256k1-n+))
                   ;; Compute s = k + e*d mod n
                   (s (scalar-add k (scalar-mul e d)))
                   ;; Signature = r || s
                   (sig (make-array 64 :element-type '(unsigned-byte 8))))

              (replace sig r-bytes :start1 0)
              (replace sig (integer-to-bytes s 32) :start1 32)

              ;; Clear sensitive data
              (secure-zero-array d-bytes)
              (secure-zero-array t-bytes)

              sig)))))))

;;; ============================================================================
;;; BIP340 Verification
;;; ============================================================================

(defun schnorr-verify (message public-key signature)
  "Verify a BIP340 Schnorr signature.

   MESSAGE: byte vector that was signed
   PUBLIC-KEY: 32-byte x-only public key
   SIGNATURE: 64-byte signature (r || s)

   Returns: T if valid, NIL if invalid"
  (declare (type (simple-array (unsigned-byte 8) (*)) message)
           (type (simple-array (unsigned-byte 8) (32)) public-key)
           (type (simple-array (unsigned-byte 8) (64)) signature))

  (handler-case
      (let* (;; Extract r and s from signature
             (r-bytes (subseq signature 0 32))
             (s-bytes (subseq signature 32 64))
             (r (bytes-to-integer r-bytes))
             (s (bytes-to-integer s-bytes)))

        ;; Check r < p and s < n
        (unless (and (< r +secp256k1-p+)
                     (< s +secp256k1-n+))
          (return-from schnorr-verify nil))

        ;; Lift x-coordinate to point P
        (let ((p-point (lift-x public-key)))
          (unless p-point
            (return-from schnorr-verify nil))

          ;; Compute challenge e = hash(r || P || m) mod n
          (let* ((e-hash (bip340-challenge-hash r-bytes public-key message))
                 (e (mod (bytes-to-integer e-hash) +secp256k1-n+))
                 ;; Compute R' = s*G - e*P
                 (neg-e (scalar-neg e))
                 (sg (fast-generator-multiply s))
                 (neg-ep (scalar-multiply neg-e (affine-to-jacobian p-point)))
                 (r-prime-jac (jacobian-add sg neg-ep))
                 (r-prime (jacobian-to-affine r-prime-jac)))

            ;; Check R' is not infinity, has even y, and x(R') = r
            (and r-prime
                 (has-even-y r-prime)
                 (= (ap-x r-prime) r)))))
    (error () nil)))

;;; ============================================================================
;;; Batch Verification
;;; ============================================================================

(defun schnorr-batch-verify (items)
  "Batch verify multiple Schnorr signatures.
   Uses random linear combinations for efficiency.

   ITEMS: list of (message public-key signature) tuples

   Returns: T if all valid, NIL if any invalid"
  (declare (type list items))

  (when (null items)
    (return-from schnorr-batch-verify t))

  ;; For single item, use regular verify
  (when (= (length items) 1)
    (let ((item (first items)))
      (return-from schnorr-batch-verify
        (schnorr-verify (first item) (second item) (third item)))))

  (handler-case
      (let ((sum-r (make-jacobian-point :x 0 :y 1 :z 0))
            (sum-sp (make-jacobian-point :x 0 :y 1 :z 0))
            (sum-s 0))

        (dolist (item items)
          (destructuring-bind (message public-key signature) item
            ;; Extract r and s
            (let* ((r-bytes (subseq signature 0 32))
                   (s-bytes (subseq signature 32 64))
                   (r (bytes-to-integer r-bytes))
                   (s (bytes-to-integer s-bytes)))

              ;; Validate bounds
              (unless (and (< r +secp256k1-p+)
                           (< s +secp256k1-n+))
                (return-from schnorr-batch-verify nil))

              ;; Lift R and P
              (let ((r-point (lift-x r-bytes))
                    (p-point (lift-x public-key)))
                (unless (and r-point p-point)
                  (return-from schnorr-batch-verify nil))

                ;; Compute challenge
                (let* ((e-hash (bip340-challenge-hash r-bytes public-key message))
                       (e (mod (bytes-to-integer e-hash) +secp256k1-n+))
                       ;; Random coefficient for linear combination
                       (a (if (eq item (first items))
                              1  ; First item uses a=1
                              (mod (bytes-to-integer (get-random-bytes 16))
                                   +secp256k1-n+))))

                  ;; Accumulate: sum_R += a*R, sum_sP += a*e*P, sum_s += a*s
                  (setf sum-r (jacobian-add sum-r
                                            (scalar-multiply a (affine-to-jacobian r-point))))
                  (setf sum-sp (jacobian-add sum-sp
                                             (scalar-multiply (scalar-mul a e)
                                                              (affine-to-jacobian p-point))))
                  (setf sum-s (scalar-add sum-s (scalar-mul a s))))))))

        ;; Verify: sum_s * G = sum_R + sum_sP
        (let* ((lhs (fast-generator-multiply sum-s))
               (rhs (jacobian-add sum-r sum-sp))
               (lhs-affine (jacobian-to-affine lhs))
               (rhs-affine (jacobian-to-affine rhs)))
          (and lhs-affine
               rhs-affine
               (= (ap-x lhs-affine) (ap-x rhs-affine))
               (= (ap-y lhs-affine) (ap-y rhs-affine)))))
    (error () nil)))

;;; ============================================================================
;;; Key Tweaking (BIP341 Taproot)
;;; ============================================================================

(defun pubkey-tweak-add (pubkey-bytes tweak-bytes)
  "Add tweak to x-only public key (BIP341).
   Returns tweaked x-only public key, or NIL if result is invalid.

   PUBKEY-BYTES: 32-byte x-only public key
   TWEAK-BYTES: 32-byte tweak value"
  (declare (type (simple-array (unsigned-byte 8) (32)) pubkey-bytes tweak-bytes))
  (let ((p-point (lift-x pubkey-bytes))
        (tweak (bytes-to-integer tweak-bytes)))
    (unless p-point
      (return-from pubkey-tweak-add nil))
    (unless (< tweak +secp256k1-n+)
      (return-from pubkey-tweak-add nil))
    ;; Q = P + tweak*G
    (let* ((tweak-g (fast-generator-multiply tweak))
           (q-jac (jacobian-add (affine-to-jacobian p-point) tweak-g))
           (q-point (jacobian-to-affine q-jac)))
      (when q-point
        (serialize-point-xonly q-point)))))

(defun privkey-tweak-add (privkey-bytes tweak-bytes)
  "Add tweak to private key (BIP341).
   Returns tweaked private key, or NIL if result is invalid.

   PRIVKEY-BYTES: 32-byte private key
   TWEAK-BYTES: 32-byte tweak value"
  (declare (type (simple-array (unsigned-byte 8) (32)) privkey-bytes tweak-bytes))
  (let* ((d (bytes-to-integer privkey-bytes))
         (tweak (bytes-to-integer tweak-bytes))
         ;; Check if public key has even y
         (p-point (jacobian-to-affine (fast-generator-multiply d))))
    (unless p-point
      (return-from privkey-tweak-add nil))
    ;; Negate d if P has odd y
    (unless (has-even-y p-point)
      (setf d (scalar-neg d)))
    ;; d' = d + tweak mod n
    (let ((d-prime (scalar-add d tweak)))
      (when (zerop d-prime)
        (return-from privkey-tweak-add nil))
      (integer-to-bytes d-prime 32))))

(defun compute-taproot-tweak (internal-pubkey &optional script-root)
  "Compute Taproot tweak for an internal public key.

   INTERNAL-PUBKEY: 32-byte x-only internal public key
   SCRIPT-ROOT: Optional 32-byte script tree Merkle root

   Returns: 32-byte tweak value"
  (declare (type (simple-array (unsigned-byte 8) (32)) internal-pubkey))
  (taptweak-hash internal-pubkey script-root))

(defun compute-taproot-output-key (internal-pubkey &optional script-root)
  "Compute Taproot output key (Q) from internal key and optional script tree.

   INTERNAL-PUBKEY: 32-byte x-only internal public key
   SCRIPT-ROOT: Optional 32-byte script tree Merkle root

   Returns: 32-byte x-only output public key"
  (declare (type (simple-array (unsigned-byte 8) (32)) internal-pubkey))
  (let ((tweak (compute-taproot-tweak internal-pubkey script-root)))
    (pubkey-tweak-add internal-pubkey tweak)))

;;; ============================================================================
;;; BIP340 Test Vectors
;;; ============================================================================

(defun run-bip340-test-vectors ()
  "Run official BIP340 test vectors. Returns T if all pass."
  (let ((vectors
          ;; (secret-key public-key aux-rand message signature)
          ;; Test vector 0
          '(("0000000000000000000000000000000000000000000000000000000000000003"
             "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
             "0000000000000000000000000000000000000000000000000000000000000000"
             "0000000000000000000000000000000000000000000000000000000000000000"
             "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
            ;; Test vector 1
            ("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
             "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
             "0000000000000000000000000000000000000000000000000000000000000001"
             "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
             "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A")
            ;; Test vector 2
            ("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"
             "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"
             "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906"
             "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"
             "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"))))
    (loop for (sk-hex pk-hex aux-hex msg-hex sig-hex) in vectors
          for i from 0
          do (let* ((sk (hex-to-bytes sk-hex))
                    (pk (hex-to-bytes pk-hex))
                    (aux (hex-to-bytes aux-hex))
                    (msg (hex-to-bytes msg-hex))
                    (expected-sig (hex-to-bytes sig-hex))
                    ;; Test signing
                    (actual-sig (schnorr-sign msg sk aux))
                    ;; Test verification
                    (verify-result (schnorr-verify msg pk expected-sig)))
               (unless (constant-time-bytes= actual-sig expected-sig)
                 (format t "~&Test vector ~D: signature mismatch~%" i)
                 (format t "  Expected: ~A~%" sig-hex)
                 (format t "  Got:      ~A~%" (bytes-to-hex actual-sig))
                 (return-from run-bip340-test-vectors nil))
               (unless verify-result
                 (format t "~&Test vector ~D: verification failed~%" i)
                 (return-from run-bip340-test-vectors nil))))
    t))
