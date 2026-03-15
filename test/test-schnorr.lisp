;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; test-schnorr.lisp - Tests for cl-schnorr

(defpackage #:cl-schnorr.test
  (:use #:cl #:cl-schnorr)
  (:export #:run-tests))

(in-package #:cl-schnorr.test)

;;; ============================================================================
;;; Test Framework
;;; ============================================================================

(defvar *test-count* 0)
(defvar *pass-count* 0)
(defvar *fail-count* 0)

(defmacro deftest (name &body body)
  "Define a test case."
  `(defun ,name ()
     (incf *test-count*)
     (handler-case
         (progn ,@body
                (incf *pass-count*)
                (format t "  PASS: ~A~%" ',name))
       (error (e)
         (incf *fail-count*)
         (format t "  FAIL: ~A - ~A~%" ',name e)))))

(defmacro assert-true (form &optional message)
  `(unless ,form
     (error "Assertion failed~@[: ~A~]" ,message)))

(defmacro assert-equal (expected actual &optional message)
  `(unless (equal ,expected ,actual)
     (error "Expected ~S but got ~S~@[: ~A~]" ,expected ,actual ,message)))

(defmacro assert-bytes= (expected actual &optional message)
  `(unless (constant-time-bytes= ,expected ,actual)
     (error "Byte arrays not equal~@[: ~A~]" ,message)))

;;; ============================================================================
;;; SHA-256 Tests
;;; ============================================================================

(deftest test-sha256-empty
  "SHA256 of empty string"
  (let ((hash (sha256 (make-array 0 :element-type '(unsigned-byte 8))))
        (expected (hex-to-bytes
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")))
    (assert-bytes= expected hash)))

(deftest test-sha256-abc
  "SHA256 of 'abc'"
  (let ((hash (sha256 (map '(vector (unsigned-byte 8)) #'char-code "abc")))
        (expected (hex-to-bytes
                   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")))
    (assert-bytes= expected hash)))

(deftest test-sha256-long
  "SHA256 of longer message"
  (let ((hash (sha256 (map '(vector (unsigned-byte 8)) #'char-code
                           "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")))
        (expected (hex-to-bytes
                   "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")))
    (assert-bytes= expected hash)))

;;; ============================================================================
;;; Field Arithmetic Tests
;;; ============================================================================

(deftest test-field-add
  "Field addition mod p"
  (assert-equal 10 (field-add 3 7))
  (assert-equal 0 (field-add +secp256k1-p+ 0))
  (assert-equal 1 (field-add (- +secp256k1-p+ 1) 2)))

(deftest test-field-mul
  "Field multiplication mod p"
  (assert-equal 21 (field-mul 3 7))
  (assert-equal 0 (field-mul +secp256k1-p+ 5)))

(deftest test-field-inv
  "Field multiplicative inverse"
  (let ((a 12345678901234567890))
    (assert-equal 1 (field-mul a (field-inv a)))))

;;; ============================================================================
;;; Curve Operations Tests
;;; ============================================================================

(deftest test-generator-on-curve
  "Generator point is on curve"
  (assert-true (point-on-curve-p *secp256k1-generator*)))

(deftest test-double-generator
  "Doubling generator point"
  (let* ((g-jac (affine-to-jacobian *secp256k1-generator*))
         (g2-jac (jacobian-double g-jac))
         (g2 (jacobian-to-affine g2-jac)))
    (assert-true (point-on-curve-p g2))))

(deftest test-scalar-multiply-order
  "n*G = infinity"
  (let* ((result (scalar-multiply +secp256k1-n+ *secp256k1-generator-jacobian*)))
    (assert-true (jacobian-infinity-p result))))

(deftest test-lift-x-generator
  "lift_x recovers generator"
  (let* ((g-x-bytes (integer-to-bytes +secp256k1-gx+ 32))
         (lifted (lift-x g-x-bytes)))
    (assert-true (not (null lifted)))
    (assert-equal +secp256k1-gx+ (ap-x lifted))
    ;; lift_x returns even y
    (assert-true (evenp (ap-y lifted)))))

;;; ============================================================================
;;; Schnorr Signature Tests
;;; ============================================================================

(deftest test-bip340-vectors
  "Official BIP340 test vectors"
  (assert-true (run-bip340-test-vectors)))

(deftest test-sign-verify-roundtrip
  "Sign and verify roundtrip"
  (let ((*test-mode-prng* t)
        (*test-prng-state* 42))
    (multiple-value-bind (sk pk) (schnorr-keygen)
      (let* ((msg (sha256 (map '(vector (unsigned-byte 8)) #'char-code "test message")))
             (sig (schnorr-sign msg sk)))
        (assert-true (schnorr-verify msg pk sig))))))

(deftest test-verify-wrong-message
  "Verification fails with wrong message"
  (let ((*test-mode-prng* t)
        (*test-prng-state* 123))
    (multiple-value-bind (sk pk) (schnorr-keygen)
      (let* ((msg1 (sha256 (map '(vector (unsigned-byte 8)) #'char-code "message 1")))
             (msg2 (sha256 (map '(vector (unsigned-byte 8)) #'char-code "message 2")))
             (sig (schnorr-sign msg1 sk)))
        (assert-true (not (schnorr-verify msg2 pk sig)))))))

(deftest test-verify-wrong-key
  "Verification fails with wrong key"
  (let ((*test-mode-prng* t))
    (let ((*test-prng-state* 100))
      (multiple-value-bind (sk1 pk1) (schnorr-keygen)
        (declare (ignore pk1))
        (let ((*test-prng-state* 200))
          (multiple-value-bind (sk2 pk2) (schnorr-keygen)
            (declare (ignore sk2))
            (let* ((msg (sha256 (map '(vector (unsigned-byte 8)) #'char-code "test")))
                   (sig (schnorr-sign msg sk1)))
              (assert-true (not (schnorr-verify msg pk2 sig))))))))))

(deftest test-pubkey-derivation
  "Public key derivation consistency"
  (let ((*test-mode-prng* t)
        (*test-prng-state* 999))
    (multiple-value-bind (sk pk) (schnorr-keygen)
      (let ((pk2 (schnorr-pubkey-from-privkey sk)))
        (assert-bytes= pk pk2)))))

;;; ============================================================================
;;; Batch Verification Tests
;;; ============================================================================

(deftest test-batch-verify-empty
  "Batch verify empty list"
  (assert-true (schnorr-batch-verify nil)))

(deftest test-batch-verify-single
  "Batch verify single signature"
  (let ((*test-mode-prng* t)
        (*test-prng-state* 500))
    (multiple-value-bind (sk pk) (schnorr-keygen)
      (let* ((msg (sha256 (map '(vector (unsigned-byte 8)) #'char-code "single")))
             (sig (schnorr-sign msg sk)))
        (assert-true (schnorr-batch-verify (list (list msg pk sig))))))))

(deftest test-batch-verify-multiple
  "Batch verify multiple valid signatures"
  (let ((*test-mode-prng* t)
        (items nil))
    (dotimes (i 3)
      (let ((*test-prng-state* (* i 100)))
        (multiple-value-bind (sk pk) (schnorr-keygen)
          (let* ((msg (sha256 (map '(vector (unsigned-byte 8)) #'char-code
                                   (format nil "message ~D" i))))
                 (sig (schnorr-sign msg sk)))
            (push (list msg pk sig) items)))))
    (assert-true (schnorr-batch-verify items))))

(deftest test-batch-verify-one-invalid
  "Batch verify fails with one invalid"
  (let ((*test-mode-prng* t)
        (items nil))
    ;; Add 2 valid signatures
    (dotimes (i 2)
      (let ((*test-prng-state* (* i 100)))
        (multiple-value-bind (sk pk) (schnorr-keygen)
          (let* ((msg (sha256 (map '(vector (unsigned-byte 8)) #'char-code
                                   (format nil "msg ~D" i))))
                 (sig (schnorr-sign msg sk)))
            (push (list msg pk sig) items)))))
    ;; Add 1 invalid (wrong message)
    (let ((*test-prng-state* 999))
      (multiple-value-bind (sk pk) (schnorr-keygen)
        (let* ((msg1 (sha256 (map '(vector (unsigned-byte 8)) #'char-code "real")))
               (msg2 (sha256 (map '(vector (unsigned-byte 8)) #'char-code "fake")))
               (sig (schnorr-sign msg1 sk)))
          (push (list msg2 pk sig) items))))
    (assert-true (not (schnorr-batch-verify items)))))

;;; ============================================================================
;;; Tagged Hash Tests
;;; ============================================================================

(deftest test-tagged-hash
  "Tagged hash domain separation"
  (let* ((msg (make-array 4 :element-type '(unsigned-byte 8)
                            :initial-contents '(1 2 3 4)))
         (hash1 (tagged-hash "Tag1" msg))
         (hash2 (tagged-hash "Tag2" msg)))
    (assert-true (not (constant-time-bytes= hash1 hash2)))))

;;; ============================================================================
;;; Key Tweaking Tests
;;; ============================================================================

(deftest test-pubkey-tweak-add
  "Public key tweak addition"
  (let ((*test-mode-prng* t)
        (*test-prng-state* 777))
    (multiple-value-bind (sk pk) (schnorr-keygen)
      (declare (ignore sk))
      (let* ((tweak (sha256 (map '(vector (unsigned-byte 8)) #'char-code "tweak")))
             (tweaked (pubkey-tweak-add pk tweak)))
        (assert-true (not (null tweaked)))
        (assert-true (not (constant-time-bytes= pk tweaked)))))))

(deftest test-taproot-output-key
  "Taproot output key computation"
  (let ((*test-mode-prng* t)
        (*test-prng-state* 888))
    (multiple-value-bind (sk pk) (schnorr-keygen)
      (declare (ignore sk))
      (let ((output-key (compute-taproot-output-key pk)))
        (assert-true (not (null output-key)))
        (assert-equal 32 (length output-key))))))

;;; ============================================================================
;;; Utility Tests
;;; ============================================================================

(deftest test-bytes-hex-roundtrip
  "Bytes to hex and back"
  (let ((original #(1 2 255 128 0)))
    (assert-true (equalp original (hex-to-bytes (bytes-to-hex original))))))

(deftest test-integer-bytes-roundtrip
  "Integer to bytes and back"
  (let ((n 12345678901234567890123456789))
    (assert-equal n (bytes-to-integer (integer-to-bytes n 32)))))

(deftest test-constant-time-equal
  "Constant time comparison"
  (let ((a #(1 2 3 4 5))
        (b #(1 2 3 4 5))
        (c #(1 2 3 4 6)))
    (assert-true (constant-time-bytes= a b))
    (assert-true (not (constant-time-bytes= a c)))))

;;; ============================================================================
;;; Test Runner
;;; ============================================================================

(defun run-tests ()
  "Run all tests and report results."
  (setf *test-count* 0
        *pass-count* 0
        *fail-count* 0)
  (format t "~&Running cl-schnorr tests...~%~%")

  ;; SHA-256
  (format t "SHA-256 Tests:~%")
  (test-sha256-empty)
  (test-sha256-abc)
  (test-sha256-long)

  ;; Field arithmetic
  (format t "~%Field Arithmetic Tests:~%")
  (test-field-add)
  (test-field-mul)
  (test-field-inv)

  ;; Curve operations
  (format t "~%Curve Operation Tests:~%")
  (test-generator-on-curve)
  (test-double-generator)
  (test-scalar-multiply-order)
  (test-lift-x-generator)

  ;; Schnorr signatures
  (format t "~%Schnorr Signature Tests:~%")
  (test-bip340-vectors)
  (test-sign-verify-roundtrip)
  (test-verify-wrong-message)
  (test-verify-wrong-key)
  (test-pubkey-derivation)

  ;; Batch verification
  (format t "~%Batch Verification Tests:~%")
  (test-batch-verify-empty)
  (test-batch-verify-single)
  (test-batch-verify-multiple)
  (test-batch-verify-one-invalid)

  ;; Tagged hashes
  (format t "~%Tagged Hash Tests:~%")
  (test-tagged-hash)

  ;; Key tweaking
  (format t "~%Key Tweaking Tests:~%")
  (test-pubkey-tweak-add)
  (test-taproot-output-key)

  ;; Utilities
  (format t "~%Utility Tests:~%")
  (test-bytes-hex-roundtrip)
  (test-integer-bytes-roundtrip)
  (test-constant-time-equal)

  ;; Summary
  (format t "~%========================================~%")
  (format t "Results: ~D/~D passed (~D failed)~%"
          *pass-count* *test-count* *fail-count*)
  (format t "========================================~%")

  (zerop *fail-count*))
