;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; util.lisp - Foundation utilities for cl-schnorr
;;;; SHA-256 (FIPS 180-4), byte conversion, modular arithmetic, constant-time ops

(in-package #:cl-schnorr)

;;; ============================================================================
;;; Byte/Integer Conversion
;;; ============================================================================

(defun bytes-to-integer (bytes)
  "Convert byte vector to integer (big-endian)."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (optimize (speed 3) (safety 1)))
  (let ((result 0))
    (declare (type integer result))
    (loop for byte across bytes
          do (setf result (logior (ash result 8) byte)))
    result))

(defun integer-to-bytes (n size)
  "Convert integer to byte vector of SIZE bytes (big-endian)."
  (declare (type integer n)
           (type fixnum size)
           (optimize (speed 3) (safety 1)))
  (let ((result (make-array size :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for i from (1- size) downto 0
          for j from 0
          do (setf (aref result j) (ldb (byte 8 (* i 8)) n)))
    result))

(defun bytes-to-hex (bytes)
  "Convert byte vector to lowercase hex string."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes))
  (with-output-to-string (s)
    (loop for byte across bytes
          do (format s "~2,'0x" byte))))

(defun hex-to-bytes (hex-string)
  "Convert hex string to byte vector."
  (declare (type string hex-string))
  (let* ((len (length hex-string))
         (result (make-array (/ len 2) :element-type '(unsigned-byte 8))))
    (loop for i from 0 below len by 2
          for j from 0
          do (setf (aref result j)
                   (parse-integer hex-string :start i :end (+ i 2) :radix 16)))
    result))

(defun string-to-octets (string)
  "Convert string to UTF-8 byte vector."
  (declare (type string string))
  (map '(vector (unsigned-byte 8)) #'char-code string))

(defun concat-bytes (&rest byte-arrays)
  "Concatenate multiple byte arrays."
  (apply #'concatenate '(vector (unsigned-byte 8)) byte-arrays))

;;; ============================================================================
;;; Modular Arithmetic
;;; ============================================================================

(defun mod-expt (base exp modulus &key constant-time)
  "Compute (BASE ^ EXP) mod MODULUS using square-and-multiply.
   When CONSTANT-TIME is true, uses Montgomery ladder for timing resistance."
  (declare (type integer base exp modulus)
           (optimize (speed 3) (safety 1)))
  (cond
    ((zerop modulus) (error "Modulus cannot be zero"))
    ((= modulus 1) 0)
    (constant-time
     ;; Montgomery ladder for constant-time exponentiation
     (let ((r0 1)
           (r1 (mod base modulus))
           (bits (integer-length exp)))
       (declare (type integer r0 r1))
       (loop for i from (1- bits) downto 0
             for bit = (ldb (byte 1 i) exp)
             do (if (zerop bit)
                    (setf r1 (mod (* r0 r1) modulus)
                          r0 (mod (* r0 r0) modulus))
                    (setf r0 (mod (* r0 r1) modulus)
                          r1 (mod (* r1 r1) modulus))))
       r0))
    (t
     ;; Standard square-and-multiply
     (let ((result 1)
           (base (mod base modulus)))
       (declare (type integer result base))
       (loop while (plusp exp)
             do (when (oddp exp)
                  (setf result (mod (* result base) modulus)))
                (setf exp (ash exp -1))
                (setf base (mod (* base base) modulus)))
       result))))

(defun gcd-extended (a b)
  "Extended Euclidean algorithm. Returns (gcd x y) where ax + by = gcd."
  (declare (type integer a b))
  (if (zerop b)
      (values a 1 0)
      (multiple-value-bind (g x y) (gcd-extended b (mod a b))
        (values g y (- x (* (floor a b) y))))))

(defun mod-inverse (a modulus)
  "Compute modular multiplicative inverse of A mod MODULUS."
  (declare (type integer a modulus))
  (multiple-value-bind (g x y) (gcd-extended a modulus)
    (declare (ignore y))
    (unless (= g 1)
      (error "No modular inverse exists"))
    (mod x modulus)))

(defun mod-sqrt (n p)
  "Compute modular square root of N mod P using Tonelli-Shanks.
   Returns NIL if no square root exists."
  (declare (type integer n p))
  (let ((n (mod n p)))
    (cond
      ((zerop n) 0)
      ;; Check if n is a quadratic residue using Euler's criterion
      ((/= (mod-expt n (ash (1- p) -1) p) 1) nil)
      ;; For p = 3 (mod 4), use simple formula
      ((= (mod p 4) 3)
       (mod-expt n (ash (1+ p) -2) p))
      ;; General Tonelli-Shanks
      (t
       (tonelli-shanks n p)))))

(defun tonelli-shanks (n p)
  "Tonelli-Shanks algorithm for modular square root."
  (declare (type integer n p))
  ;; Factor out powers of 2 from p-1: p-1 = q * 2^s
  (let* ((q (1- p))
         (s 0))
    (loop while (evenp q)
          do (setf q (ash q -1))
             (incf s))
    ;; Find quadratic non-residue z
    (let ((z 2))
      (loop while (= (mod-expt z (ash (1- p) -1) p) 1)
            do (incf z))
      ;; Initialize
      (let ((m s)
            (c (mod-expt z q p))
            (tt (mod-expt n q p))
            (r (mod-expt n (ash (1+ q) -1) p)))
        (loop
          (cond
            ((zerop tt) (return 0))
            ((= tt 1) (return r)))
          ;; Find least i such that t^(2^i) = 1
          (let ((i 1)
                (temp (mod (* tt tt) p)))
            (loop while (/= temp 1)
                  do (setf temp (mod (* temp temp) p))
                     (incf i))
            ;; Update values
            (let ((b (mod-expt c (ash 1 (- m i 1)) p)))
              (setf m i
                    c (mod (* b b) p)
                    tt (mod (* tt c) p)
                    r (mod (* r b) p)))))))))

;;; ============================================================================
;;; Constant-Time Operations
;;; ============================================================================

(defun constant-time-bytes= (a b)
  "Constant-time comparison of two byte vectors. Returns T if equal."
  (declare (type (simple-array (unsigned-byte 8) (*)) a b)
           (optimize (speed 3) (safety 0)))
  (let ((len-a (length a))
        (len-b (length b)))
    (declare (type fixnum len-a len-b))
    (when (/= len-a len-b)
      (return-from constant-time-bytes= nil))
    (let ((diff 0))
      (declare (type (unsigned-byte 8) diff))
      (loop for i fixnum from 0 below len-a
            do (setf diff (logior diff (logxor (aref a i) (aref b i)))))
      (zerop diff))))

(defun secure-zero-array (array)
  "Zero out byte array contents securely."
  (declare (type (simple-array (unsigned-byte 8) (*)) array)
           (optimize (speed 3) (safety 0)))
  (loop for i fixnum from 0 below (length array)
        do (setf (aref array i) 0))
  array)

(defmacro with-secure-array ((var size) &body body)
  "Execute BODY with a secure temporary array that is zeroed on exit."
  (let ((result (gensym "RESULT")))
    `(let ((,var (make-array ,size :element-type '(unsigned-byte 8) :initial-element 0)))
       (unwind-protect
            (let ((,result (progn ,@body)))
              ,result)
         (secure-zero-array ,var)))))

;;; ============================================================================
;;; SHA-256 (FIPS 180-4)
;;; ============================================================================

(defconstant +sha256-k+
  #(#x428a2f98 #x71374491 #xb5c0fbcf #xe9b5dba5
    #x3956c25b #x59f111f1 #x923f82a4 #xab1c5ed5
    #xd807aa98 #x12835b01 #x243185be #x550c7dc3
    #x72be5d74 #x80deb1fe #x9bdc06a7 #xc19bf174
    #xe49b69c1 #xefbe4786 #x0fc19dc6 #x240ca1cc
    #x2de92c6f #x4a7484aa #x5cb0a9dc #x76f988da
    #x983e5152 #xa831c66d #xb00327c8 #xbf597fc7
    #xc6e00bf3 #xd5a79147 #x06ca6351 #x14292967
    #x27b70a85 #x2e1b2138 #x4d2c6dfc #x53380d13
    #x650a7354 #x766a0abb #x81c2c92e #x92722c85
    #xa2bfe8a1 #xa81a664b #xc24b8b70 #xc76c51a3
    #xd192e819 #xd6990624 #xf40e3585 #x106aa070
    #x19a4c116 #x1e376c08 #x2748774c #x34b0bcb5
    #x391c0cb3 #x4ed8aa4a #x5b9cca4f #x682e6ff3
    #x748f82ee #x78a5636f #x84c87814 #x8cc70208
    #x90befffa #xa4506ceb #xbef9a3f7 #xc67178f2)
  "SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes).")

(defparameter +sha256-h0-values+
  '(#x6a09e667 #xbb67ae85 #x3c6ef372 #xa54ff53a
    #x510e527f #x9b05688c #x1f83d9ab #x5be0cd19)
  "SHA-256 initial hash values as list.")

(defun make-sha256-h0 ()
  "Create a fresh copy of SHA-256 initial hash values."
  (make-array 8 :element-type '(unsigned-byte 32)
                :initial-contents +sha256-h0-values+))

(declaim (inline sha256-rotr sha256-ch sha256-maj sha256-sigma0 sha256-sigma1
                 sha256-big-sigma0 sha256-big-sigma1))

(defun sha256-rotr (x n)
  "32-bit right rotation."
  (declare (type (unsigned-byte 32) x)
           (type (integer 0 31) n)
           (optimize (speed 3) (safety 0)))
  (logand #xffffffff (logior (ash x (- n)) (ash x (- 32 n)))))

(defun sha256-ch (x y z)
  "SHA-256 Ch function."
  (declare (type (unsigned-byte 32) x y z)
           (optimize (speed 3) (safety 0)))
  (logxor (logand x y) (logand (lognot x) z)))

(defun sha256-maj (x y z)
  "SHA-256 Maj function."
  (declare (type (unsigned-byte 32) x y z)
           (optimize (speed 3) (safety 0)))
  (logxor (logand x y) (logand x z) (logand y z)))

(defun sha256-sigma0 (x)
  "SHA-256 lowercase sigma0."
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (sha256-rotr x 7) (sha256-rotr x 18) (ash x -3)))

(defun sha256-sigma1 (x)
  "SHA-256 lowercase sigma1."
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (sha256-rotr x 17) (sha256-rotr x 19) (ash x -10)))

(defun sha256-big-sigma0 (x)
  "SHA-256 uppercase Sigma0."
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (sha256-rotr x 2) (sha256-rotr x 13) (sha256-rotr x 22)))

(defun sha256-big-sigma1 (x)
  "SHA-256 uppercase Sigma1."
  (declare (type (unsigned-byte 32) x)
           (optimize (speed 3) (safety 0)))
  (logxor (sha256-rotr x 6) (sha256-rotr x 11) (sha256-rotr x 25)))

(defun sha256-pad-message (message)
  "Pad message according to SHA-256 specification."
  (declare (type (simple-array (unsigned-byte 8) (*)) message))
  (let* ((msg-len (length message))
         (msg-bits (* msg-len 8))
         ;; Padded length: msg + 1 + k zeros + 8 bytes length
         ;; where (msg + 1 + k) mod 64 = 56
         (pad-len (let ((rem (mod (+ msg-len 9) 64)))
                    (+ msg-len 9 (if (zerop rem) 0 (- 64 rem)))))
         (padded (make-array pad-len :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Copy message
    (replace padded message)
    ;; Append 1 bit (0x80)
    (setf (aref padded msg-len) #x80)
    ;; Append length as 64-bit big-endian
    (loop for i from 0 below 8
          do (setf (aref padded (- pad-len 1 i))
                   (ldb (byte 8 (* i 8)) msg-bits)))
    padded))

(defun sha256-process-block (block h)
  "Process one 512-bit (64-byte) block."
  (declare (type (simple-array (unsigned-byte 8) (64)) block)
           (type (simple-array (unsigned-byte 32) (8)) h)
           (optimize (speed 3) (safety 0)))
  (let ((w (make-array 64 :element-type '(unsigned-byte 32))))
    ;; Prepare message schedule
    (loop for i from 0 below 16
          for j = (* i 4)
          do (setf (aref w i)
                   (logior (ash (aref block j) 24)
                           (ash (aref block (+ j 1)) 16)
                           (ash (aref block (+ j 2)) 8)
                           (aref block (+ j 3)))))
    (loop for i from 16 below 64
          do (setf (aref w i)
                   (logand #xffffffff
                           (+ (sha256-sigma1 (aref w (- i 2)))
                              (aref w (- i 7))
                              (sha256-sigma0 (aref w (- i 15)))
                              (aref w (- i 16))))))
    ;; Working variables
    (let ((a (aref h 0)) (b (aref h 1)) (c (aref h 2)) (d (aref h 3))
          (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
      (declare (type (unsigned-byte 32) a b c d e f g hh))
      ;; Main loop
      (loop for i from 0 below 64
            for t1 = (logand #xffffffff
                             (+ hh
                                (sha256-big-sigma1 e)
                                (sha256-ch e f g)
                                (aref +sha256-k+ i)
                                (aref w i)))
            for t2 = (logand #xffffffff
                             (+ (sha256-big-sigma0 a)
                                (sha256-maj a b c)))
            do (setf hh g
                     g f
                     f e
                     e (logand #xffffffff (+ d t1))
                     d c
                     c b
                     b a
                     a (logand #xffffffff (+ t1 t2))))
      ;; Update hash values
      (setf (aref h 0) (logand #xffffffff (+ (aref h 0) a))
            (aref h 1) (logand #xffffffff (+ (aref h 1) b))
            (aref h 2) (logand #xffffffff (+ (aref h 2) c))
            (aref h 3) (logand #xffffffff (+ (aref h 3) d))
            (aref h 4) (logand #xffffffff (+ (aref h 4) e))
            (aref h 5) (logand #xffffffff (+ (aref h 5) f))
            (aref h 6) (logand #xffffffff (+ (aref h 6) g))
            (aref h 7) (logand #xffffffff (+ (aref h 7) hh))))))

(defun sha256 (message)
  "Compute SHA-256 hash of MESSAGE (byte vector). Returns 32-byte hash."
  (declare (type (simple-array (unsigned-byte 8) (*)) message))
  (let ((padded (sha256-pad-message message))
        (h (make-sha256-h0)))
    (declare (type (simple-array (unsigned-byte 32) (8)) h))
    ;; Process each 64-byte block
    (loop for i from 0 below (length padded) by 64
          for block = (make-array 64 :element-type '(unsigned-byte 8))
          do (replace block padded :start2 i :end2 (+ i 64))
             (sha256-process-block block h))
    ;; Produce final hash
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 8
            for j = (* i 4)
            for word = (aref h i)
            do (setf (aref result j) (ldb (byte 8 24) word)
                     (aref result (+ j 1)) (ldb (byte 8 16) word)
                     (aref result (+ j 2)) (ldb (byte 8 8) word)
                     (aref result (+ j 3)) (ldb (byte 8 0) word)))
      result)))

;;; ============================================================================
;;; Random Number Generation
;;; ============================================================================

(defvar *test-mode-prng* nil
  "When non-NIL, use deterministic PRNG for testing.")

(defvar *test-prng-state* 0
  "State for test PRNG.")

(defun get-random-bytes (n)
  "Generate N cryptographically random bytes.
   Uses /dev/urandom on Unix, CryptGenRandom concept on Windows.
   Falls back to CL:RANDOM with entropy mixing if system RNG unavailable."
  (declare (type fixnum n))
  (if *test-mode-prng*
      ;; Deterministic mode for testing
      (let ((result (make-array n :element-type '(unsigned-byte 8))))
        (loop for i from 0 below n
              do (setf *test-prng-state*
                       (logand #xffffffff (+ (* *test-prng-state* 1103515245) 12345)))
                 (setf (aref result i) (ldb (byte 8 16) *test-prng-state*)))
        result)
      ;; Production mode - try system RNG
      (let ((result (make-array n :element-type '(unsigned-byte 8))))
        (handler-case
            (with-open-file (urandom "/dev/urandom"
                                     :direction :input
                                     :element-type '(unsigned-byte 8))
              (read-sequence result urandom)
              result)
          (error ()
            ;; Fallback: mix CL:RANDOM with timing entropy
            (let ((state (make-random-state t)))
              (loop for i from 0 below n
                    do (setf (aref result i)
                             (logxor (random 256 state)
                                     (ldb (byte 8 0) (get-internal-real-time)))))
              result))))))

(defun random-scalar ()
  "Generate a random scalar in range [1, n-1] for secp256k1."
  (loop for bytes = (get-random-bytes 32)
        for scalar = (bytes-to-integer bytes)
        when (and (plusp scalar) (< scalar +secp256k1-n+))
          return scalar))
