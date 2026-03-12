;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; field.lisp - secp256k1 field constants and parameters
;;;; Defines the prime field Fp where p = 2^256 - 2^32 - 977

(in-package #:cl-schnorr)

;;; ============================================================================
;;; Constant Definition Macro
;;; ============================================================================
;;; SBCL's defconstant requires EQL on reload, but bignums are not EQL
;;; across compilation units. This macro uses EQUAL for safe redefinition.

(defmacro define-constant (name value &optional doc)
  "Define a constant, using EQUAL comparison for safe bignum redefinition."
  `(defconstant ,name
     (if (boundp ',name) (symbol-value ',name) ,value)
     ,@(when doc (list doc))))

;;; ============================================================================
;;; secp256k1 Curve Parameters
;;; ============================================================================
;;; Curve equation: y^2 = x^3 + 7 (mod p)
;;; This is a Koblitz curve with a = 0, b = 7

(define-constant +secp256k1-p+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  "secp256k1 field prime: p = 2^256 - 2^32 - 977")

(define-constant +secp256k1-n+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  "secp256k1 curve order (number of points on curve)")

(define-constant +secp256k1-a+ 0
  "secp256k1 curve parameter a (coefficient of x)")

(define-constant +secp256k1-b+ 7
  "secp256k1 curve parameter b (constant term)")

(define-constant +secp256k1-gx+
  #x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  "secp256k1 generator point x-coordinate")

(define-constant +secp256k1-gy+
  #x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
  "secp256k1 generator point y-coordinate")

(define-constant +secp256k1-h+ 1
  "secp256k1 cofactor (number of points / order)")

;;; ============================================================================
;;; GLV Endomorphism Parameters
;;; ============================================================================
;;; secp256k1 has an efficiently computable endomorphism:
;;; lambda * P = (beta * x, y) where lambda^3 = 1 (mod n) and beta^3 = 1 (mod p)
;;; This enables ~2x speedup in scalar multiplication

(define-constant +secp256k1-lambda+
  #x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72
  "GLV endomorphism scalar: lambda^3 = 1 (mod n)")

(define-constant +secp256k1-beta+
  #x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
  "GLV endomorphism field element: beta^3 = 1 (mod p)")

;;; GLV decomposition constants
;;; For scalar k, find k1, k2 such that k*P = k1*P + k2*lambda*P
;;; with |k1|, |k2| ~ sqrt(n)

(define-constant +secp256k1-glv-a1+
  #x3086d221a7d46bcde86c90e49284eb15
  "GLV lattice basis vector a1")

(define-constant +secp256k1-glv-b1+
  #xe4437ed6010e88286f547fa90abfe4c3
  "GLV lattice basis vector b1 (negated)")

(define-constant +secp256k1-glv-a2+
  #x114ca50f7a8e2f3f657c1108d9d44cfd8
  "GLV lattice basis vector a2")

;;; ============================================================================
;;; Field Arithmetic
;;; ============================================================================

(declaim (inline field-add field-sub field-mul field-neg field-inv))

(defun field-add (a b)
  "Add two field elements (mod p)."
  (declare (type integer a b)
           (optimize (speed 3) (safety 0)))
  (mod (+ a b) +secp256k1-p+))

(defun field-sub (a b)
  "Subtract two field elements (mod p)."
  (declare (type integer a b)
           (optimize (speed 3) (safety 0)))
  (mod (- a b) +secp256k1-p+))

(defun field-mul (a b)
  "Multiply two field elements (mod p)."
  (declare (type integer a b)
           (optimize (speed 3) (safety 0)))
  (mod (* a b) +secp256k1-p+))

(defun field-neg (a)
  "Negate a field element (mod p)."
  (declare (type integer a)
           (optimize (speed 3) (safety 0)))
  (if (zerop a) 0 (- +secp256k1-p+ a)))

(defun field-inv (a)
  "Compute multiplicative inverse (mod p) using Fermat's little theorem."
  (declare (type integer a)
           (optimize (speed 3) (safety 1)))
  (when (zerop a)
    (error "Cannot invert zero"))
  (mod-expt a (- +secp256k1-p+ 2) +secp256k1-p+))

(defun field-sqrt (a)
  "Compute square root (mod p). Returns NIL if no root exists.
   For secp256k1, p = 3 (mod 4), so sqrt(a) = a^((p+1)/4) when it exists."
  (declare (type integer a)
           (optimize (speed 3) (safety 1)))
  (let* ((a (mod a +secp256k1-p+))
         ;; p+1 = 2^256 - 2^32 - 976, and (p+1)/4 is computed below
         (exp (ash (1+ +secp256k1-p+) -2))
         (root (mod-expt a exp +secp256k1-p+)))
    ;; Verify: root^2 = a (mod p)
    (if (= (field-mul root root) a)
        root
        nil)))

;;; ============================================================================
;;; Scalar Field Arithmetic (mod n)
;;; ============================================================================

(declaim (inline scalar-add scalar-sub scalar-mul scalar-neg scalar-inv))

(defun scalar-add (a b)
  "Add two scalars (mod n)."
  (declare (type integer a b)
           (optimize (speed 3) (safety 0)))
  (mod (+ a b) +secp256k1-n+))

(defun scalar-sub (a b)
  "Subtract two scalars (mod n)."
  (declare (type integer a b)
           (optimize (speed 3) (safety 0)))
  (mod (- a b) +secp256k1-n+))

(defun scalar-mul (a b)
  "Multiply two scalars (mod n)."
  (declare (type integer a b)
           (optimize (speed 3) (safety 0)))
  (mod (* a b) +secp256k1-n+))

(defun scalar-neg (a)
  "Negate a scalar (mod n)."
  (declare (type integer a)
           (optimize (speed 3) (safety 0)))
  (if (zerop a) 0 (- +secp256k1-n+ a)))

(defun scalar-inv (a)
  "Compute multiplicative inverse (mod n)."
  (declare (type integer a)
           (optimize (speed 3) (safety 1)))
  (when (zerop a)
    (error "Cannot invert zero"))
  (mod-expt a (- +secp256k1-n+ 2) +secp256k1-n+))

;;; ============================================================================
;;; Validation
;;; ============================================================================

(defun valid-field-element-p (x)
  "Check if X is a valid field element (0 <= x < p)."
  (and (integerp x)
       (>= x 0)
       (< x +secp256k1-p+)))

(defun valid-scalar-p (k)
  "Check if K is a valid non-zero scalar (1 <= k < n)."
  (and (integerp k)
       (> k 0)
       (< k +secp256k1-n+)))
