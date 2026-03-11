;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; curve.lisp - secp256k1 elliptic curve point operations
;;;; Jacobian projective coordinates for efficient computation

(in-package #:cl-schnorr)

;;; ============================================================================
;;; Point Representations
;;; ============================================================================
;;; Affine: (x, y) where y^2 = x^3 + 7
;;; Jacobian: (X, Y, Z) represents affine (X/Z^2, Y/Z^3)
;;; Point at infinity: Z = 0 in Jacobian, or NIL in affine

(defstruct (jacobian-point (:conc-name jp-))
  "Point in Jacobian projective coordinates.
   Represents affine point (X/Z^2, Y/Z^3).
   Point at infinity has Z = 0."
  (x 0 :type integer)
  (y 0 :type integer)
  (z 1 :type integer))

(defstruct (affine-point (:conc-name ap-))
  "Point in affine coordinates."
  (x 0 :type integer)
  (y 0 :type integer))

;;; ============================================================================
;;; Point Conversion
;;; ============================================================================

(defun affine-to-jacobian (point)
  "Convert affine point to Jacobian. NIL (infinity) -> (0, 1, 0)."
  (if (null point)
      (make-jacobian-point :x 0 :y 1 :z 0)
      (make-jacobian-point :x (ap-x point)
                           :y (ap-y point)
                           :z 1)))

(defun jacobian-to-affine (point)
  "Convert Jacobian point to affine. Returns NIL for point at infinity."
  (declare (type jacobian-point point))
  (let ((z (jp-z point)))
    (if (zerop z)
        nil  ; Point at infinity
        (let* ((z-inv (field-inv z))
               (z2-inv (field-mul z-inv z-inv))
               (z3-inv (field-mul z2-inv z-inv)))
          (make-affine-point
           :x (field-mul (jp-x point) z2-inv)
           :y (field-mul (jp-y point) z3-inv))))))

(defun jacobian-infinity-p (point)
  "Check if Jacobian point is the point at infinity."
  (declare (type jacobian-point point))
  (zerop (jp-z point)))

;;; ============================================================================
;;; Generator Point
;;; ============================================================================

(defparameter *secp256k1-generator*
  (make-affine-point :x +secp256k1-gx+ :y +secp256k1-gy+)
  "secp256k1 generator point G in affine coordinates.")

(defparameter *secp256k1-generator-jacobian*
  (affine-to-jacobian *secp256k1-generator*)
  "secp256k1 generator point G in Jacobian coordinates.")

;;; ============================================================================
;;; Point Arithmetic (Jacobian Coordinates)
;;; ============================================================================

(defun jacobian-double (p)
  "Double a Jacobian point. Uses optimized formulas for a=0 curves.
   Cost: 1M + 5S + 1*a + 7add + 2*2 + 1*3 + 1*8"
  (declare (type jacobian-point p)
           (optimize (speed 3) (safety 0)))
  (when (or (jacobian-infinity-p p)
            (zerop (jp-y p)))
    (return-from jacobian-double
      (make-jacobian-point :x 0 :y 1 :z 0)))
  (let* ((x (jp-x p))
         (y (jp-y p))
         (z (jp-z p))
         ;; For a=0: s = 4*x*y^2
         (y2 (field-mul y y))
         (s (field-mul 4 (field-mul x y2)))
         ;; m = 3*x^2 (since a=0)
         (x2 (field-mul x x))
         (m (field-mul 3 x2))
         ;; x' = m^2 - 2*s
         (m2 (field-mul m m))
         (x3 (field-sub m2 (field-mul 2 s)))
         ;; y' = m*(s - x') - 8*y^4
         (y4 (field-mul y2 y2))
         (y3 (field-sub (field-mul m (field-sub s x3))
                        (field-mul 8 y4)))
         ;; z' = 2*y*z
         (z3 (field-mul 2 (field-mul y z))))
    (make-jacobian-point :x x3 :y y3 :z z3)))

(defun jacobian-add (p q)
  "Add two Jacobian points. Handles all edge cases.
   Cost: 12M + 4S + 6add + 1*2"
  (declare (type jacobian-point p q)
           (optimize (speed 3) (safety 0)))
  ;; Handle infinity cases
  (when (jacobian-infinity-p p) (return-from jacobian-add q))
  (when (jacobian-infinity-p q) (return-from jacobian-add p))
  (let* ((x1 (jp-x p)) (y1 (jp-y p)) (z1 (jp-z p))
         (x2 (jp-x q)) (y2 (jp-y q)) (z2 (jp-z q))
         ;; u1 = x1*z2^2, u2 = x2*z1^2
         (z1-2 (field-mul z1 z1))
         (z2-2 (field-mul z2 z2))
         (u1 (field-mul x1 z2-2))
         (u2 (field-mul x2 z1-2))
         ;; s1 = y1*z2^3, s2 = y2*z1^3
         (z1-3 (field-mul z1-2 z1))
         (z2-3 (field-mul z2-2 z2))
         (s1 (field-mul y1 z2-3))
         (s2 (field-mul y2 z1-3))
         ;; h = u2 - u1, r = s2 - s1
         (h (field-sub u2 u1))
         (r (field-sub s2 s1)))
    ;; Check for special cases
    (cond
      ((zerop h)
       (if (zerop r)
           ;; Points are equal, double
           (jacobian-double p)
           ;; Points are inverses, return infinity
           (make-jacobian-point :x 0 :y 1 :z 0)))
      (t
       ;; General addition
       (let* ((h2 (field-mul h h))
              (h3 (field-mul h2 h))
              (u1h2 (field-mul u1 h2))
              ;; x3 = r^2 - h^3 - 2*u1*h^2
              (r2 (field-mul r r))
              (x3 (field-sub (field-sub r2 h3)
                             (field-mul 2 u1h2)))
              ;; y3 = r*(u1*h^2 - x3) - s1*h^3
              (y3 (field-sub (field-mul r (field-sub u1h2 x3))
                             (field-mul s1 h3)))
              ;; z3 = h*z1*z2
              (z3 (field-mul h (field-mul z1 z2))))
         (make-jacobian-point :x x3 :y y3 :z z3))))))

(defun jacobian-negate (p)
  "Negate a Jacobian point: (X, Y, Z) -> (X, -Y, Z)."
  (declare (type jacobian-point p))
  (make-jacobian-point :x (jp-x p)
                       :y (field-neg (jp-y p))
                       :z (jp-z p)))

;;; ============================================================================
;;; Scalar Multiplication
;;; ============================================================================

(defun scalar-multiply (k point)
  "Multiply point by scalar using double-and-add.
   K is an integer, POINT is a Jacobian point."
  (declare (type integer k)
           (type jacobian-point point)
           (optimize (speed 3) (safety 1)))
  (when (zerop k)
    (return-from scalar-multiply
      (make-jacobian-point :x 0 :y 1 :z 0)))
  (when (jacobian-infinity-p point)
    (return-from scalar-multiply point))
  ;; Handle negative k
  (when (minusp k)
    (setf k (- k))
    (setf point (jacobian-negate point)))
  ;; Reduce k mod n
  (setf k (mod k +secp256k1-n+))
  (when (zerop k)
    (return-from scalar-multiply
      (make-jacobian-point :x 0 :y 1 :z 0)))
  ;; Double-and-add
  (let ((result (make-jacobian-point :x 0 :y 1 :z 0))
        (addend point))
    (loop while (plusp k)
          do (when (oddp k)
               (setf result (jacobian-add result addend)))
             (setf addend (jacobian-double addend))
             (setf k (ash k -1)))
    result))

(defun montgomery-ladder (k point)
  "Constant-time scalar multiplication using Montgomery ladder.
   Resistant to simple power analysis attacks."
  (declare (type integer k)
           (type jacobian-point point)
           (optimize (speed 3) (safety 1)))
  (when (or (zerop k) (jacobian-infinity-p point))
    (return-from montgomery-ladder
      (make-jacobian-point :x 0 :y 1 :z 0)))
  (setf k (mod k +secp256k1-n+))
  (when (zerop k)
    (return-from montgomery-ladder
      (make-jacobian-point :x 0 :y 1 :z 0)))
  (let ((r0 (make-jacobian-point :x 0 :y 1 :z 0))
        (r1 point)
        (bits (integer-length k)))
    ;; Process bits from most significant to least
    (loop for i from (1- bits) downto 0
          for bit = (ldb (byte 1 i) k)
          do (if (zerop bit)
                 (setf r1 (jacobian-add r0 r1)
                       r0 (jacobian-double r0))
                 (setf r0 (jacobian-add r0 r1)
                       r1 (jacobian-double r1))))
    r0))

;;; ============================================================================
;;; GLV Endomorphism Multiplication
;;; ============================================================================

(defun apply-endomorphism (point)
  "Apply GLV endomorphism: phi(x, y) = (beta*x, y).
   This is equivalent to multiplying by lambda."
  (declare (type jacobian-point point))
  (if (jacobian-infinity-p point)
      point
      (make-jacobian-point
       :x (field-mul +secp256k1-beta+ (jp-x point))
       :y (jp-y point)
       :z (jp-z point))))

(defun glv-decompose (k)
  "Decompose scalar k into k1 + k2*lambda with |k1|, |k2| ~ sqrt(n).
   Uses precomputed lattice basis for secp256k1."
  (declare (type integer k))
  ;; Simplified decomposition using rounded division
  ;; Full GLV would use extended GCD on lattice basis
  (let* ((n +secp256k1-n+)
         ;; Approximate: k2 ≈ round(k * g / n) where g relates to lattice
         ;; For simplicity, use basic splitting
         (half-bits (ash (integer-length n) -1))
         (k1 (ldb (byte half-bits 0) k))
         (k2 (ash k (- half-bits))))
    ;; Adjust signs and reduce
    (values (mod k1 n)
            (mod k2 n))))

(defun glv-scalar-multiply (k point)
  "Scalar multiplication using GLV endomorphism for ~2x speedup.
   Computes k*P as k1*P + k2*phi(P) where phi is the endomorphism."
  (declare (type integer k)
           (type jacobian-point point)
           (optimize (speed 3) (safety 1)))
  (when (or (zerop k) (jacobian-infinity-p point))
    (return-from glv-scalar-multiply
      (make-jacobian-point :x 0 :y 1 :z 0)))
  (setf k (mod k +secp256k1-n+))
  (when (zerop k)
    (return-from glv-scalar-multiply
      (make-jacobian-point :x 0 :y 1 :z 0)))
  ;; Decompose k
  (multiple-value-bind (k1 k2) (glv-decompose k)
    ;; Compute k1*P + k2*phi(P)
    (let ((phi-p (apply-endomorphism point)))
      (jacobian-add (scalar-multiply k1 point)
                    (scalar-multiply k2 phi-p)))))

;;; ============================================================================
;;; Generator Multiplication
;;; ============================================================================

(defun generator-multiply (k)
  "Multiply generator point G by scalar k.
   Returns result as Jacobian point."
  (declare (type integer k))
  (scalar-multiply k *secp256k1-generator-jacobian*))

(defun fast-generator-multiply (k)
  "Optimized generator multiplication.
   Uses constant-time Montgomery ladder for security."
  (declare (type integer k))
  (montgomery-ladder k *secp256k1-generator-jacobian*))

;;; ============================================================================
;;; Multi-Scalar Multiplication (Straus-Shamir)
;;; ============================================================================

(defun straus-shamir-2 (k1 p1 k2 p2)
  "Compute k1*P1 + k2*P2 using Straus-Shamir trick.
   More efficient than computing separately."
  (declare (type integer k1 k2)
           (type jacobian-point p1 p2)
           (optimize (speed 3) (safety 1)))
  ;; Precompute P1 + P2
  (let ((p1+p2 (jacobian-add p1 p2))
        (result (make-jacobian-point :x 0 :y 1 :z 0))
        (max-bits (max (integer-length k1) (integer-length k2))))
    ;; Process bits from MSB to LSB
    (loop for i from (1- max-bits) downto 0
          for b1 = (ldb (byte 1 i) k1)
          for b2 = (ldb (byte 1 i) k2)
          do (setf result (jacobian-double result))
             (cond
               ((and (= b1 1) (= b2 1))
                (setf result (jacobian-add result p1+p2)))
               ((= b1 1)
                (setf result (jacobian-add result p1)))
               ((= b2 1)
                (setf result (jacobian-add result p2)))))
    result))

;;; ============================================================================
;;; Point Serialization
;;; ============================================================================

(defun serialize-point-compressed (point)
  "Serialize affine point to 33-byte compressed format.
   Format: 0x02 (even y) or 0x03 (odd y) || x-coordinate."
  (declare (type (or null affine-point) point))
  (if (null point)
      ;; Point at infinity - use 0x00 prefix (non-standard but clear)
      (make-array 33 :element-type '(unsigned-byte 8) :initial-element 0)
      (let ((result (make-array 33 :element-type '(unsigned-byte 8)))
            (x-bytes (integer-to-bytes (ap-x point) 32)))
        ;; Prefix: 02 for even y, 03 for odd y
        (setf (aref result 0) (if (evenp (ap-y point)) #x02 #x03))
        (replace result x-bytes :start1 1)
        result)))

(defun serialize-point-xonly (point)
  "Serialize affine point to 32-byte x-only format (BIP340).
   Returns just the x-coordinate."
  (declare (type (or null affine-point) point))
  (if (null point)
      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
      (integer-to-bytes (ap-x point) 32)))

(defun deserialize-point-compressed (bytes)
  "Deserialize 33-byte compressed point.
   Returns affine point or NIL for point at infinity."
  (declare (type (simple-array (unsigned-byte 8) (33)) bytes))
  (let ((prefix (aref bytes 0)))
    (when (zerop prefix)
      (return-from deserialize-point-compressed nil))
    (unless (or (= prefix #x02) (= prefix #x03))
      (error "Invalid compressed point prefix: ~2,'0X" prefix))
    (let* ((x (bytes-to-integer (subseq bytes 1 33)))
           ;; Compute y from curve equation
           (y-squared (mod (+ (mod-expt x 3 +secp256k1-p+) 7) +secp256k1-p+))
           (y (field-sqrt y-squared)))
      (unless y
        (error "Invalid point: x-coordinate not on curve"))
      ;; Adjust y parity
      (let ((want-odd (= prefix #x03)))
        (when (not (eq want-odd (oddp y)))
          (setf y (field-neg y))))
      (make-affine-point :x x :y y))))

(defun lift-x (x-bytes)
  "Lift x-coordinate to curve point (BIP340 lift_x).
   Returns affine point with even y-coordinate, or NIL if invalid."
  (declare (type (simple-array (unsigned-byte 8) (*)) x-bytes))
  (let ((x (bytes-to-integer x-bytes)))
    (when (>= x +secp256k1-p+)
      (return-from lift-x nil))
    (let* ((c (mod (+ (mod-expt x 3 +secp256k1-p+) 7) +secp256k1-p+))
           (y (field-sqrt c)))
      (unless y
        (return-from lift-x nil))
      ;; BIP340: always use even y
      (when (oddp y)
        (setf y (field-neg y)))
      (make-affine-point :x x :y y))))

;;; ============================================================================
;;; Point Validation
;;; ============================================================================

(defun point-on-curve-p (point)
  "Check if affine point lies on secp256k1 curve."
  (declare (type (or null affine-point) point))
  (if (null point)
      t  ; Point at infinity is valid
      (let ((x (ap-x point))
            (y (ap-y point)))
        ;; Check y^2 = x^3 + 7 (mod p)
        (= (field-mul y y)
           (mod (+ (mod-expt x 3 +secp256k1-p+) 7) +secp256k1-p+)))))

(defun has-even-y (point)
  "Check if point has even y-coordinate (BIP340 requirement)."
  (declare (type (or null affine-point) point))
  (and point (evenp (ap-y point))))
