;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; cl-schnorr.asd - ASDF system definition
;;;; BIP340 Schnorr signatures for secp256k1

(asdf:defsystem #:cl-schnorr
  :description "BIP340 Schnorr signatures for secp256k1 - pure Common Lisp, zero dependencies"
  :author "Parkian Company LLC"
  :license "BSD-3-Clause"
  :version "1.0.0"
  :homepage "https://github.com/parkian/cl-schnorr"
  :bug-tracker "https://github.com/parkian/cl-schnorr/issues"

  :depends-on ()  ; No external dependencies

  :serial t
  :components
  ((:file "package")
   (:module "src"
    :serial t
    :components
    ((:file "util")        ; SHA256, byte conversion, modular arithmetic
     (:file "field")       ; secp256k1 field constants and operations
     (:file "curve")       ; EC point operations in Jacobian coordinates
     (:file "tagged-hash") ; BIP340/BIP341 tagged hashes
     (:file "schnorr"))))  ; Sign, verify, key tweaking

  :in-order-to ((test-op (test-op #:cl-schnorr/test))))

(asdf:defsystem #:cl-schnorr/test
  :description "Tests for cl-schnorr"
  :depends-on (#:cl-schnorr)
  :serial t
  :components
  ((:module "test"
    :components
    ((:file "test-schnorr"))))
  :perform (test-op (o c)
             (let ((result (uiop:symbol-call :cl-schnorr.test :run-tests)))
               (unless result
                 (error "Tests failed")))))
