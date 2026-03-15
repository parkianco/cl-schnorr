;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause
;;;;
;;;; cl-schnorr.asd - ASDF system definition
;;;; BIP340 Schnorr signatures for secp256k1

(asdf:defsystem #:cl-schnorr
  :description "BIP340 Schnorr signatures for secp256k1 - pure Common Lisp, zero dependencies"
  :author "Park Ian Co"
  :license "Apache-2.0"
  :version "0.1.0"
  :homepage "https://github.com/parkian/cl-schnorr"
  :bug-tracker "https://github.com/parkian/cl-schnorr/issues"

  :depends-on ()  ; No external dependencies

  :serial t
  :components
  ((:file "package")
   (:module "src"
                :components ((:file "package")
                             (:file "conditions" :depends-on ("package"))
                             (:file "types" :depends-on ("package"))
                             (:file "cl-schnorr" :depends-on ("package" "conditions" "types"))))))  ; Sign, verify, key tweaking

  :in-order-to ((asdf:test-op (test-op #:cl-schnorr/test))))

(asdf:defsystem #:cl-schnorr/test
  :description "Tests for cl-schnorr"
  :depends-on (#:cl-schnorr)
  :serial t
  :components
  ((:module "test"
    :components
    ((:file "test-schnorr"))))
  :perform (asdf:test-op (o c)
             (let ((result (uiop:symbol-call :cl-schnorr.test :run-tests)))
               (unless result
                 (error "Tests failed")))))
