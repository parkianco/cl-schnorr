;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-schnorr)

(define-condition cl-schnorr-error (error)
  ((message :initarg :message :reader cl-schnorr-error-message))
  (:report (lambda (condition stream)
             (format stream "cl-schnorr error: ~A" (cl-schnorr-error-message condition)))))
