;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-schnorr)

;;; Core types for cl-schnorr
(deftype cl-schnorr-id () '(unsigned-byte 64))
(deftype cl-schnorr-status () '(member :ready :active :error :shutdown))
