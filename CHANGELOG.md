# Changelog

All notable changes to ShrouDB Forge are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [v1.5.9] - 2026-04-09

- Version bump release

## [v1.5.8] - 2026-04-09

### Added

- OCSP fuzz tests, event model adaptation, and policy mode config
- adapt to chronicle-core 1.3.0 event model
- runtime-configurable scheduler interval via CONFIG GET/SET (LOW-22)

## [v1.5.6] - 2026-04-04

### Changed

- use shared ServerAuthConfig from shroudb-acl

## [v1.5.5] - 2026-04-02

### Fixed

- use entrypoint script to fix volume mount permissions

### Other

- Add proptest fuzz tests for CA name and X.509 subject validation
- Use check_dispatch_acl for consistent ACL error formatting

## [v1.5.4] - 2026-04-01

### Other

- Add concurrent/failure/expansion tests from ENGINE_REVIEW_v6
- Remove local path patch for shroudb-courier-core — fixes CI

## [v1.5.3] - 2026-04-01

### Other

- Add CourierOps dependency for scheduler notifications
- Make CRL generation atomic with revocation

## [v1.5.2] - 2026-04-01

### Other

- Wire shroudb-server-bootstrap, eliminate startup boilerplate
- Add storage corruption recovery test

## [v1.5.1] - 2026-04-01

### Other

- Migrate client to shroudb-client-common, eliminate ~63 lines of duplication

## [v1.5.0] - 2026-04-01

### Other

- Wire KeepOps into Forge for defense-in-depth PKI key storage

## [v1.4.4] - 2026-04-01

### Other

- Fail-closed audit for all Forge operations
- Arc-wrap CAs, add key retirement with zeroization
- Redact key_material in CaKeyVersion Debug output
- Add AGENTS.md

## [v1.4.3] - 2026-04-01

### Other

- Migrate TCP handler to shroudb-server-tcp, eliminate ~165 lines of duplication (v1.4.3)

## [v1.4.2] - 2026-03-31

### Other

- Add unit tests to forge-core: CA types, cert types, key state, algorithms (v1.4.2)

## [v1.4.1] - 2026-03-31

### Other

- Add edge case tests: max TTL rejected, empty subject, CRL best-effort (v1.4.1)
- Make CRL regeneration best-effort after revocation

## [v1.4.0] - 2026-03-31

### Other

- Wire ChronicleOps audit events into Forge engine (v1.4.0)

## [v1.3.2] - 2026-03-31

### Other

- Connect regenerate_crl command, apply ForgeConfig defaults (v1.3.2)

## [v1.3.1] - 2026-03-31

### Other

- Harden server: expect context on unwraps (v1.3.1)
- Wire actor identity + scheduler graceful shutdown
- Wire optional Sentry ABAC into Forge (v1.2.0)
- Harden Forge v1.1.0: dedup, error handling, CSPRNG safety
- Add README, DOCS, and ABOUT documentation

## [v1.0.0] - 2026-03-29

### Other

- Forge v1: internal certificate authority engine

