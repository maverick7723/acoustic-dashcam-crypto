# Acoustic Dashcam - Cryptography Module 🛡️

This repository contains the core cryptography and vault management logic (`VaultManager.kt`, `EncryptionHelper.kt`) for the Android application **Acoustic Dashcam: Audio Vault**.

## Why is this public?
Acoustic Dashcam is designed for high-stakes evidentiary recording. We believe security apps should not ask for blind trust. We are open-sourcing our AES-256-GCM encryption pipeline and our PBKDF2 (600,000 iteration) key derivation implementation so security researchers and users can verify that data is handled securely, completely offline, and without developer backdoors.

## Security Highlights
* **Zero-Telemetry:** The app has no network transmission capabilities for audio data.
* **Stateless PBKDF2 Derivation:** Keys are bound to the user's secure hardware enclave and a user-defined Vault PIN. 
* **Forensic Memory Hygiene:** Plaintext PCM buffers and passwords are explicitly zero-filled (`java.util.Arrays.fill(bytes, 0.toByte())`) immediately after IO operations to prevent heap-dump extraction.
* **The "Nuclear Option":** Support for an instant, permanent purge of Android Keystore aliases, rendering all `.vault` files mathematically irrecoverable.

*Note: This repository contains only the core cryptographic logic, not the full proprietary application source code (UI, Billing, App Architecture). We do not accept pull requests at this time.*
