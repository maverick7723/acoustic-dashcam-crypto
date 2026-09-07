# Privacy Policy for Acoustic Dashcam

**Effective Date:** August 20, 2026  
**Status:** Zero-Trust / Offline-First / Open-Source  

Acoustic Dashcam is built from the ground up with a "Privacy by Architecture" philosophy. This app is designed to be a strictly offline, zero-telemetry audio safety and evidence-capture tool.

---

## 1. Zero Data Collection & Zero Telemetry
We do not collect, transmit, store on external servers, or share any user data.

- **Audio Recordings:** All audio captured via the microphone is encrypted in real-time on your device. The developer has zero access to your audio files or encryption keys.
- **Personal Identifiers:** We do not collect names, email addresses, phone numbers, or device IDs.
- **Telemetry & Analytics:** There are no third-party tracking SDKs, advertising frameworks, crash reporters, or analytics tools integrated into this app.

---

## 2. Permissions & On-Device Usage

To function as a reliable background acoustic recorder, the app requests the following Android permissions, used strictly locally on your device:

- **MICROPHONE (`RECORD_AUDIO` & `FOREGROUND_SERVICE_MICROPHONE`):** Used strictly to capture audio in periodic chunks. A persistent status bar notification is always displayed while recording is active.
- **LOCATION (`ACCESS_FINE_LOCATION` & `ACCESS_COARSE_LOCATION`):** If granted, location data is used strictly on-device to geotag your recordings for historical context. Location coordinates never leave your device.
- **NOTIFICATIONS (`POST_NOTIFICATIONS`):** Used to display required active foreground recording status and security alerts.
- **INTERNET (`INTERNET`):** Required exclusively by Android system APIs for local Google Identity credential verification to derive your encryption salt. No audio data, logs, or personal information are transmitted.

---

## 3. Local Encryption & Security
The app utilizes industry-standard **AES-256-GCM** hardware-backed encryption to secure all recordings at rest.

- **Hardware Keystore & Master PIN:** Encryption keys are generated locally via the Android KeyStore hardware enclave or derived locally from your Master Vault PIN.
- **Google Identity:** Google Credential Manager is used strictly on-device to retrieve a unique Subject ID. This ID acts as a local cryptographic salt for your Master Key and is never transmitted to our servers or any third party.
- **Screenshot & Thumbnail Protection:** Screenshots, screen recording, and task-switcher thumbnail previews are strictly blocked inside the app via Android `FLAG_SECURE`.

---

## 4. Data Sovereignty & Storage
Your data stays entirely on your device.

- **Local Storage:** Encrypted files are stored in your app's private sandbox or your chosen local directory via the Storage Access Framework (`Documents/AcousticDashcam_Vault`).
- **No Cloud Backups:** We do not provide or support cloud storage. If you delete the app or lose your device, your recordings cannot be recovered by the developer.

---

## 5. User Control & Data Deletion
You maintain complete sovereignty over your data:

- **Manual Deletion:** You can permanently delete individual recordings at any time.
- **Panic Button (Nuclear Wipe):** The app includes a "Hold to Nuke" Panic Button feature that permanently purges all hardware encryption keys and local files, rendering existing recordings mathematically unrecoverable.

---

## 6. Children's Privacy (COPPA Compliance)
Acoustic Dashcam is intended for adult users aged 18 and older due to legal requirements surrounding audio recording consent laws. We do not knowingly collect or solicit data from children under 13.

---

## 7. Open-Source Verification
To ensure full transparency and auditability, Acoustic Dashcam's source code is publicly available. Anyone can verify our zero-knowledge claims and security architecture on GitHub:
https://github.com/chaudharygaurav3-cmyk/Maan-Recorder

---

## 8. Contact & Support
Because Acoustic Dashcam is a zero-knowledge offline application, we cannot identify you or access your data. For technical inquiries or support, contact the developer at:

**Developer Email:** chaudharygaurav3@gmail.com  
**GitHub Repository:** https://github.com/chaudharygaurav3-cmyk/Maan-Recorder
