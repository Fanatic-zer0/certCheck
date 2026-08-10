# Certcheck

**Certcheck** is a native macOS certificate toolkit — built entirely in Swift

## Features

### 🔍 Inspect
- **Cert Decode**: Parse and inspect X.509 certificates (subject, issuer, validity, fingerprints, extensions, SANs)
- **CSR Decode**: Decode Certificate Signing Requests with signature verification

### ✅ Verify
- **Cert ↔ Key**: Verify certificate matches private key
- **Cert ↔ CSR**: Verify certificate was issued from a CSR
- **CSR ↔ Key**: Verify CSR was created with a private key
- **Chain Verify**: Validate full certificate chains (leaf → intermediate → root)

### 📚 Stores
- **CA Bundle**: Parse and inspect PEM CA bundles / truststores
- **Keystore**: Inspect JKS, JCEKS, and PKCS#12 (.p12/.pfx) keystores

### 🔐 Generate
- **Generate CSR**: Create Certificate Signing Requests with RSA/ECDSA/Ed25519 keys
- **Generate Cert**: Create self-signed, root CA, intermediate CA, or CA-signed certificates
- **To PFX**: Bundle certificates, keys, and chains into PKCS#12 files

## Architecture

```
Certcheck/
├── Package.swift                # Swift Package Manager config
├── Sources/Certcheck/
│   ├── CertcheckApp.swift       # App entry point (@main)
│   ├── ContentView.swift        # Main view + tab routing
│   ├── Models/
│   │   └── Models.swift         # Core data models (CertInfo, TrustEntry, etc.)
│   ├── Services/
│   │   └── CertService.swift    # Certificate crypto operations (Security framework)
│   └── Views/
│       ├── SharedComponents.swift  # Sidebar, FieldRow, ActionButton, etc.
│       ├── InspectViews.swift      # CertDecode, CSRDecode
│       ├── VerifyViews.swift       # CertKey, CertCSR, CSRKey, ChainVerify
│       ├── StoresViews.swift       # CABundle, Keystore
│       └── GenerateViews.swift     # GenCSR, GenCert, ToPFX
```

## Building

```bash
cd Certcheck
swift build
swift run
```

Or open in Xcode:
```bash
open Package.swift
```

## Requirements

- macOS 13.0+ (Ventura)
- Swift 5.9+
- Xcode 15.0+ (for development)


### Features Requiring OpenSSL

Some advanced features are **stubbed** and would require OpenSSL CLI integration (via `Process`) or C interop:

- CSR parsing (ASN.1 structure)
- Private key import (PEM → SecKey)
- Key generation (RSA/EC/Ed25519)
- Certificate signing
- PKCS#12 export with password protection
- JKS/JCEKS keystore parsing

