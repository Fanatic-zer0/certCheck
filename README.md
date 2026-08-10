# Certcheck

**Certcheck** is a simple native macOS certificate toolkit — built entirely in Swift.


## Features

### 🔍 Inspect
- **Cert Decode**: Parse and inspect X.509 certificates (subject, issuer, validity, fingerprints, extensions, SANs)
- **CSR Decode**: Decode Certificate Signing Requests with signature verification
- **Key Inspect**: Validate key for the cert

### ✅ Verify
- **Cert ↔ Key**: Verify certificate matches private key
- **Cert ↔ CSR**: Verify certificate was issued from a CSR
- **CSR ↔ Key**: Verify CSR was created with a private key
- **Cert Diff**: View difference between 2 certs
- **Chain Verify**: Validate full certificate chains (leaf → intermediate → root)

### 📚 Stores
- **CA Bundle**: Parse and inspect PEM CA bundles / truststores
- **Keystore**: Inspect JKS, JCEKS, and PKCS#12 (.p12/.pfx) keystores

### 🔐 Generate
- **Generate CSR**: Create Certificate Signing Requests with RSA/ECDSA/Ed25519 keys
- **Generate Cert**: Create self-signed, root CA, intermediate CA, or CA-signed certificates
- **Converter**: Convert Cert from PEM to DER or PKCS#7/ P7B
- **To PFX**: Bundle certificates, keys, and chains into PKCS#12 files

## Screenshot

<img width="1384" height="951" alt="image" src="https://github.com/user-attachments/assets/ba8b121b-2e6a-4a1b-ad7f-985b7b2b92d3" />



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

