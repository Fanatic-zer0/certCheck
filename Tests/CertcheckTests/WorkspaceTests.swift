#if WORKSPACE_CHECK
import Foundation
import SwiftUI

class XCTestCase {}

func XCTAssertEqual<Value: Equatable>(_ actual: Value, _ expected: Value,
                                      file: StaticString = #file, line: UInt = #line) {
    precondition(actual == expected, "Expected \(expected), got \(actual)", file: file, line: line)
}

func XCTAssertNotEqual<Value: Equatable>(_ actual: Value, _ expected: Value,
                                         file: StaticString = #file, line: UInt = #line) {
    precondition(actual != expected, "Expected different values", file: file, line: line)
}

func XCTAssertTrue(_ value: Bool, file: StaticString = #file, line: UInt = #line) {
    precondition(value, "Expected true", file: file, line: line)
}

func XCTAssertNil<Value>(_ value: Value?, file: StaticString = #file, line: UInt = #line) {
    precondition(value == nil, "Expected nil", file: file, line: line)
}
#else
import XCTest
@testable import Certcheck
#endif

final class WorkspaceTests: XCTestCase {
    func testCertificateExtensionCompleteness() {
        let text = """
        Certificate:
            Data:
                Signature Algorithm: sha256WithRSAEncryption
                X509v3 extensions:
                    X509v3 Basic Constraints: critical
                        CA:TRUE, pathlen:1
                    X509v3 Key Usage: critical
                        Certificate Sign, CRL Sign
                    X509v3 Extended Key Usage:
                        TLS Web Server Authentication, TLS Web Client Authentication
                    X509v3 Subject Alternative Name:
                        DNS:a.b.c.d.e.f, DNS:api.example.test, IP Address:127.0.0.1
                    X509v3 Subject Key Identifier:
                        AA:BB:CC:DD
                    X509v3 Authority Key Identifier:
                        keyid:11:22:33:44
                        DirName:/CN=Root CA
                        serial:01:02
                    Authority Information Access:
                        OCSP - URI:http://ocsp.example.test/check
                        CA Issuers - URI:http://ca.example.test/root.crt
                    X509v3 CRL Distribution Points:
                        Full Name:
                          URI:http://ca.example.test/root.crl
                    X509v3 Certificate Policies:
                        Policy: 1.2.3.4
                          CPS: https://ca.example.test/cps
                          User Notice:
                            Explicit Text: Policy terms
                    1.2.3.4.5: critical
                        0000 - 04 04 00 ff 01 02   ......
            Signature Algorithm: sha256WithRSAEncryption
                 aa:bb:cc
        """
        let result = OpenSSLHelper.shared.parseCertificateExtensionsText(text)
        XCTAssertEqual(result.extensions.count, 10)
        XCTAssertEqual(result.sigAlg, "sha256WithRSAEncryption")
        XCTAssertEqual(result.extensions[0].critical, true)
        XCTAssertEqual(result.extensions[0].value, "CA:TRUE, pathlen:1")
        XCTAssertEqual(result.extensions[3].value, "DNS:a.b.c.d.e.f, DNS:api.example.test, IP Address:127.0.0.1")
        XCTAssertEqual(result.san, ["DNS:a.b.c.d.e.f", "DNS:api.example.test", "IP Address:127.0.0.1"])
        XCTAssertEqual(result.extensions[5].value, "keyid:11:22:33:44\nDirName:/CN=Root CA\nserial:01:02")
        XCTAssertEqual(result.extensions[6].value, "OCSP - URI:http://ocsp.example.test/check\nCA Issuers - URI:http://ca.example.test/root.crt")
        XCTAssertEqual(result.extensions[7].value, "Full Name:\n  URI:http://ca.example.test/root.crl")
        XCTAssertEqual(result.extensions[8].value, "Policy: 1.2.3.4\n  CPS: https://ca.example.test/cps\n  User Notice:\n    Explicit Text: Policy terms")
        XCTAssertEqual(result.extensions[9].name, "1.2.3.4.5")
        XCTAssertEqual(result.extensions[9].critical, true)
        XCTAssertEqual(result.extensions[9].value, "0000 - 04 04 00 ff 01 02   ......")
        XCTAssertTrue(OpenSSLHelper.shared.parseCertificateExtensionsText("Signature Algorithm: Ed25519").extensions.isEmpty)
        let edgeCases = OpenSSLHelper.shared.parseCertificateExtensionsText("""
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                URI:https://example.test/a,b, DirName:/CN=Example, Inc/O=QA, DNS:example.test
            1.3.6.1.4.1.11129.2.4.2:
                0000 - 00 ff 01 02   ....
        """)
        XCTAssertEqual(edgeCases.san, ["URI:https://example.test/a,b", "DirName:/CN=Example, Inc/O=QA", "DNS:example.test"])
        XCTAssertEqual(edgeCases.extensions[1].name, "Certificate Transparency SCTs (1.3.6.1.4.1.11129.2.4.2)")
    }

    func testCertificateValidityBoundaries() {
        XCTAssertEqual(CertInfo.CertType.leaf.label, "Leaf (End-Entity)")
        XCTAssertEqual(CertInfo.CertType.intermediateCA.label, "Intermediate CA (Subordinate Authority)")
        XCTAssertEqual(CertInfo.CertType.rootCA.label, "Root CA (Root Authority)")
        let validity = CertificateValidity(notBefore: "2026-01-01T00:00:00Z", notAfter: "2027-01-01T00:00:00.000Z")
        let start = validity.notBefore!
        let end = validity.notAfter!
        let cases: [(Date, CertificateValidity.Status)] = [
            (start.addingTimeInterval(-1), .notYetValid),
            (start, .valid),
            (end.addingTimeInterval(-1), .valid),
            (end, .expired)
        ]
        for (date, expected) in cases {
            XCTAssertEqual(validity.status(at: date), expected)
        }
        XCTAssertEqual(CertificateValidity(notBefore: "bad", notAfter: "bad").status(at: start), .unknown)
        XCTAssertEqual(CertificateValidity(notBefore: "2027-01-01T00:00:00Z", notAfter: "2026-01-01T00:00:00Z").status(at: start), .unknown)
    }

    func testCertificateGenerationRejectsInvalidLifetime() {
        do {
            _ = try CertService.shared.generateCertificate(
                type: .selfSigned,
                subject: CertSubject(cn: "invalid.example.test"),
                keyAlgo: KeyAlgoConfig(),
                validDays: 0,
                caCertPEM: nil,
                caKeyPEM: nil,
                csrPEM: nil
            )
            preconditionFailure("Zero-day certificate lifetime was accepted")
        } catch {
            XCTAssertEqual(error.localizedDescription, "Validity must be a positive whole number of days.")
        }
    }

    func testCSRTextParsing() {
        let output = """
        Certificate Request:
            Subject: CN=csr.example.test, O=Certcheck QA
            Subject Public Key Info:
                Public Key Algorithm: ED25519
                ED25519 Public-Key:
                    pub:
            Attributes:
                Requested Extensions:
                    X509v3 Subject Alternative Name:
                        URI:https://example.test/a,b, DirName:/CN=Example, Inc/O=QA, DNS:api.example.test
                    X509v3 Key Usage: critical
                        Digital Signature, Key Encipherment
            Signature Algorithm: ED25519
        """
        let info = OpenSSLHelper.shared.parseCSRText(output, der: Data([1, 2, 3]), signatureIsValid: true)
        XCTAssertEqual(info.subject.map(\.key), ["CN", "O"])
        XCTAssertEqual(info.subject.map(\.value), ["csr.example.test", "Certcheck QA"])
        XCTAssertEqual(info.publicKey.type, "Ed25519")
        XCTAssertEqual(info.publicKey.bits, 256)
        XCTAssertEqual(info.signatureAlg, "ED25519")
        XCTAssertEqual(info.selfSigValid, true)
        XCTAssertEqual(info.sans, ["URI:https://example.test/a,b", "DirName:/CN=Example, Inc/O=QA", "DNS:api.example.test"])
        XCTAssertEqual(info.extensions.count, 2)
        XCTAssertEqual(info.extensions[0].value, "URI:https://example.test/a,b, DirName:/CN=Example, Inc/O=QA, DNS:api.example.test")
        XCTAssertEqual(info.extensions[1].critical, true)
        XCTAssertEqual(info.extensions[1].value, "Digital Signature, Key Encipherment")
        XCTAssertEqual(info.fingerprints.md5.count, 47)
        XCTAssertEqual(info.fingerprints.sha1.count, 59)
        XCTAssertEqual(info.fingerprints.sha256.count, 95)

        let ec = OpenSSLHelper.shared.parseCSRText("""
        Subject: CN=ec.example.test
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
            Signature Algorithm: ecdsa-with-SHA256
        """, der: Data([4, 5, 6]), signatureIsValid: false)
        XCTAssertEqual(ec.publicKey.type, "EC")
        XCTAssertEqual(ec.publicKey.bits, 256)
        XCTAssertEqual(ec.selfSigValid, false)
    }

    func testIndependentSessionsAndToolSelection() async {
        await MainActor.run {
            let workspace = Workspace()
            let firstID = workspace.selectedID!
            workspace.newSession(for: .certDecode)
            let secondID = workspace.selectedID!
            XCTAssertNotEqual(firstID, secondID)
            XCTAssertEqual(workspace.selectedSession?.title, "Cert Decode")
            workspace.selectTool(.csrDecode)
            workspace.selectTool(.certDecode)
            XCTAssertEqual(workspace.selectedID, secondID)
            XCTAssertEqual(workspace.sessions.count, 3)
            workspace.select(firstID)
            workspace.selectTool(.csrDecode)
            workspace.selectTool(.certDecode)
            XCTAssertEqual(workspace.selectedID, firstID)
        }
    }

    func testClosingSessionsAndReopeningTool() async {
        await MainActor.run {
            let workspace = Workspace()
            let firstID = workspace.selectedID!
            workspace.newSession(for: .certDecode)
            let secondID = workspace.selectedID!
            workspace.close(firstID)
            XCTAssertEqual(workspace.selectedID, secondID)
            workspace.close(secondID)
            XCTAssertTrue(workspace.sessions.isEmpty)
            XCTAssertNil(workspace.selectedID)
            workspace.selectTool(.certDecode)
            XCTAssertEqual(workspace.sessions.count, 1)
            XCTAssertNotEqual(workspace.selectedID, secondID)
        }
    }

    func testRenameReorderAndInvalidActions() async {
        await MainActor.run {
            let workspace = Workspace()
            let firstID = workspace.selectedID!
            workspace.newSession(for: .certDecode)
            let secondID = workspace.selectedID!
            workspace.rename(firstID, title: "  example.com  ")
            workspace.rename(firstID, title: " \n ")
            XCTAssertEqual(workspace.sessions[0].title, "example.com")
            workspace.move(secondID, by: -1)
            XCTAssertEqual(workspace.sessions[0].id, secondID)
            XCTAssertEqual(workspace.selectedID, secondID)
            workspace.move(secondID, by: -1)
            workspace.close(UUID())
            workspace.select(UUID())
            XCTAssertEqual(workspace.sessions.count, 2)
            XCTAssertEqual(workspace.selectedID, secondID)
        }
    }

    func testResourceNamesAndFallbacks() async {
        await MainActor.run {
            let workspace = Workspace()
            let firstID = workspace.selectedID!
            workspace.newSession(for: .certDecode)
            let secondID = workspace.selectedID!
            workspace.updateResourceName(firstID, subject: [("CN", " example.com ")], sans: ["DNS:other.example"])
            XCTAssertEqual(workspace.sessions[0].title, "example.com")
            XCTAssertEqual(workspace.selectedSession?.title, "Cert Decode")
            workspace.updateResourceName(secondID, subject: [("cn", " ")], sans: ["", "DNS:san.example"])
            XCTAssertEqual(workspace.selectedSession?.title, "san.example")
            workspace.updateResourceName(secondID, subject: [], sans: [])
            XCTAssertEqual(workspace.selectedSession?.title, "Cert Decode")
            workspace.rename(secondID, title: "Production")
            workspace.updateResourceName(secondID, subject: [("CN", "new.example")], sans: [])
            XCTAssertEqual(workspace.selectedSession?.title, "Production")
            workspace.close(firstID)
            workspace.updateResourceName(firstID, subject: [("CN", "closed.example")], sans: [])
            XCTAssertEqual(workspace.sessions.count, 1)
        }
    }
}

#if WORKSPACE_CHECK
@main
struct WorkspaceCheck {
    @MainActor
    static func main() async throws {
        let tests = WorkspaceTests()
        await tests.testIndependentSessionsAndToolSelection()
        await tests.testClosingSessionsAndReopeningTool()
        await tests.testRenameReorderAndInvalidActions()
        await tests.testResourceNamesAndFallbacks()
        tests.testCertificateValidityBoundaries()
        tests.testCertificateExtensionCompleteness()
        tests.testCSRTextParsing()
        tests.testCertificateGenerationRejectsInvalidLifetime()
        print("PASS: all 8 workspace and decoder tests")
        if let path = ProcessInfo.processInfo.environment["CERTCHECK_DECODER_SAMPLE"] {
            try benchmarkAndRender(path: path)
        }
        if let paths = ProcessInfo.processInfo.environment["CERTCHECK_CSR_SAMPLES"] {
            try verifyCSRFixtures(paths: paths.split(separator: ":").map(String.init))
        }
        if let paths = ProcessInfo.processInfo.environment["CERTCHECK_CHAIN_SAMPLES"] {
            try verifyChainFixtures(paths: paths.split(separator: ":").map(String.init))
        }
    }

    @MainActor
    private static func benchmarkAndRender(path: String) throws {
        let pem = try String(contentsOfFile: path, encoding: .utf8)
        let info = try CertService.shared.parseCertificate(pem: pem)
        print("Decoded \(info.extensions.count) extensions; \(info.san.count) alternative names")
        XCTAssertNil(info.extensionWarning)
        var samples: [Double] = []
        for _ in 0..<10 {
            let start = ProcessInfo.processInfo.systemUptime
            _ = try CertService.shared.parseCertificate(pem: pem)
            samples.append((ProcessInfo.processInfo.systemUptime - start) * 1_000)
        }
        samples.sort()
        print(String(format: "Decoder: 10 warm parses; median %.1f ms; max %.1f ms", samples[5], samples[9]))
        let validity = CertificateValidity(notBefore: info.notBefore, notAfter: info.notAfter)
        for width in [CGFloat(600), CGFloat(1000)] {
            let content = CertificateResultsView(info: info, validity: validity)
                .padding(20)
                .frame(width: width)
                .background(Color(nsColor: .windowBackgroundColor))
                .environment(\.colorScheme, .light)
            let renderer = ImageRenderer(content: content)
            renderer.scale = 2
            guard let image = renderer.nsImage,
                  let tiff = image.tiffRepresentation,
                  let bitmap = NSBitmapImageRep(data: tiff),
                  let data = bitmap.representation(using: .png, properties: [:]) else {
                throw NSError(domain: "DecoderRender", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "Could not render decoder at width \(width)"])
            }
            let output = URL(fileURLWithPath: ".build/decoder-\(Int(width)).png")
            try data.write(to: output)
            print("Rendered \(output.path)")
        }
    }

    @MainActor
    private static func verifyCSRFixtures(paths: [String]) throws {
        for path in paths {
            let pem = try String(contentsOfFile: path, encoding: .utf8)
            let info = try OpenSSLHelper.shared.parseCSR(pem)
            precondition(info.selfSigValid == true, "Valid CSR signature was not recognized: \(path)")
            precondition(info.fingerprints.md5.count == 47 && info.fingerprints.sha1.count == 59 && info.fingerprints.sha256.count == 95,
                         "CSR fingerprints missing: \(path)")
            print("PASS: \(URL(fileURLWithPath: path).lastPathComponent), \(info.publicKey.type) \(info.publicKey.bits)-bit, \(info.sans.count) SANs")
        }
        if let path = paths.first {
            let original = try String(contentsOfFile: path, encoding: .utf8)
            let payload = original
                .components(separatedBy: .newlines)
                .filter { !$0.hasPrefix("-----") }
                .joined()
            var der = try Data(base64Encoded: payload).unwrap("Could not decode CSR fixture")
            der[der.index(before: der.endIndex)] ^= 1
            let base64 = der.base64EncodedString(options: .lineLength64Characters)
            let tampered = "-----BEGIN CERTIFICATE REQUEST-----\n\(base64)\n-----END CERTIFICATE REQUEST-----\n"
            let info = try OpenSSLHelper.shared.parseCSR(tampered)
            precondition(info.selfSigValid == false, "Tampered CSR signature was accepted")
            print("PASS: tampered CSR signature rejected")
        }
    }

    @MainActor
    private static func verifyChainFixtures(paths: [String]) throws {
        precondition(paths.count == 2, "Expected leaf and root PEM paths")
        let leaf = try String(contentsOfFile: paths[0], encoding: .utf8)
        let root = try String(contentsOfFile: paths[1], encoding: .utf8)
        let links = try CertService.shared.verifyChain(chainPEM: leaf + "\n" + root)
        precondition(links.count == 2 && links.allSatisfy { $0.issuerChainOk && $0.signatureOk == true },
                     "Valid chain was rejected")
        precondition(links.allSatisfy { !$0.notBefore.isEmpty && !$0.notAfter.isEmpty },
                     "Chain validity dates are missing")
        let incomplete = try CertService.shared.verifyChain(chainPEM: leaf)
        precondition(incomplete.count == 1 && !incomplete[0].issuerChainOk,
                     "Incomplete chain was accepted")

        let payload = leaf.components(separatedBy: .newlines)
            .filter { !$0.hasPrefix("-----") }.joined()
        var der = try Data(base64Encoded: payload).unwrap("Could not decode leaf fixture")
        der[der.index(before: der.endIndex)] ^= 1
        let tampered = "-----BEGIN CERTIFICATE-----\n\(der.base64EncodedString(options: .lineLength64Characters))\n-----END CERTIFICATE-----\n"
        let invalid = try CertService.shared.verifyChain(chainPEM: tampered + "\n" + root)
        precondition(invalid.count == 2 && !invalid[0].signatureOk!,
                     "Tampered certificate signature was accepted")
        do {
            _ = try CertService.shared.checkBundleMembership(
                certsPEM: leaf,
                bundlePEM: root + "\n-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"
            )
            preconditionFailure("Invalid bundle certificate was silently ignored")
        } catch {
            print("PASS: invalid bundle certificate reported")
        }
        print("PASS: valid chain, incomplete chain rejection, and invalid leaf signature")
    }
}
#endif

#if WORKSPACE_CHECK
private extension Optional {
    func unwrap(_ message: String) throws -> Wrapped {
        guard let self else {
            throw NSError(domain: "WorkspaceCheck", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: message])
        }
        return self
    }
}
#endif
