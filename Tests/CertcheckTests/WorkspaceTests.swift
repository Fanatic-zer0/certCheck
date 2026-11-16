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
        print("PASS: all 6 workspace and decoder tests")
        if let path = ProcessInfo.processInfo.environment["CERTCHECK_DECODER_SAMPLE"] {
            try benchmarkAndRender(path: path)
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
}
#endif
