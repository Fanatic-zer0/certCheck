#if WORKSPACE_CHECK
import Foundation

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
    static func main() async {
        let tests = WorkspaceTests()
        await tests.testIndependentSessionsAndToolSelection()
        await tests.testClosingSessionsAndReopeningTool()
        await tests.testRenameReorderAndInvalidActions()
        await tests.testResourceNamesAndFallbacks()
        print("PASS: all 4 workspace tests")
    }
}
#endif
