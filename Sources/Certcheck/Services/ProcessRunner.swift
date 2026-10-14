import Foundation

/// Runs a subprocess while concurrently draining stdout/stderr on background queues.
///
/// Calling `waitUntilExit()` before reading pipe output is a classic deadlock: if the
/// child writes enough output to fill the kernel pipe buffer (~64KB) on a stream nobody
/// is reading yet, the child blocks on write() while the parent blocks in
/// waitUntilExit() — neither side can proceed. From the UI's perspective this looks like
/// a hang/blank screen rather than a crash. Draining both pipes on separate queues while
/// the process runs avoids the deadlock regardless of output size or ordering.
enum ProcessRunner {
    struct Result {
        let exitCode: Int32
        let stdout: Data
        let stderr: Data
    }

    static func run(executable: String, arguments: [String], stdin: Data? = nil) throws -> Result {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        let inPipe: Pipe?
        if stdin != nil {
            let pipe = Pipe()
            process.standardInput = pipe
            inPipe = pipe
        } else {
            inPipe = nil
        }

        try process.run()

        if let stdin = stdin, let inPipe = inPipe {
            try inPipe.fileHandleForWriting.write(contentsOf: stdin)
            try inPipe.fileHandleForWriting.close()
        }

        var stdoutData = Data()
        var stderrData = Data()
        let group = DispatchGroup()

        group.enter()
        DispatchQueue.global(qos: .utility).async {
            stdoutData = outPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            stderrData = errPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }

        process.waitUntilExit()
        group.wait()

        return Result(exitCode: process.terminationStatus, stdout: stdoutData, stderr: stderrData)
    }
}
