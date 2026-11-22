import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public struct Workspace {
    public let root: URL
    public init(root: URL? = nil) {
        if let root { self.root = root }
        else if let path = ProcessInfo.processInfo.environment["REDAPPLE_HOME"], !path.isEmpty {
            self.root = URL(fileURLWithPath: (path as NSString).expandingTildeInPath, isDirectory: true)
        } else {
            #if os(macOS)
            self.root = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/RedApple", isDirectory: true)
            #else
            self.root = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".redapple", isDirectory: true)
            #endif
        }
    }
    public func url(_ filename: String) -> URL { root.appendingPathComponent(filename) }
    public func load<T: Decodable>(_ type: T.Type, from filename: String) throws -> T? {
        let path = url(filename)
        guard FileManager.default.fileExists(atPath: path.path) else { return nil }
        return try JSON.decoder.decode(type, from: Data(contentsOf: path))
    }
    public func save<T: Encodable>(_ value: T, to filename: String) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let data = try JSON.encoder.encode(value)
        // A unique same-directory temporary file avoids partial reads by other processes.
        let destination = url(filename)
        let temp = root.appendingPathComponent(".\(filename).\(UUID().uuidString).tmp")
        defer { try? fm.removeItem(at: temp) }
        guard fm.createFile(atPath: temp.path, contents: data, attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        // rename is atomic and replaces the old inode without exposing a truncated file.
        guard rename(temp.path, destination.path) == 0 else { throw CocoaError(.fileWriteUnknown) }
    }
    public func loadPatches() throws -> PatchDatabase {
        if let cached = try load(PatchDatabase.self, from: "native-patches.json") { return cached }
        if let web = try load(PatchDatabase.self, from: "releases.json") { return web }
        return try PatchDatabase.bundled()
    }
}

/// App-only triage is separate from engine-owned output and original workbench leads.
public struct LeadTriage: Codable, Equatable {
    public var status: String = "new"
    public var notes: String = ""
    public var updatedAt: String = ""
    public init(status: String = "new", notes: String = "") {
        self.status = status; self.notes = notes
        self.updatedAt = ISO8601DateFormatter().string(from: Date())
    }
}

public enum TriageError: LocalizedError {
    case conflict
    public var errorDescription: String? { "This field changed in another window. Reselect the lead to reload, then apply your edit." }
}

public extension Workspace {
    func saveTriage(id: String, base: LeadTriage, edited: LeadTriage) throws -> [String: LeadTriage] {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let descriptor = open(url(".native-triage.lock").path, O_CREAT | O_RDWR, 0o600)
        guard descriptor >= 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { close(descriptor) }
        guard flock(descriptor, LOCK_EX) == 0 else { throw CocoaError(.fileWriteUnknown) }
        defer { flock(descriptor, LOCK_UN) }
        var saved = try load([String: LeadTriage].self, from: "native-triage.json") ?? [:]
        var current = saved[id] ?? base
        if edited.status != base.status {
            guard current.status == base.status || current.status == edited.status else { throw TriageError.conflict }
            current.status = edited.status
        }
        if edited.notes != base.notes {
            guard current.notes == base.notes || current.notes == edited.notes else { throw TriageError.conflict }
            current.notes = edited.notes
        }
        current.updatedAt = ISO8601DateFormatter().string(from: Date())
        saved[id] = current
        try save(saved, to: "native-triage.json")
        return saved
    }
}

public struct WorkbenchLead: Decodable, Identifiable {
    public var id: String { kind + ":" + target }
    public var kind: String
    public var target: String
    public var status: String
    public var notes: String
    public var updatedAt: String
    public var origin: String?
}
