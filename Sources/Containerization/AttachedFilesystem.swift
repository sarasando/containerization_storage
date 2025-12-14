//===----------------------------------------------------------------------===//
// Copyright © 2025 Apple Inc. and the Containerization project authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//===----------------------------------------------------------------------===//

import ContainerizationExtras
import ContainerizationOCI

/// A filesystem that was attached and able to be mounted inside the runtime environment.
public struct AttachedFilesystem: Sendable {
    /// The type of the filesystem.
    public var type: String
    /// The path to the filesystem within a sandbox.
    public var source: String
    /// Destination when mounting the filesystem inside a sandbox.
    public var destination: String
    /// The options to use when mounting the filesystem.
    public var options: [String]

    #if os(macOS)
    public init(mount: Mount, allocator: any AddressAllocator<Character>) throws {
        switch mount.type {
        case "virtiofs":
            let name = try hashMountSource(source: mount.source)
            self.source = name
        case "ext4":
            let char = try allocator.allocate()
            self.source = "/dev/vd\(char)"
        default:
            self.source = mount.source
        }
        self.type = mount.type
        self.options = mount.options
        self.destination = mount.destination
    }
    #endif

    public init(type: String, source: String, destination: String, options: [String]) {
        self.type = type
        self.source = source
        self.destination = destination
        self.options = options
    }
}


/// sara
import Foundation
import ContainerizationEXT4

extension AttachedFilesystem {

    static func writableOverlay(
        at url: URL,
        sizeBytes: UInt64
    ) async throws -> AttachedFilesystem {

        FileManager.default.createFile(atPath: url.path, contents: nil)

        let handle = try FileHandle(forWritingTo: url)
        try handle.truncate(atOffset: sizeBytes)
        try handle.close()

        try await EXT4.makeFilesystem(
            image: url,
            label: "container-upper"
        )

        return AttachedFilesystem(
            type: "ext4",
            source: url.path,
            destination: "",
            options: []
        )
    }
}
