import Foundation
import Compression

// Minimal ZIP container support for .odpass bundles: writes "stored" entries,
// reads "stored" and "deflate" entries.
public enum ZipArchive {
  public struct Entry {
    public var path: String
    public var data: Data

    public init(path: String, data: Data) {
      self.path = path
      self.data = data
    }
  }

  // MARK: - Writing

  public static func archive(entries: [Entry]) -> Data {
    var out = Data()
    var central = Data()
    var count: UInt16 = 0

    for entry in entries {
      let nameData = Data(entry.path.utf8)
      let crc = crc32(entry.data)
      let offset = UInt32(out.count)

      out.append(u32(0x04034b50))
      out.append(u16(20))
      out.append(u16(1 << 11)) // UTF-8 names
      out.append(u16(0)) // stored
      out.append(u16(0)); out.append(u16(0)) // time, date
      out.append(u32(crc))
      out.append(u32(UInt32(entry.data.count)))
      out.append(u32(UInt32(entry.data.count)))
      out.append(u16(UInt16(nameData.count)))
      out.append(u16(0))
      out.append(nameData)
      out.append(entry.data)

      central.append(u32(0x02014b50))
      central.append(u16(20)); central.append(u16(20))
      central.append(u16(1 << 11))
      central.append(u16(0))
      central.append(u16(0)); central.append(u16(0))
      central.append(u32(crc))
      central.append(u32(UInt32(entry.data.count)))
      central.append(u32(UInt32(entry.data.count)))
      central.append(u16(UInt16(nameData.count)))
      central.append(u16(0)); central.append(u16(0))
      central.append(u16(0)); central.append(u16(0))
      central.append(u32(0))
      central.append(u32(offset))
      central.append(nameData)
      count += 1
    }

    let centralOffset = UInt32(out.count)
    out.append(central)
    out.append(u32(0x06054b50))
    out.append(u16(0)); out.append(u16(0))
    out.append(u16(count)); out.append(u16(count))
    out.append(u32(UInt32(central.count)))
    out.append(u32(centralOffset))
    out.append(u16(0))
    return out
  }

  // MARK: - Reading

  public static func extract(_ data: Data) -> [String: Data]? {
    guard let eocd = findEndOfCentralDirectory(data) else { return nil }
    let centralOffset = Int(readU32(data, eocd + 16))
    let entryCount = Int(readU16(data, eocd + 10))
    var result: [String: Data] = [:]
    var cursor = centralOffset

    for _ in 0..<entryCount {
      guard cursor + 46 <= data.count, readU32(data, cursor) == 0x02014b50 else { return nil }
      let method = readU16(data, cursor + 10)
      let compressedSize = Int(readU32(data, cursor + 20))
      let uncompressedSize = Int(readU32(data, cursor + 24))
      let nameLength = Int(readU16(data, cursor + 28))
      let extraLength = Int(readU16(data, cursor + 30))
      let commentLength = Int(readU16(data, cursor + 32))
      let localOffset = Int(readU32(data, cursor + 42))
      guard cursor + 46 + nameLength <= data.count else { return nil }
      let name = String(data: data.subdata(in: (cursor + 46)..<(cursor + 46 + nameLength)), encoding: .utf8) ?? ""

      guard localOffset + 30 <= data.count, readU32(data, localOffset) == 0x04034b50 else { return nil }
      let localNameLength = Int(readU16(data, localOffset + 26))
      let localExtraLength = Int(readU16(data, localOffset + 28))
      let dataStart = localOffset + 30 + localNameLength + localExtraLength
      guard dataStart + compressedSize <= data.count else { return nil }
      let raw = data.subdata(in: dataStart..<(dataStart + compressedSize))

      if method == 0 {
        result[name] = raw
      } else if method == 8 {
        guard let inflated = inflate(raw, expectedSize: uncompressedSize) else { return nil }
        result[name] = inflated
      } else {
        return nil
      }
      cursor += 46 + nameLength + extraLength + commentLength
    }
    return result
  }

  private static func findEndOfCentralDirectory(_ data: Data) -> Int? {
    let minEOCD = 22
    guard data.count >= minEOCD else { return nil }
    let searchStart = max(0, data.count - 65_557)
    var i = data.count - minEOCD
    while i >= searchStart {
      if readU32(data, i) == 0x06054b50 { return i }
      i -= 1
    }
    return nil
  }

  private static func inflate(_ data: Data, expectedSize: Int) -> Data? {
    guard expectedSize > 0 else { return Data() }
    let capacity = max(expectedSize, 64)
    let destination = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
    defer { destination.deallocate() }
    let written = data.withUnsafeBytes { (source: UnsafeRawBufferPointer) -> Int in
      guard let base = source.bindMemory(to: UInt8.self).baseAddress else { return 0 }
      return compression_decode_buffer(destination, capacity, base, data.count, nil, COMPRESSION_ZLIB)
    }
    guard written > 0 else { return nil }
    return Data(bytes: destination, count: written)
  }

  // MARK: - Byte helpers

  private static func u16(_ value: UInt16) -> Data {
    withUnsafeBytes(of: value.littleEndian) { Data($0) }
  }

  private static func u32(_ value: UInt32) -> Data {
    withUnsafeBytes(of: value.littleEndian) { Data($0) }
  }

  private static func readU16(_ data: Data, _ offset: Int) -> UInt16 {
    UInt16(data[data.startIndex + offset]) | (UInt16(data[data.startIndex + offset + 1]) << 8)
  }

  private static func readU32(_ data: Data, _ offset: Int) -> UInt32 {
    UInt32(readU16(data, offset)) | (UInt32(readU16(data, offset + 2)) << 16)
  }

  private static let crcTable: [UInt32] = (0..<256).map { i -> UInt32 in
    var c = UInt32(i)
    for _ in 0..<8 {
      c = (c & 1) != 0 ? (0xEDB88320 ^ (c >> 1)) : (c >> 1)
    }
    return c
  }

  public static func crc32(_ data: Data) -> UInt32 {
    var crc: UInt32 = 0xFFFFFFFF
    for byte in data {
      crc = crcTable[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8)
    }
    return crc ^ 0xFFFFFFFF
  }
}
