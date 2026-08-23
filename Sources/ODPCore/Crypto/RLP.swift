import Foundation

// Minimal recursive-length-prefix encoder (Ethereum's serialization format).
// Sufficient for encoding legacy transactions as a list of byte strings.
indirect enum RLPItem {
  case data(Data)
  case list([RLPItem])
}

enum RLP {
  static func encode(_ item: RLPItem) -> Data {
    switch item {
    case .data(let value):
      return encodeData(value)
    case .list(let items):
      var body = Data()
      for element in items { body.append(encode(element)) }
      return encodeLength(body.count, offset: 0xc0) + body
    }
  }

  private static func encodeData(_ value: Data) -> Data {
    // A single byte below 0x80 is its own encoding.
    if value.count == 1, value[value.startIndex] < 0x80 { return value }
    return encodeLength(value.count, offset: 0x80) + value
  }

  private static func encodeLength(_ length: Int, offset: UInt8) -> Data {
    if length < 56 { return Data([offset + UInt8(length)]) }
    let lengthBytes = bigEndian(length)
    return Data([offset + 55 + UInt8(lengthBytes.count)]) + lengthBytes
  }

  /// Minimal big-endian byte representation (no leading zero bytes).
  static func bigEndian(_ value: Int) -> Data {
    var v = value
    var bytes: [UInt8] = []
    while v > 0 {
      bytes.insert(UInt8(v & 0xff), at: 0)
      v >>= 8
    }
    return Data(bytes)
  }

  static func bigEndian(_ value: UInt64) -> Data {
    var v = value
    var bytes: [UInt8] = []
    while v > 0 {
      bytes.insert(UInt8(v & 0xff), at: 0)
      v >>= 8
    }
    return Data(bytes)
  }
}
