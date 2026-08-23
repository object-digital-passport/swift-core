import Foundation

/// Minimal Ethereum ABI codec — enough to call and decode the ODP contract.
/// Supports the static and dynamic head/tail encoding for the types the ODP
/// functions use: uint*, bool, address, bytes32 (and fixed bytes), string,
/// dynamic bytes, tuples, and dynamic arrays.
public enum ABI {
  public indirect enum Value: Equatable, Sendable {
    case uint(Data)         // big-endian magnitude, ≤32 bytes (left-padded on encode)
    case bool(Bool)
    case address(String)    // 0x-hex, 20 bytes
    case fixedBytes(Data)   // ≤32 bytes, right-padded on encode
    case string(String)
    case bytes(Data)
    case tuple([Value])
    case array([Value])

    public var isDynamic: Bool {
      switch self {
      case .string, .bytes, .array: return true
      case .tuple(let items): return items.contains { $0.isDynamic }
      default: return false
      }
    }
  }

  // MARK: - Convenience builders

  public static func uint(_ value: UInt64) -> Value { .uint(bigEndian(value)) }
  public static func uint256(_ bytes: Data) -> Value { .uint(bytes) }

  // MARK: - Selector

  /// First 4 bytes of keccak256 of a canonical signature, e.g. "getPassport(string)".
  public static func selector(_ signature: String) -> Data {
    Keccak256.hash(Data(signature.utf8)).prefix(4)
  }

  /// Full calldata: selector ‖ encoded arguments.
  public static func encodeCall(_ signature: String, _ args: [Value]) -> Data {
    var data = Data(selector(signature))
    data.append(encodeTuple(args))
    return data
  }

  // MARK: - Encoding

  public static func encodeTuple(_ values: [Value]) -> Data {
    var headLength = 0
    for v in values { headLength += v.isDynamic ? 32 : encode(v).count }

    var head = Data()
    var tail = Data()
    var offset = headLength
    for v in values {
      if v.isDynamic {
        head.append(leftPad(bigEndian(UInt64(offset))))
        let enc = encode(v)
        tail.append(enc)
        offset += enc.count
      } else {
        head.append(encode(v))
      }
    }
    return head + tail
  }

  private static func encode(_ value: Value) -> Data {
    switch value {
    case .uint(let bytes):
      return leftPad(trim(bytes))
    case .bool(let flag):
      return leftPad(Data([flag ? 1 : 0]))
    case .address(let hex):
      let raw = Data(hexString: hex) ?? Data()
      return leftPad(raw.suffix(20))
    case .fixedBytes(let bytes):
      return rightPad(bytes.prefix(32))
    case .string(let string):
      return encodeBytes(Data(string.utf8))
    case .bytes(let bytes):
      return encodeBytes(bytes)
    case .tuple(let items):
      return encodeTuple(items)
    case .array(let items):
      return leftPad(bigEndian(UInt64(items.count))) + encodeTuple(items)
    }
  }

  private static func encodeBytes(_ bytes: Data) -> Data {
    var out = leftPad(bigEndian(UInt64(bytes.count)))
    out.append(bytes)
    let remainder = bytes.count % 32
    if remainder != 0 { out.append(Data(repeating: 0, count: 32 - remainder)) }
    return out
  }

  // MARK: - Decoding

  /// A shape used only to decode a return value. `Sendable` because it is one:
  /// a tree of cases carrying nothing but more of itself. The `static let`
  /// shapes built from it in `ODPContract`, `ODPPassportEvents` and
  /// `ODPProofRegistry` are read from whatever context decodes an RPC reply,
  /// and without the conformance each of them is a concurrency warning.
  public indirect enum Kind: Sendable {
    case uint, bool, address, bytes32, string, bytes
    case tuple([Kind])
    case array(Kind)

    var isDynamic: Bool {
      switch self {
      case .string, .bytes, .array: return true
      case .tuple(let kinds): return kinds.contains { $0.isDynamic }
      default: return false
      }
    }
  }

  public static func decode(_ kinds: [Kind], from data: Data) -> [Value]? {
    decodeTuple(kinds, data: data, base: 0)
  }

  private static func decodeTuple(_ kinds: [Kind], data: Data, base: Int) -> [Value]? {
    var values = [Value]()
    var headCursor = base
    for kind in kinds {
      if kind.isDynamic {
        guard let offset = word(data, headCursor)?.uint64 else { return nil }
        guard let value = decode(kind, data: data, at: base + Int(offset)) else { return nil }
        values.append(value)
        headCursor += 32
      } else {
        guard let value = decode(kind, data: data, at: headCursor) else { return nil }
        values.append(value)
        headCursor += staticSize(kind)
      }
    }
    return values
  }

  private static func decode(_ kind: Kind, data: Data, at offset: Int) -> Value? {
    switch kind {
    case .uint:
      guard let w = word(data, offset) else { return nil }
      return .uint(trim(w))
    case .bool:
      guard let w = word(data, offset) else { return nil }
      return .bool(w.last == 1)
    case .address:
      guard let w = word(data, offset) else { return nil }
      return .address("0x" + w.suffix(20).hexEncodedString())
    case .bytes32:
      guard let w = word(data, offset) else { return nil }
      return .fixedBytes(w)
    case .string:
      guard let raw = decodeBytes(data, at: offset) else { return nil }
      return .string(String(decoding: raw, as: UTF8.self))
    case .bytes:
      guard let raw = decodeBytes(data, at: offset) else { return nil }
      return .bytes(raw)
    case .tuple(let kinds):
      return decodeTuple(kinds, data: data, base: offset).map { .tuple($0) }
    case .array(let element):
      // The length word is attacker-controlled: it arrives from whichever
      // public RPC endpoint answered. Bound it against the response before
      // converting — `Int(count)` traps above Int.max, and a merely large
      // value would try to allocate that many elements. Every element costs
      // at least one word, so the response length is a safe ceiling.
      guard let count = word(data, offset)?.uint64,
            count <= UInt64(data.count) else { return nil }
      let kinds = Array(repeating: element, count: Int(count))
      return decodeTuple(kinds, data: data, base: offset + 32).map { .array($0) }
    }
  }

  private static func decodeBytes(_ data: Data, at offset: Int) -> Data? {
    // Same untrusted length as in `.array` above.
    guard let length = word(data, offset)?.uint64,
          length <= UInt64(data.count) else { return nil }
    let start = offset + 32
    let end = start + Int(length)
    guard end <= data.count else { return nil }
    return data.subdata(in: start..<end)
  }

  private static func staticSize(_ kind: Kind) -> Int {
    if case .tuple(let kinds) = kind { return kinds.reduce(0) { $0 + staticSize($1) } }
    return 32
  }

  // MARK: - Word / padding helpers

  private static func word(_ data: Data, _ offset: Int) -> Data? {
    guard offset >= 0, offset + 32 <= data.count else { return nil }
    return data.subdata(in: offset..<offset + 32)
  }

  private static func bigEndian(_ value: UInt64) -> Data {
    var v = value.bigEndian
    return withUnsafeBytes(of: &v) { Data($0) }
  }

  private static func trim(_ data: Data) -> Data {
    var bytes = [UInt8](data)
    while bytes.first == 0 && bytes.count > 1 { bytes.removeFirst() }
    return Data(bytes)
  }

  private static func leftPad(_ data: Data, to size: Int = 32) -> Data {
    guard data.count < size else { return data.suffix(size) }
    return Data(repeating: 0, count: size - data.count) + data
  }

  private static func rightPad(_ data: Data, to size: Int = 32) -> Data {
    guard data.count < size else { return data.prefix(size) }
    return data + Data(repeating: 0, count: size - data.count)
  }
}

extension Data {
  /// Interprets the trailing 8 bytes as a big-endian UInt64 (for ABI offsets/lengths).
  public var uint64: UInt64 {
    suffix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
  }
}

// Извлечение значений из декодированного слова. Живёт рядом с самим ABI,
// а не рядом с контрактом: это про формат, а не про конкретный реестр.

extension ABI.Value {
  public var stringValue: String? {
    if case .string(let value) = self { return value }
    return nil
  }

  public var addressValue: String? {
    if case .address(let value) = self { return value }
    return nil
  }

  public var boolValue: Bool? {
    if case .bool(let value) = self { return value }
    return nil
  }

  public var uintValue: UInt64 {
    if case .uint(let bytes) = self { return bytes.uint64 }
    return 0
  }

  /// 0x-prefixed hex for a bytes32 word.
  public var hexValue: String? {
    if case .fixedBytes(let bytes) = self { return "0x" + bytes.hexEncodedString() }
    return nil
  }
}
