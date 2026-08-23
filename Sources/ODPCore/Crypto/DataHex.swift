import Foundation

extension Data {
  public func hexEncodedString() -> String {
    map { String(format: "%02x", $0) }.joined()
  }

  public init?(hexString: String) {
    var hex = hexString
    if hex.hasPrefix("0x") { hex = String(hex.dropFirst(2)) }
    guard hex.count % 2 == 0 else { return nil }
    var bytes = [UInt8]()
    bytes.reserveCapacity(hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    self = Data(bytes)
  }
}
