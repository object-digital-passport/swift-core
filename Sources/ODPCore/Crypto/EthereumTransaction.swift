import Foundation

// A legacy (type-0) Ethereum transaction with EIP-155 replay protection.
// Amounts that can exceed 64 bits (gasPrice, value) are carried as minimal
// big-endian byte strings; counters that comfortably fit use UInt64.
public struct EthereumTransaction {
  public var nonce: UInt64
  public var gasPrice: Data      // big-endian wei, no leading zeros
  public var gasLimit: UInt64
  public var to: Data            // 20-byte recipient, empty for contract creation
  public var value: Data         // big-endian wei, no leading zeros
  public var data: Data
  public var chainId: UInt64

  /// Swift does not synthesise a public memberwise initialiser for a public
  /// struct, and a caller outside this module needs one.
  public init(
    nonce: UInt64,
    gasPrice: Data,
    gasLimit: UInt64,
    to: Data,
    value: Data,
    data: Data,
    chainId: UInt64
  ) {
    self.nonce = nonce
    self.gasPrice = gasPrice
    self.gasLimit = gasLimit
    self.to = to
    self.value = value
    self.data = data
    self.chainId = chainId
  }

  /// EIP-155 signing hash: keccak256(rlp([nonce, gasPrice, gasLimit, to,
  /// value, data, chainId, 0, 0])).
  public func signingHash() -> Data {
    let items: [RLPItem] = fields() + [
      .data(RLP.bigEndian(chainId)),
      .data(Data()),
      .data(Data()),
    ]
    return Keccak256.hash(RLP.encode(.list(items)))
  }

  /// Signs with the given key and returns the raw, broadcast-ready bytes for
  /// eth_sendRawTransaction. Returns nil if signing fails.
  public func signedRawTransaction(privateKey: Data) -> Data? {
    guard let sig = Secp256k1Context.shared.signRecoverable(hash: signingHash(), privateKey: privateKey) else {
      return nil
    }
    let v = UInt64(sig.recid) + chainId * 2 + 35
    let items: [RLPItem] = fields() + [
      .data(RLP.bigEndian(v)),
      .data(trimLeadingZeros(sig.r)),
      .data(trimLeadingZeros(sig.s)),
    ]
    return RLP.encode(.list(items))
  }

  private func fields() -> [RLPItem] {
    [
      .data(RLP.bigEndian(nonce)),
      .data(gasPrice),
      .data(RLP.bigEndian(gasLimit)),
      .data(to),
      .data(value),
      .data(data),
    ]
  }

  private func trimLeadingZeros(_ data: Data) -> Data {
    var bytes = [UInt8](data)
    while bytes.first == 0 { bytes.removeFirst() }
    return Data(bytes)
  }
}
