import Foundation

/// Signs and broadcasts state-changing calls to the ODP registry. Every write
/// path in the app funnels through here so nonce, gas and confirmation
/// handling live in one place.
public struct ODPTransactor : Sendable {
  public var rpc: PolygonRPC = ODPChain.rpc
  public var contract: String = ODPChain.contract

  /// Значения по умолчанию — боевой реестр; подменяются в тестах
  /// и на другой сети.
  public init(rpc: PolygonRPC = ODPChain.rpc, contract: String = ODPChain.contract) {
    self.rpc = rpc
    self.contract = contract
  }


  public enum TxError: LocalizedError {
    case estimateFailed(String)
    case signingFailed
    case broadcastFailed(String)
    case reverted
    case notConfirmed

    public var errorDescription: String? {
      switch self {
      case .estimateFailed(let message): return message
      case .signingFailed: return "signing failed"
      case .broadcastFailed(let message): return message
      case .reverted: return "transaction reverted"
      case .notConfirmed: return "transaction not confirmed in time"
      }
    }
  }

  /// Simulates the call first (so a revert surfaces before spending gas),
  /// then signs and broadcasts it. Returns the transaction hash once mined.
  public func send(calldata: Data, from address: String, privateKey: Data) async throws -> String {
    // eth_estimateGas doubles as a dry run — a revert here costs nothing.
    let estimated: UInt64
    do {
      estimated = try await rpc.estimateGas(from: address, to: contract, data: calldata)
    } catch let error as PolygonRPC.RPCError {
      throw TxError.estimateFailed(Self.describe(error))
    }

    let nonce = try await rpc.transactionCount(address: address)
    let gasPrice = try await rpc.gasPrice()

    let transaction = EthereumTransaction(
      nonce: nonce,
      gasPrice: Self.bump(gasPrice, percent: 25),
      // Headroom over the estimate: the registry's ID generation loops on
      // collision, so actual usage can exceed a lucky-path estimate.
      gasLimit: estimated + estimated / 4 + 30_000,
      to: Data(hexString: contract) ?? Data(),
      value: Data(),
      data: calldata,
      chainId: rpc.chainId
    )

    guard let raw = transaction.signedRawTransaction(privateKey: privateKey) else {
      throw TxError.signingFailed
    }

    let hash: String
    do {
      hash = try await rpc.sendRawTransaction(raw)
    } catch let error as PolygonRPC.RPCError {
      throw TxError.broadcastFailed(Self.describe(error))
    }

    guard let succeeded = try? await rpc.waitForReceipt(hash: hash) else {
      throw TxError.notConfirmed
    }
    guard succeeded else { throw TxError.reverted }
    return hash
  }

  /// Multiplies a minimal big-endian wei quantity by (100 + percent)/100.
  private static func bump(_ wei: Data, percent: UInt64) -> Data {
    var value = [UInt8](wei)
    // Multiply by (100 + percent), then divide by 100, in base-256.
    var carry: UInt64 = 0
    for index in stride(from: value.count - 1, through: 0, by: -1) {
      let product = UInt64(value[index]) * (100 + percent) + carry
      value[index] = UInt8(product & 0xFF)
      carry = product >> 8
    }
    while carry > 0 {
      value.insert(UInt8(carry & 0xFF), at: 0)
      carry >>= 8
    }
    var remainder: UInt64 = 0
    for index in value.indices {
      let current = remainder << 8 | UInt64(value[index])
      value[index] = UInt8(current / 100)
      remainder = current % 100
    }
    while value.first == 0 && value.count > 1 { value.removeFirst() }
    return Data(value)
  }

  public static func describe(_ error: PolygonRPC.RPCError) -> String {
    switch error {
    case .remote(let message): return ODPRevert.describe(message)
    case .transport: return "network unavailable"
    case .decode: return "unexpected response"
    }
  }
}

/// Decodes the registry's single custom error `EC(uint16)` into something a
/// person can act on. Codes come from ObjectDigitalPassport.sol / ODPPassportLib.
public enum ODPRevert {
  public static func describe(_ message: String) -> String {
    guard let code = extractCode(from: message) else { return message }
    return text(for: code) ?? "contract rejected the call (EC \(code))"
  }

  /// EC(uint16) is selector 0x9d62d4fc followed by a 32-byte code word.
  private static func extractCode(from message: String) -> UInt16? {
    guard let range = message.range(of: "9d62d4fc") else { return nil }
    let tail = message[range.upperBound...].prefix(64)
    guard tail.count == 64, let value = UInt64(tail.suffix(8), radix: 16) else { return nil }
    return UInt16(truncatingIfNeeded: value)
  }

  private static func text(for code: UInt16) -> String? {
    switch code {
    case 1: return "monthly mint limit reached for this profile"
    case 2: return "profile ID is not registered on-chain"
    case 3: return "this wallet has no ODP profile yet"
    case 11, 18: return "passport is revoked"
    case 12: return "passport not found on-chain"
    case 17, 19, 26, 98: return "this wallet is not allowed to change that passport"
    case 29: return "a digital object needs a file hash"
    case 30: return "passport data hash is missing"
    case 53: return "this wallet already has a profile"
    case 54: return "profile type must be C, B, P or M"
    case 57, 56: return "only the registry owner may do that"
    case 58: return "the registry is frozen — no new mints"
    case 68: return "mint month must match the current UTC month"
    case 91, 92: return "title must be 1–128 characters"
    case 99, 100: return "author name must be 1–128 characters"
    case 101, 102: return "short description must be 1–256 characters"
    case 93: return "domain must be 128 characters or fewer"
    case 103, 104: return "identification anchors are missing"
    case 105: return "add photo, dimensions, materials and distinguishing features"
    case 106: return "a physical object must not carry a file hash"
    case 107: return "a primary photo is required"
    default: return nil
    }
  }
}
