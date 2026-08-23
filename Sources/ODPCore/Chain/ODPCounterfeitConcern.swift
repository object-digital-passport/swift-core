import Foundation

/// The authenticity concern ("counterfeit flag") one institution raised against
/// a passport. Institutional opinion, not a legal judgement (spec §Counterfeit concerns).
public struct ODPCounterfeitConcernRecord: Equatable {
  public var passportId: String
  public var active: Bool
  public var proverCreatorId: String
  public var reasonHash: String
  public var timestamp: Date?

  /// True when this flag was raised by the given profile — only the raiser may clear it.
  public func isRaised(by creatorId: String) -> Bool {
    !creatorId.isEmpty && proverCreatorId == creatorId
  }
}

/// Read/write interface to `ODPCounterfeitConcern`. Signatures come from
/// `chain/contracts/ODPCounterfeitConcern.sol` in the protocol repository.
///
/// Only `P` and `M` profiles may raise a flag; only the profile that raised it
/// may clear it.
public struct ODPCounterfeitRegistry : Sendable {
  public var rpc: PolygonRPC = ODPChain.rpc
  public var address: String = ODPChain.counterfeitConcern

  /// Значения по умолчанию — боевой реестр; подменяются в тестах
  /// и на другой сети.
  public init(rpc: PolygonRPC = ODPChain.rpc, address: String = ODPChain.counterfeitConcern) {
    self.rpc = rpc
    self.address = address
  }


  // MARK: - Reads

  /// The concern on a passport, or nil when the satellite has no record.
  /// An inactive record comes back with `active == false` and empty fields.
  public func concern(passportId: String) async -> ODPCounterfeitConcernRecord? {
    let call = ABI.encodeCall("getCounterfeitConcern(string)", [.string(passportId)])
    guard let ret = try? await rpc.ethCall(to: address, data: call),
          let f = ABI.decode([.bool, .string, .bytes32, .uint], from: ret),
          f.count >= 4 else { return nil }
    let seconds = f[3].uintValue
    return ODPCounterfeitConcernRecord(
      passportId: passportId,
      active: f[0].boolValue ?? false,
      proverCreatorId: f[1].stringValue ?? "",
      reasonHash: f[2].hexValue ?? "",
      timestamp: seconds > 0 ? Date(timeIntervalSince1970: TimeInterval(seconds)) : nil
    )
  }

  /// Active concerns across a set of passports, in the order given.
  public func activeConcerns(passportIds: [String]) async -> [ODPCounterfeitConcernRecord] {
    var found: [ODPCounterfeitConcernRecord] = []
    for id in passportIds {
      if let record = await concern(passportId: id), record.active { found.append(record) }
    }
    return found
  }

  // MARK: - Writes

  /// `raiseCounterfeitConcern` calldata. The reason itself stays off-chain —
  /// the contract stores only its keccak-256 hash, which must be non-zero.
  public static func raiseCalldata(passportId: String, reason: String) -> Data {
    ABI.encodeCall(
      "raiseCounterfeitConcern(string,bytes32)",
      [.string(passportId), .fixedBytes(reasonHashData(reason))]
    )
  }

  /// `clearCounterfeitConcern` calldata. Reverts unless the caller's profile
  /// raised this flag.
  public static func clearCalldata(passportId: String) -> Data {
    ABI.encodeCall("clearCounterfeitConcern(string)", [.string(passportId)])
  }

  // MARK: - Reason hashing

  /// keccak-256 of the UTF-8 reason text, as stored on chain.
  public static func reasonHash(_ reason: String) -> String {
    "0x" + reasonHashData(reason).hexEncodedString()
  }

  /// True when `reason` is the text behind an on-chain `reasonHash`.
  public static func reason(_ reason: String, matches hash: String) -> Bool {
    let normalized = hash.hasPrefix("0x") ? hash : "0x" + hash
    return reasonHash(reason).caseInsensitiveCompare(normalized) == .orderedSame
  }

  private static func reasonHashData(_ reason: String) -> Data {
    Keccak256.hash(Data(reason.utf8))
  }
}
