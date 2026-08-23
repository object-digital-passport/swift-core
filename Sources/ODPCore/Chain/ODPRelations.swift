import Foundation

/// One-level affiliation between two `P` institutions: a child proposes, the
/// parent confirms, either side lives with a single active parent at a time.
public struct PAffiliation: Equatable {
  public var childId: String
  public var activeParent: String
  public var joinedAt: Date?
  public var detachedAt: Date?
  public var lastDetachedFromParent: String

  public var isActive: Bool { !activeParent.isEmpty }
}

/// Who may mint on a creator's behalf. Brands hand this to a studio or a
/// production line instead of sharing the profile's key.
public struct MintAgent: Equatable {
  public var creatorId: String
  public var wallet: String

  public var isSet: Bool {
    !wallet.isEmpty && wallet != ODPChain.zeroAddress
  }
}

/// Read/write interface to `ODPRegistryRelations`. Signatures come from
/// `chain/contracts/ODPRegistryRelations.sol` in the protocol repository.
public struct ODPRelations : Sendable {
  public var rpc: PolygonRPC = ODPChain.rpc
  public var address: String = ODPChain.relations

  /// Значения по умолчанию — боевой реестр; подменяются в тестах
  /// и на другой сети.
  public init(rpc: PolygonRPC = ODPChain.rpc, address: String = ODPChain.relations) {
    self.rpc = rpc
    self.address = address
  }


  // MARK: - P-to-P affiliation

  public func affiliation(childId: String) async -> PAffiliation? {
    let call = ABI.encodeCall("getPAffiliationAudit(string)", [.string(childId)])
    guard let ret = try? await rpc.ethCall(to: address, data: call),
          let f = ABI.decode([.string, .uint, .uint, .string], from: ret),
          f.count >= 4 else { return nil }
    return PAffiliation(
      childId: childId,
      activeParent: f[0].stringValue ?? "",
      joinedAt: Self.date(f[1].uintValue),
      detachedAt: Self.date(f[2].uintValue),
      lastDetachedFromParent: f[3].stringValue ?? ""
    )
  }

  public func children(parentId: String) async -> [String] {
    let call = ABI.encodeCall("getPAffiliatedChildren(string)", [.string(parentId)])
    guard let ret = try? await rpc.ethCall(to: address, data: call),
          let decoded = ABI.decode([.array(.string)], from: ret),
          case .array(let items) = decoded.first else { return [] }
    return items.compactMap { $0.stringValue }
  }

  public func isPending(parentId: String, childId: String) async -> Bool {
    let call = ABI.encodeCall(
      "isPAffiliationPending(string,string)",
      [.string(parentId), .string(childId)]
    )
    guard let ret = try? await rpc.ethCall(to: address, data: call),
          let decoded = ABI.decode([.bool], from: ret) else { return false }
    return decoded.first?.boolValue ?? false
  }

  /// Sent by the child `P`; the named parent has to confirm before it counts.
  public static func proposeAffiliationCalldata(parentId: String) -> Data {
    ABI.encodeCall("proposePAffiliation(string)", [.string(parentId)])
  }

  /// Sent by the parent `P`.
  public static func confirmAffiliationCalldata(childId: String) -> Data {
    ABI.encodeCall("confirmPAffiliation(string)", [.string(childId)])
  }

  /// Parent only — the spec gives the child no way out on its own.
  public static func detachAffiliationCalldata(childId: String) -> Data {
    ABI.encodeCall("detachPAffiliation(string)", [.string(childId)])
  }

  public static func cancelAffiliationRequestCalldata(parentId: String) -> Data {
    ABI.encodeCall("cancelPAffiliationRequest(string)", [.string(parentId)])
  }

  // MARK: - Mint agent

  /// The wallet currently allowed to mint for this profile, if any.
  public func mintAgent(creatorId: String) async -> MintAgent {
    let call = ABI.encodeCall("mintAgentForCreator(string)", [.string(creatorId)])
    guard let ret = try? await rpc.ethCall(to: address, data: call),
          let decoded = ABI.decode([.address], from: ret) else {
      return MintAgent(creatorId: creatorId, wallet: "")
    }
    return MintAgent(creatorId: creatorId, wallet: decoded.first?.addressValue ?? "")
  }

  /// Sent by the wallet that wants to become an agent.
  public static func requestMintAgentCalldata(principalCreatorId: String) -> Data {
    ABI.encodeCall("requestMintAgentRole(string)", [.string(principalCreatorId)])
  }

  /// Sent by the profile owner to accept a requesting wallet.
  public static func confirmMintAgentCalldata(agent: String) -> Data {
    ABI.encodeCall("confirmMintAgentRole(address)", [.address(agent)])
  }

  public static func revokeMintAgentCalldata() -> Data {
    ABI.selector("revokeMintAgentRole()")
  }

  // MARK: - Publishing delegation

  /// (agent, expiry) allowed to publish on this wallet's behalf.
  public func publishingDelegation(creatorWallet: String) async -> (agent: String, expires: Date?)? {
    let call = ABI.encodeCall(
      "getCreatorPublishingDelegation(address)",
      [.address(creatorWallet)]
    )
    guard let ret = try? await rpc.ethCall(to: address, data: call),
          let f = ABI.decode([.address, .uint], from: ret), f.count >= 2,
          let agent = f[0].addressValue, agent != ODPChain.zeroAddress else { return nil }
    return (agent, Self.date(f[1].uintValue))
  }

  public static func delegatePublishingCalldata(agent: String, expiresAt: Date) -> Data {
    ABI.encodeCall(
      "delegateCreatorPublishing(address,uint256)",
      [.address(agent), ABI.uint(UInt64(max(0, expiresAt.timeIntervalSince1970)))]
    )
  }

  public static func revokePublishingCalldata() -> Data {
    ABI.selector("revokeCreatorPublishing()")
  }

  // MARK: - Helpers

  private static func date(_ seconds: UInt64) -> Date? {
    seconds > 0 ? Date(timeIntervalSince1970: TimeInterval(seconds)) : nil
  }
}
