import Foundation

/// One institutional attestation stored in the proofs satellite. Immutable and
/// additive: a proof never edits the passport it points at (spec §Proof records).
public struct ODPProofRecord: Equatable, Identifiable {
  public var proofId: String
  public var contractVersion: UInt8
  public var prover: String
  public var passportId: String
  public var documentHash: String
  public var documentUrl: String
  public var timestamp: Date?

  public var id: String { proofId }

  /// True when the institution attached an expertise document by hash.
  public var hasDocument: Bool {
    !documentHash.isEmpty && documentHash != ODPChain.zeroHash
  }
}

/// Read/write interface to `ODPPassportProofRegistry`. Signatures come from
/// `chain/contracts/ODPPassportProofRegistry.sol` in the protocol repository.
///
/// Only `P` and `M` profiles may submit; submissions revert on a revoked passport.
public struct ODPProofRegistry : Sendable {
  public var rpc: PolygonRPC = ODPChain.rpc
  public var address: String = ODPChain.proofRegistry

  /// Значения по умолчанию — боевой реестр; подменяются в тестах
  /// и на другой сети.
  public init(rpc: PolygonRPC = ODPChain.rpc, address: String = ODPChain.proofRegistry) {
    self.rpc = rpc
    self.address = address
  }


  private static let recordKind: ABI.Kind = .tuple([
    .string, .uint, .string, .string, .bytes32, .string, .uint,
  ])

  // MARK: - Reads

  /// Proof IDs attached to one passport.
  public func proofIds(passportId: String) async -> [String] {
    await ids(ABI.encodeCall("getProofsForPassport(string)", [.string(passportId)]))
  }

  /// Proof IDs issued by one institution profile (`P-…` or `M-…`).
  public func proofIds(institution creatorId: String) async -> [String] {
    await ids(ABI.encodeCall("getProofsByInstitution(string)", [.string(creatorId)]))
  }

  public func proof(id: String) async -> ODPProofRecord? {
    let call = ABI.encodeCall("getProof(string)", [.string(id)])
    guard let ret = try? await rpc.ethCall(to: address, data: call),
          let decoded = ABI.decode([Self.recordKind], from: ret),
          case .tuple(let f) = decoded.first, f.count >= 7,
          let proofId = f[0].stringValue, !proofId.isEmpty else { return nil }
    let seconds = f[6].uintValue
    return ODPProofRecord(
      proofId: proofId,
      contractVersion: UInt8(f[1].uintValue & 0xFF),
      prover: f[2].stringValue ?? "",
      passportId: f[3].stringValue ?? "",
      documentHash: f[4].hexValue ?? "",
      documentUrl: f[5].stringValue ?? "",
      timestamp: seconds > 0 ? Date(timeIntervalSince1970: TimeInterval(seconds)) : nil
    )
  }

  /// Full records for one passport, newest first. The satellite exposes IDs
  /// only, so each record costs one extra call.
  public func proofs(passportId: String) async -> [ODPProofRecord] {
    await records(for: await proofIds(passportId: passportId))
  }

  /// Full records issued by one institution, newest first.
  public func proofs(institution creatorId: String) async -> [ODPProofRecord] {
    await records(for: await proofIds(institution: creatorId))
  }

  // MARK: - Writes

  /// `submitProof` calldata. `documentHash` may be empty when no expertise
  /// document is attached; `documentUrl` must then be empty too (spec §Proof records).
  public static func submitProofCalldata(
    passportId: String,
    documentHash: String,
    documentUrl: String,
    year: UInt32,
    month: UInt8
  ) -> Data {
    let hash = Self.bytes32(documentHash)
    let url = hash.allSatisfy { $0 == 0 } ? "" : documentUrl
    return ABI.encodeCall(
      "submitProof(string,bytes32,string,uint32,uint8)",
      [
        .string(passportId),
        .fixedBytes(hash),
        .string(url),
        ABI.uint(UInt64(year)),
        ABI.uint(UInt64(month)),
      ]
    )
  }

  // MARK: - Helpers

  private func ids(_ call: Data) async -> [String] {
    guard let ret = try? await rpc.ethCall(to: address, data: call),
          let decoded = ABI.decode([.array(.string)], from: ret),
          case .array(let items) = decoded.first else { return [] }
    return items.compactMap { $0.stringValue }
  }

  private func records(for ids: [String]) async -> [ODPProofRecord] {
    var found: [ODPProofRecord] = []
    for id in ids {
      if let record = await proof(id: id) { found.append(record) }
    }
    return found.sorted { ($0.timestamp ?? .distantPast) > ($1.timestamp ?? .distantPast) }
  }

  /// 32 bytes from a hex string; all-zero when the string is empty or malformed.
  public static func bytes32(_ hex: String) -> Data {
    let body = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
    guard let data = Data(hexString: body), data.count == 32 else {
      return Data(repeating: 0, count: 32)
    }
    return data
  }
}
