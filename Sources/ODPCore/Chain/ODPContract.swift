import Foundation

/// The on-chain card a passport carries, read back from the registry.
/// Verification compares these against the local bundle — the chain is
/// authoritative on every mismatch (spec §6).
public struct OnChainPassport: Equatable {
  public var passportId: String
  public var contractVersion: UInt8
  public var creator: String
  public var owner: String
  public var creatorId: String
  public var year: UInt32
  public var month: UInt8
  public var title: String
  public var authorName: String
  public var shortDescription: String
  public var domain: String
  public var objectType: String

  // Media anchors
  public var dataHash: String = ""
  public var anchorsHash: String = ""
  public var imageHash: String = ""
  public var fileHash: String = ""
  public var dataUrl: String = ""
  public var imageUrl: String = ""

  // Classification / lifecycle
  public var revoked: Bool = false
  public var mintedAt: Date?
}

/// Live verification state for a passport, resolved against the registry.
public enum OnChainStatus: Equatable {
  case checking
  case anchored(OnChainPassport, mismatches: [String])
  case notAnchored
  case unavailable

  public var record: OnChainPassport? {
    if case .anchored(let record, _) = self { return record }
    return nil
  }
}

/// Read/write interface to the deployed ODP registry. Signatures come from
/// `chain/contracts/ObjectDigitalPassport.sol` in the project repository and
/// every selector used here was matched against the deployed bytecode.
public struct ODPContract: Sendable {
  public var rpc: PolygonRPC = ODPChain.rpc
  public var address: String = ODPChain.contract

  /// По умолчанию — боевой реестр; подменяется в тестах и на другой сети.
  public init(rpc: PolygonRPC = ODPChain.rpc, address: String = ODPChain.contract) {
    self.rpc = rpc
    self.address = address
  }


  // MARK: - ABI shapes

  private static let headerKind: ABI.Kind = .tuple([
    .string, .uint, .address, .address, .string, .uint, .uint,
    .string, .string, .string, .string, .string,
  ])

  private static let mediaKind: ABI.Kind = .tuple([
    .bytes32, .string, .bytes32, .string, .bytes32, .bytes32, .uint,
  ])

  private static let classificationKind: ABI.Kind = .tuple([
    .uint, .uint, .uint, .uint, .uint, .uint, .bool, .uint, .bytes32, .address,
  ])

  // MARK: - Creator registry

  /// The profile ID (`C-…`) this wallet registered, or nil when unregistered.
  public func creatorId(forWallet wallet: String) async -> String? {
    let calldata = ABI.encodeCall("getCreatorByWallet(address)", [.address(wallet)])
    guard let ret = try? await rpc.ethCall(to: address, data: calldata),
          let values = ABI.decode([.string], from: ret),
          case .string(let id) = values.first, !id.isEmpty else { return nil }
    return id
  }

  public static func registerCreatorCalldata(type: String) -> Data {
    let letter = type.uppercased().first.map { String($0) } ?? "C"
    return ABI.encodeCall("registerCreator(bytes1)", [.fixedBytes(Data(letter.utf8))])
  }

  // MARK: - Passport reads

  /// Full on-chain state for a passport ID, or nil when it isn't registered.
  public func fetchPassport(id: String) async -> OnChainPassport? {
    let call = ABI.encodeCall("getPassportHeader(string)", [.string(id)])
    guard let ret = try? await rpc.ethCall(to: address, data: call),
          let decoded = ABI.decode([Self.headerKind], from: ret),
          case .tuple(let f) = decoded.first, f.count >= 12 else { return nil }

    var record = OnChainPassport(
      passportId: f[0].stringValue ?? id,
      contractVersion: UInt8(f[1].uintValue & 0xFF),
      creator: f[2].addressValue ?? "",
      owner: f[3].addressValue ?? "",
      creatorId: f[4].stringValue ?? "",
      year: UInt32(truncatingIfNeeded: f[5].uintValue),
      month: UInt8(f[6].uintValue & 0xFF),
      title: f[7].stringValue ?? "",
      authorName: f[8].stringValue ?? "",
      shortDescription: f[9].stringValue ?? "",
      domain: f[10].stringValue ?? "",
      objectType: f[11].stringValue ?? ""
    )

    if let media = await media(id: id) {
      record.dataHash = media.0
      record.dataUrl = media.1
      record.imageHash = media.2
      record.imageUrl = media.3
      record.fileHash = media.4
      record.anchorsHash = media.5
    }
    if let classification = await classification(id: id) {
      record.revoked = classification.0
      record.mintedAt = classification.1
    }
    return record
  }

  /// (dataHash, dataUrl, imageHash, imageUrl, fileHash, anchorsHash)
  ///
  /// Шесть значений — это форма ответа контракта, а не выбор: они
  /// раскладываются по местам сразу у единственного вызывающего.
  private func media(id: String) async -> (String, String, String, String, String, String)? { // swiftlint:disable:this large_tuple
    let call = ABI.encodeCall("getPassportMedia(string)", [.string(id)])
    guard let ret = try? await rpc.ethCall(to: address, data: call),
          let decoded = ABI.decode([Self.mediaKind], from: ret),
          case .tuple(let f) = decoded.first, f.count >= 6 else { return nil }
    return (
      f[0].hexValue ?? "", f[1].stringValue ?? "", f[2].hexValue ?? "",
      f[3].stringValue ?? "", f[4].hexValue ?? "", f[5].hexValue ?? ""
    )
  }

  /// (revoked, mintedAt)
  private func classification(id: String) async -> (Bool, Date?)? {
    let call = ABI.encodeCall("getPassportClassification(string)", [.string(id)])
    guard let ret = try? await rpc.ethCall(to: address, data: call),
          let decoded = ABI.decode([Self.classificationKind], from: ret),
          case .tuple(let f) = decoded.first, f.count >= 7 else { return nil }
    let timestamp = f[5].uintValue
    let revoked = f[6].boolValue ?? false
    return (revoked, timestamp > 0 ? Date(timeIntervalSince1970: TimeInterval(timestamp)) : nil)
  }

  /// Passport IDs minted by a wallet, newest last. Returns (ids, total).
  public func passportIds(creator: String, offset: UInt64 = 0, limit: UInt64 = 200) async -> ([String], UInt64) {
    let call = ABI.encodeCall(
      "getPassportsByCreatorPaged(address,uint256,uint256)",
      [.address(creator), ABI.uint(offset), ABI.uint(limit)]
    )
    guard let ret = try? await rpc.ethCall(to: address, data: call),
          let decoded = ABI.decode([.array(.string), .uint], from: ret),
          decoded.count >= 2,
          case .array(let items) = decoded[0] else { return ([], 0) }
    return (items.compactMap { $0.stringValue }, decoded[1].uintValue)
  }

  // MARK: - Verification

  /// Resolves a passport against the chain and lists any field that disagrees
  /// with the local bundle. On-chain data is authoritative (spec §6).
  public func status(
    for passport: ODPPassport,
    imageData: Data?,
    detailImages: [Data]
  ) async -> OnChainStatus {
    guard Identity.isValidPassportId(passport.passportId) else { return .notAnchored }
    guard let record = await fetchPassport(id: passport.passportId) else {
      // Distinguish "not registered" from "network down" with a liveness probe.
      return await version() == nil ? .unavailable : .notAnchored
    }

    // Both sides go through NFC first, the way the reference verifier does
    // (`web/frontend/verify.html`, `nfcs()`): the registry holds whatever form
    // the minting client sent, and a decomposed title compared against a
    // composed one is a false mismatch, not a tampered card.
    let same = { (a: String, b: String) in ODPPassport.nfc(a) == ODPPassport.nfc(b) }

    var mismatches: [String] = []
    if !passport.title.isEmpty, !same(record.title, passport.effectiveTitle) { mismatches.append("title") }
    if !passport.authorName.isEmpty, !same(record.authorName, passport.authorName) { mismatches.append("author") }
    if !record.objectType.isEmpty, !same(record.objectType, passport.objectType) { mismatches.append("objectType") }
    if !passport.authorWallet.isEmpty,
       record.creator.lowercased() != passport.authorWallet.lowercased() { mismatches.append("wallet") }

    // The strongest check: does the local bundle hash to what was anchored?
    // Every shot has to go in — the detail photos are inside `anchorsHash`,
    // and hashing without them made this report a mismatch on every passport
    // that carried more than one image.
    if record.dataHash != ODPChain.zeroHash, !record.dataHash.isEmpty {
      let local = passport.dataHashHex(imageData: imageData, detailImages: detailImages)
      if local?.lowercased() != record.dataHash.lowercased() { mismatches.append("dataHash") }
    }
    return .anchored(record, mismatches: mismatches)
  }

  // MARK: - Registry health

  public func version() async -> UInt8? {
    guard let ret = try? await rpc.ethCall(to: address, data: ABI.selector("CONTRACT_VERSION()")),
          let values = ABI.decode([.uint], from: ret),
          let raw = values.first?.uintValue else { return nil }
    return UInt8(truncatingIfNeeded: raw)
  }

  public func frozen() async -> Bool? {
    guard let ret = try? await rpc.ethCall(to: address, data: ABI.selector("frozen()")),
          let values = ABI.decode([.bool], from: ret) else { return nil }
    return values.first?.boolValue
  }
}

/// Formats a big-endian wei amount as a short POL string, e.g. "0.0142 POL".
public enum POLFormatter {
  public static func string(weiBigEndian wei: Data) -> String {
    var value = Decimal(0)
    for byte in wei { value = value * 256 + Decimal(UInt(byte)) }
    let pol = value / Decimal(sign: .plus, exponent: 18, significand: 1)

    let formatter = NumberFormatter()
    formatter.numberStyle = .decimal
    formatter.minimumFractionDigits = 0
    formatter.maximumFractionDigits = 4
    formatter.roundingMode = .down
    let number = formatter.string(from: pol as NSDecimalNumber) ?? "0"
    return "\(number) POL"
  }
}
