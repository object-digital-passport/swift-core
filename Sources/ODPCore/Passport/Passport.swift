import Foundation
import CryptoKit

public struct ODPPassport: Identifiable, Codable, Equatable, Sendable {
  public var passportId: String = ""
  public var title: String = ""
  public var shortDescription: String = ""
  public var subject: String = ""
  public var authorName: String = ""
  public var authorWallet: String = ""
  public var authorCreatorId: String = ""
  public var domain: String = ""
  public var objectType: String = "physical"
  public var status: String = "produced_object"
  public var contentClass: String = "static"
  public var aiStatus: String = "none"
  public var method: String = "nfc seal"
  public var editionModel: String = "unique"
  public var editionNumber: String = ""
  public var editionTotal: String = ""
  public var category: String = ""
  public var notes: String = ""
  public var materials: String = ""
  public var creationDate: String = ""
  public var dimWidth: String = ""
  public var dimDepth: String = ""
  public var dimHeight: String = ""
  public var dimUnit: String = ""
  public var weightValue: String = ""
  public var weightUnit: String = ""
  public var extraParameterName: String = ""
  public var extraParameter: String = ""
  public var sealType: String = "nfc"
  // Numbered physical seal (spec §6 Method B).
  public var sealNumber: String = ""
  public var sealMaterial: String = ""
  public var sealColor: String = ""
  public var sealSize: String = ""
  // NFC crypto seal (spec §6, Method A). publicKey is the 16-byte EV2 AES app
  // key (hex) also published on-chain as nfcPublicKey.
  public var nfcUid: String = ""
  public var nfcPublicKey: String = ""
  public var nfcModel: String = ""       // "NTAG424DNA" | "NTAG424DNA_TAGTAMPER"
  public var nfcInstalledAt: String = ""
  public var registeredAt: Date = Date()
  /// Transaction that anchored this passport, once minted on-chain.
  public var txHash: String = ""
  public var imageFileName: String?
  /// Extra shots of the same object. Only the primary photo reaches the chain
  /// as `imageHash`; the rest are `photo` anchors with `role: detail` (§8).
  public var detailImageFileNames: [String] = []

  public var id: String { passportId }

  // Decoded key by key so a saved collection survives new fields being added as
  // the spec moves on — the synthesized decoder throws on the first missing key,
  // which would silently drop every stored passport.
  public init() {}

  public init(from decoder: Decoder) throws {
    let c = try decoder.container(keyedBy: CodingKeys.self)
    func string(_ key: CodingKeys, _ fallback: String = "") -> String {
      (try? c.decodeIfPresent(String.self, forKey: key)) ?? fallback
    }
    passportId = string(.passportId)
    title = string(.title)
    shortDescription = string(.shortDescription)
    subject = string(.subject)
    authorName = string(.authorName)
    authorWallet = string(.authorWallet)
    authorCreatorId = string(.authorCreatorId)
    domain = string(.domain)
    objectType = string(.objectType, "physical")
    status = string(.status, "produced_object")
    contentClass = string(.contentClass, "static")
    aiStatus = string(.aiStatus, "none")
    method = string(.method, "nfc seal")
    editionModel = string(.editionModel, "unique")
    editionNumber = string(.editionNumber)
    editionTotal = string(.editionTotal)
    category = string(.category)
    notes = string(.notes)
    materials = string(.materials)
    creationDate = string(.creationDate)
    dimWidth = string(.dimWidth)
    dimDepth = string(.dimDepth)
    dimHeight = string(.dimHeight)
    dimUnit = string(.dimUnit)
    weightValue = string(.weightValue)
    weightUnit = string(.weightUnit)
    extraParameterName = string(.extraParameterName)
    extraParameter = string(.extraParameter)
    sealType = string(.sealType, "nfc")
    sealNumber = string(.sealNumber)
    sealMaterial = string(.sealMaterial)
    sealColor = string(.sealColor)
    sealSize = string(.sealSize)
    nfcUid = string(.nfcUid)
    nfcPublicKey = string(.nfcPublicKey)
    nfcModel = string(.nfcModel)
    nfcInstalledAt = string(.nfcInstalledAt)
    txHash = string(.txHash)
    registeredAt = (try? c.decodeIfPresent(Date.self, forKey: .registeredAt)) ?? Date()
    imageFileName = try? c.decodeIfPresent(String.self, forKey: .imageFileName)
    detailImageFileNames =
      (try? c.decodeIfPresent([String].self, forKey: .detailImageFileNames)) ?? []
  }

  public var registrationDateLabel: String {
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(identifier: "UTC")!
    let c = calendar.dateComponents([.year, .month, .day], from: registeredAt)
    return String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
  }

  public var editionLabel: String {
    if editionModel == "unique" { return "unique" }
    let n = editionNumber.isEmpty ? "?" : editionNumber
    let t = editionTotal.isEmpty ? "?" : editionTotal
    return "\(n) / \(t)"
  }

  /// The on-chain card requires a non-empty short description (1..256 bytes).
  /// Falls back to the notes, then the title, so older drafts stay mintable.
  public var effectiveShortDescription: String {
    for candidate in [shortDescription, notes, title] {
      let trimmed = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
      if !trimmed.isEmpty { return String(trimmed.prefix(256)) }
    }
    return "untitled"
  }

  public var effectiveTitle: String { title.isEmpty ? "untitled" : title }

  /// `additionalMetadata` key for the free-form extra field. The label the
  /// author typed becomes a snake_case key so the value means something to a
  /// reader; an unnamed value falls back to the generic key.
  public var extraParameterKey: String {
    let slug = extraParameterName
      .lowercased()
      .replacingOccurrences(of: " ", with: "_")
      .filter { $0.isLetter || $0.isNumber || $0 == "_" }
    return slug.isEmpty ? "extra_parameter" : slug
  }

  public var effectiveDomain: String { domain.isEmpty ? "contemporary_art" : domain }

  // MARK: - Identification anchors (spec v0.6 §5.2)

  public var materialList: [String] {
    materials
      .split(separator: ",")
      .map { $0.trimmingCharacters(in: .whitespaces) }
      .filter { !$0.isEmpty }
  }

  public var hasDimensions: Bool {
    [dimWidth, dimDepth, dimHeight].contains { Self.decimal($0) != nil }
  }

  /// Normalizes text to Unicode NFC, which SPEC §10 step 1 requires before
  /// anything is hashed.
  ///
  /// It matters because both forms reach the app: macOS hands out filenames —
  /// and some clipboard content — decomposed, and a CSV exported there carries
  /// that straight into a passport. "Ёлка" is one scalar composed (U+0401) and
  /// two decomposed (U+0415 U+0308); without this they hash differently, the
  /// reference verifier normalizes and we would not, and the card is immutable
  /// on chain — so a passport minted from decomposed text could never be made
  /// to verify.
  public static func nfc(_ text: String) -> String {
    text.precomposedStringWithCanonicalMapping
  }

  /// Parses a number the user typed. `Double.init` only accepts a dot, but a
  /// `.decimalPad` on a Russian keyboard produces a comma — so "25,5" used to
  /// parse as nil, the dimensions anchor was silently dropped, and the mint
  /// was refused for "missing: dimensions" the user had in fact filled in.
  public static func decimal(_ text: String) -> Double? {
    let normalized = text
      .trimmingCharacters(in: .whitespaces)
      .replacingOccurrences(of: ",", with: ".")
      // Grouping separators some keyboards insert.
      .replacingOccurrences(of: "\u{00A0}", with: "")
      .replacingOccurrences(of: " ", with: "")
    guard !normalized.isEmpty else { return nil }
    return Double(normalized)
  }

  /// The `anchors` array: verifiable properties binding the passport to the
  /// object. `anchorsHash` commits to this array on its own so it can be
  /// checked in isolation, and `anchorTypesMask` mirrors the types present.
  public func anchors(imageData: Data?, detailImages: [Data]) -> [[String: Any]] {
    var result: [[String: Any]] = []

    // The shape follows `schema/examples/physical.json`: the role lives in
    // `data.role`, and the file path is a bundle detail that belongs in the
    // manifest rather than in the anchor.
    if let imageData {
      result.append([
        "type": "photo",
        "data": ["role": "primary"],
        "hash": "sha256:" + Self.sha256Hex(imageData),
        "verification": "compare the object with the primary photo",
      ])
    }

    for detail in detailImages {
      result.append([
        "type": "photo",
        "data": ["role": "detail"],
        "hash": "sha256:" + Self.sha256Hex(detail),
        "verification": "compare the object with this shot",
      ])
    }

    if hasDimensions {
      var dims: [String: Any] = [:]
      if let w = Self.decimal(dimWidth) { dims["width"] = w }
      if let d = Self.decimal(dimDepth) { dims["depth"] = d }
      if let h = Self.decimal(dimHeight) { dims["height"] = h }
      dims["unit"] = dimUnit.isEmpty ? "cm" : dimUnit
      if let weight = Self.decimal(weightValue) {
        dims["weight"] = weight
        dims["weightUnit"] = weightUnit.isEmpty ? "kg" : weightUnit
      }
      result.append([
        "type": "dimensions",
        "data": dims,
        "verification": "measure the object and compare with the recorded values",
      ])
    }

    let materialsFound = materialList
    if !materialsFound.isEmpty {
      result.append([
        "type": "materials",
        "data": ["list": materialsFound],
        "verification": "inspect materials and technique",
      ])
    }

    let features = notes.trimmingCharacters(in: .whitespacesAndNewlines)
    if !features.isEmpty {
      result.append([
        "type": "distinguishing_features",
        "data": ["text": features],
        "verification": "locate the described features on the object",
      ])
    }

    if objectType == "digital" || objectType == "mixed", let imageData {
      result.append([
        "type": "file_hash",
        "data": ["algorithm": "sha256"],
        "hash": "sha256:" + Self.sha256Hex(imageData),
        "verification": "hash the original file and compare",
      ])
    }

    if !nfcUid.isEmpty {
      var nfc: [String: Any] = [
        "uid": nfcUid.lowercased(),
        "model": nfcModel.isEmpty ? "NTAG424DNA" : nfcModel,
      ]
      if !nfcPublicKey.isEmpty { nfc["publicKey"] = nfcPublicKey.lowercased() }
      // §6 requires an installation date on the anchor; fall back to the
      // registration day for seals provisioned before it was recorded.
      nfc["installedAt"] = nfcInstalledAt.isEmpty ? registrationDateLabel : nfcInstalledAt
      result.append([
        "type": "nfc",
        "data": nfc,
        "verification": "tap the seal and run mutual authentication",
      ])
    }

    if sealType == "numbered" || sealType == "both" {
      var seal: [String: Any] = [
        "number": sealNumber.isEmpty ? "1" : sealNumber,
        "type": sealMaterial.isEmpty ? "holographic sticker" : sealMaterial,
      ]
      if !sealColor.isEmpty { seal["color"] = sealColor }
      if !sealSize.isEmpty { seal["size"] = sealSize }
      result.append([
        "type": "numbered_seal",
        "data": seal,
        "verification": "check the seal number and that the seal is intact",
      ])
    }

    return result
  }

  public func anchorTypesMask(imageData: Data?, detailImages: [Data]) -> UInt32 {
    var mask: UInt32 = 0
    for anchor in anchors(imageData: imageData, detailImages: detailImages) {
      switch anchor["type"] as? String {
      case "photo": mask |= ODPAnchorBit.photo
      case "dimensions": mask |= ODPAnchorBit.dimensions
      case "materials": mask |= ODPAnchorBit.materials
      case "distinguishing_features": mask |= ODPAnchorBit.distinguishingFeatures
      case "marks": mask |= ODPAnchorBit.marks
      case "file_hash": mask |= ODPAnchorBit.fileHash
      case "nfc": mask |= ODPAnchorBit.nfc
      case "numbered_seal": mask |= ODPAnchorBit.numberedSeal
      default: break
      }
    }
    return mask
  }

  /// SHA-256 of the canonical minified `anchors` array (same rules as dataHash).
  public func anchorsHashHex(imageData: Data?, detailImages: [Data]) -> String? {
    let array = anchors(imageData: imageData, detailImages: detailImages)
    guard let data = try? CanonicalJSON.data(from: array) else { return nil }
    return "0x" + Self.sha256Hex(data)
  }

  /// Requirements the contract enforces at mint, as human-readable keys.
  /// Empty means the passport satisfies the hard identification minimum.
  public func missingMintRequirements(imageData: Data?, detailImages: [Data]) -> [String] {
    var missing: [String] = []
    let mask = anchorTypesMask(imageData: imageData, detailImages: detailImages)

    if objectType == "physical" || objectType == "mixed" {
      if mask & ODPAnchorBit.photo == 0 { missing.append("photo") }
      if mask & ODPAnchorBit.dimensions == 0 { missing.append("dimensions") }
      if mask & ODPAnchorBit.materials == 0 { missing.append("materials") }
      if mask & ODPAnchorBit.distinguishingFeatures == 0 { missing.append("features") }
    }
    if objectType == "digital" || objectType == "mixed" {
      if mask & ODPAnchorBit.fileHash == 0 { missing.append("file") }
    }
    return missing
  }

  // MARK: - passport.json (spec v0.6)

  public func passportJSONObject(imageData: Data?, detailImages: [Data]) -> [String: Any] {
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(identifier: "UTC")!
    let year = calendar.component(.year, from: registeredAt)
    let month = calendar.component(.month, from: registeredAt)

    let isoFormatter = ISO8601DateFormatter()
    isoFormatter.formatOptions = [.withInternetDateTime]
    isoFormatter.timeZone = TimeZone(identifier: "UTC")
    let utcIso = isoFormatter.string(from: registeredAt)
    let localIso = utcIso.replacingOccurrences(of: "Z", with: "+00:00")

    var author: [String: Any] = ["name": authorName]
    if !authorWallet.isEmpty { author["wallet"] = authorWallet }
    if !authorCreatorId.isEmpty { author["creatorId"] = authorCreatorId }

    var edition: [String: Any] = ["model": editionModel]
    if let n = Int(editionNumber) { edition["number"] = n }
    if let t = Int(editionTotal) { edition["total"] = t }

    var json: [String: Any] = [
      "version": "0.6",
      // `null` until minted — the contract assigns the ID. The hashing rule
      // (§6) always nulls it out, see canonicalJSONData.
      "passportId": passportId.isEmpty ? NSNull() : passportId,
      "title": effectiveTitle,
      "shortDescription": effectiveShortDescription,
      "authorName": authorName,
      "anchors": anchors(imageData: imageData, detailImages: detailImages),
      "authorship": ["author": author],
      "domain": effectiveDomain,
      "objectType": objectType,
      "status": status,
      "contentClass": contentClass,
      "aiStatus": aiStatus,
      "verificationMethod": method,
      "edition": edition,
      "year": year,
      "month": month,
      "registeredAt": Int(registeredAt.timeIntervalSince1970),
      "registration": [
        "utcIso8601": utcIso,
        "localIso8601": localIso,
        "ianaTimeZone": "UTC",
      ],
    ]

    if !notes.isEmpty { json["description"] = notes }
    if !creationDate.isEmpty { json["creationDate"] = creationDate }
    if !subject.isEmpty { json["subject"] = subject }

    // v0.6 removed the `physical` block: materials, dimensions, marks and the
    // seal all live in `anchors` now (§8 migration table).
    if objectType == "digital" || objectType == "mixed" {
      var digital: [String: Any] = [:]
      if !category.isEmpty { digital["subtype"] = category }
      if let imageData {
        digital["fileHash"] = "sha256:" + Self.sha256Hex(imageData)
        digital["fileSize"] = imageData.count
        digital["format"] = "image/jpeg"
      }
      json["digital"] = digital
    }

    // v0.6 has no top-level category; it rides in additionalMetadata for every
    // object type (digital objects also expose it as `digital.subtype`).
    var additional: [String: Any] = [:]
    if !extraParameter.isEmpty { additional[extraParameterKey] = extraParameter }
    if !category.isEmpty { additional["category"] = category }
    if !additional.isEmpty { json["additionalMetadata"] = additional }
    return json
  }

  // Canonical minified bytes: sorted keys, no whitespace (spec §10). See
  // `CanonicalJSON` for why this is not `JSONSerialization.sortedKeys`.
  public func canonicalJSONData(imageData: Data?, detailImages: [Data]) -> Data? {
    let object = passportJSONObject(imageData: imageData, detailImages: detailImages)
    return try? CanonicalJSON.data(from: object)
  }

  /// Bytes `dataHash` commits to. Per spec §6 the passport ID is nulled out
  /// when hashing, because the contract assigns it during the mint — so the
  /// hash computed before minting still matches the finished bundle.
  ///
  /// Nil means the passport holds something with no canonical form (today:
  /// only a dimension outside the plain-decimal range). Returning zero bytes
  /// instead would produce a perfectly valid-looking hash of nothing, and it
  /// would be anchored on chain before anyone noticed.
  public func canonicalHashingData(imageData: Data?, detailImages: [Data]) -> Data? {
    var object = passportJSONObject(imageData: imageData, detailImages: detailImages)
    object["passportId"] = NSNull()
    return try? CanonicalJSON.data(from: object)
  }

  public func dataHashHex(imageData: Data?, detailImages: [Data]) -> String? {
    guard let data = canonicalHashingData(imageData: imageData, detailImages: detailImages) else {
      return nil
    }
    return "0x" + Self.sha256Hex(data)
  }

  public static func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }

  // MARK: - Parsing (verification of imported passport.json)

  public static func fromJSONObject(_ dict: [String: Any], fallbackId: String? = nil) -> ODPPassport? {
    guard let title = dict["title"] as? String else { return nil }
    // `passportId` is null in a pre-mint bundle; the real ID then comes from
    // the manifest.
    let passportId = (dict["passportId"] as? String) ?? fallbackId ?? ""
    var p = ODPPassport()
    p.passportId = passportId
    p.title = title
    p.shortDescription = dict["shortDescription"] as? String ?? ""
    p.authorName = dict["authorName"] as? String ?? ""
    if let authorship = dict["authorship"] as? [String: Any],
       let author = authorship["author"] as? [String: Any] {
      if let name = author["name"] as? String, !name.isEmpty { p.authorName = name }
      p.authorWallet = author["wallet"] as? String ?? ""
      p.authorCreatorId = author["creatorId"] as? String ?? ""
    }
    p.domain = dict["domain"] as? String ?? ""
    p.objectType = dict["objectType"] as? String ?? "physical"
    p.status = dict["status"] as? String ?? ""
    p.contentClass = dict["contentClass"] as? String ?? ""
    p.aiStatus = dict["aiStatus"] as? String ?? ""
    p.method = dict["verificationMethod"] as? String ?? ""
    p.subject = dict["subject"] as? String ?? ""
    if let edition = dict["edition"] as? [String: Any] {
      p.editionModel = edition["model"] as? String ?? "unique"
      if let n = edition["number"] as? Int { p.editionNumber = String(n) }
      if let t = edition["total"] as? Int { p.editionTotal = String(t) }
    }
    p.notes = dict["description"] as? String ?? ""
    p.creationDate = dict["creationDate"] as? String ?? ""
    if let physical = dict["physical"] as? [String: Any] {
      p.category = physical["category"] as? String ?? ""
      if let seal = physical["seal"] as? [String: Any],
         let nfc = seal["nfc"] as? [String: Any] {
        p.nfcUid = (nfc["uid"] as? String ?? "").uppercased()
        p.nfcPublicKey = (nfc["publicKey"] as? String ?? "")
        p.nfcModel = nfc["model"] as? String ?? ""
        p.nfcInstalledAt = nfc["installedAt"] as? String ?? ""
        p.sealType = "nfc"
      }
    }
    // v0.6 moves the seal onto the anchors array; read it back from there.
    if let anchors = dict["anchors"] as? [[String: Any]] {
      for anchor in anchors {
        guard let type = anchor["type"] as? String,
              let data = anchor["data"] as? [String: Any] else { continue }
        switch type {
        case "nfc":
          p.nfcUid = (data["uid"] as? String ?? "").uppercased()
          p.nfcPublicKey = data["publicKey"] as? String ?? ""
          p.nfcModel = data["model"] as? String ?? ""
          p.nfcInstalledAt = data["installedAt"] as? String ?? ""
          p.sealType = "nfc"
        case "materials":
          if let list = data["list"] as? [String], !list.isEmpty {
            p.materials = list.joined(separator: ", ")
          }
        case "dimensions":
          if let w = data["width"] as? Double { p.dimWidth = Self.trimNumber(w) }
          if let d = data["depth"] as? Double { p.dimDepth = Self.trimNumber(d) }
          if let h = data["height"] as? Double { p.dimHeight = Self.trimNumber(h) }
          p.dimUnit = data["unit"] as? String ?? ""
        case "distinguishing_features":
          if p.notes.isEmpty { p.notes = data["text"] as? String ?? "" }
        default:
          break
        }
      }
    }
    if let digital = dict["digital"] as? [String: Any],
       let subtype = digital["subtype"] as? String {
      p.category = subtype
    }
    if let additional = dict["additionalMetadata"] as? [String: Any] {
      if let c = additional["category"] as? String, !c.isEmpty { p.category = c }
      // Anything else the author added is shown back as the named extra field.
      for key in additional.keys.sorted() where key != "category" {
        guard let value = additional[key] as? String else { continue }
        p.extraParameterName = key == "extra_parameter" ? "" : key
        p.extraParameter = value
        break
      }
    }
    if let registeredAt = dict["registeredAt"] as? Int {
      p.registeredAt = Date(timeIntervalSince1970: TimeInterval(registeredAt))
    }
    p.normalizeText()
    return p
  }

  /// Brings every text field to NFC. Applied at the two places text enters a
  /// passport — the form (`AppModel.buildPassport`) and a parsed `.odpass`
  /// (`fromJSONObject`) — so the model only ever holds normalized text and
  /// comparisons against the chain, search and `extraParameterKey` all agree.
  ///
  /// `CanonicalJSON` normalizes again on the way out. That is deliberate
  /// belt-and-braces: this list has to be extended when a text field is added,
  /// and the hash must not depend on someone remembering to.
  ///
  /// File names are left alone on purpose — they address bytes already written
  /// to disk, and renormalizing one would break the lookup.
  public mutating func normalizeText() {
    passportId = Self.nfc(passportId)
    title = Self.nfc(title)
    shortDescription = Self.nfc(shortDescription)
    subject = Self.nfc(subject)
    authorName = Self.nfc(authorName)
    domain = Self.nfc(domain)
    objectType = Self.nfc(objectType)
    status = Self.nfc(status)
    contentClass = Self.nfc(contentClass)
    aiStatus = Self.nfc(aiStatus)
    method = Self.nfc(method)
    editionModel = Self.nfc(editionModel)
    editionNumber = Self.nfc(editionNumber)
    editionTotal = Self.nfc(editionTotal)
    category = Self.nfc(category)
    notes = Self.nfc(notes)
    materials = Self.nfc(materials)
    creationDate = Self.nfc(creationDate)
    dimWidth = Self.nfc(dimWidth)
    dimDepth = Self.nfc(dimDepth)
    dimHeight = Self.nfc(dimHeight)
    dimUnit = Self.nfc(dimUnit)
    weightValue = Self.nfc(weightValue)
    weightUnit = Self.nfc(weightUnit)
    extraParameterName = Self.nfc(extraParameterName)
    extraParameter = Self.nfc(extraParameter)
    sealType = Self.nfc(sealType)
    sealNumber = Self.nfc(sealNumber)
    sealMaterial = Self.nfc(sealMaterial)
    sealColor = Self.nfc(sealColor)
    sealSize = Self.nfc(sealSize)
    nfcModel = Self.nfc(nfcModel)
    nfcInstalledAt = Self.nfc(nfcInstalledAt)
  }

  private static func trimNumber(_ value: Double) -> String {
    value == value.rounded() ? String(Int(value)) : String(value)
  }
}

public enum VerifyResult: String, Codable, Sendable {
  case verified, unverifiable, tampered
}

