import Foundation

// Builds and parses .odpass bundles (spec §15): a ZIP with passport.json,
// manifest.json and optional originals/ sidecars.
public enum OdpassBundle {
  /// Nil when the passport has no canonical form — see
  /// `ODPPassport.canonicalHashingData`. A bundle whose hashes couldn't be
  /// computed must not be written: it would look complete and verify as
  /// altered on every device that opened it.
  public static func build(
    passport: ODPPassport,
    imageData: Data?,
    detailImages: [Data],
    receipt: MintReceipt? = nil
  ) -> Data? {
    var entries: [ZipArchive.Entry] = []

    guard let passportJSON = passport.canonicalJSONData(
            imageData: imageData,
            detailImages: detailImages
          ),
          // Every shot is inside these hashes. Leaving `detailImages` out here
          // while the mint put them in was why a shared bundle of a passport
          // with more than one photo never matched the registry.
          let dataHash = passport.dataHashHex(imageData: imageData, detailImages: detailImages),
          let anchorsHash = passport.anchorsHashHex(imageData: imageData, detailImages: detailImages)
    else { return nil }
    entries.append(ZipArchive.Entry(path: "passport.json", data: passportJSON))

    var originals: [String: String] = [:]
    var files: [[String: Any]] = [["path": "passport.json", "role": "passport", "mime": "application/json"]]

    if let imageData {
      let path = "originals/image__photo.jpg"
      entries.append(ZipArchive.Entry(path: path, data: imageData))
      originals["imageHash"] = path
      files.append([
        "path": path,
        "role": "image",
        "mime": "image/jpeg",
        "sizeBytes": imageData.count,
        "sha256": "0x" + ODPPassport.sha256Hex(imageData),
      ])
    }

    // Every extra shot travels with the bundle. Their hashes are inside
    // anchorsHash, so a bundle missing them would verify as altered.
    for (index, detail) in detailImages.enumerated() {
      let path = "originals/image__photo-\(index + 2).jpg"
      entries.append(ZipArchive.Entry(path: path, data: detail))
      originals["photo\(index + 2)"] = path
      files.append([
        "path": path,
        "role": "image",
        "mime": "image/jpeg",
        "sizeBytes": detail.count,
        "sha256": "0x" + ODPPassport.sha256Hex(detail),
      ])
    }

    let isoFormatter = ISO8601DateFormatter()
    isoFormatter.formatOptions = [.withInternetDateTime]
    isoFormatter.timeZone = TimeZone(identifier: "UTC")

    let zeroHash = "0x" + String(repeating: "0", count: 64)
    let zeroAddress = "0x" + String(repeating: "0", count: 40)
    var manifest: [String: Any] = [
      "format": "odpass-bundle",
      "bundleVersion": "1",
      "passportId": passport.passportId,
      "createdAtUtc": isoFormatter.string(from: Date()),
      "mode": "full",
      "onChain": [
        "dataHash": dataHash,
        "anchorsHash": anchorsHash,
        "anchorTypesMask": passport.anchorTypesMask(
          imageData: imageData,
          detailImages: detailImages
        ),
        "imageHash": imageData.map { "0x" + ODPPassport.sha256Hex($0) } ?? zeroHash,
        "fileHash": passport.objectType == "physical"
          ? zeroHash
          : (imageData.map { "0x" + ODPPassport.sha256Hex($0) } ?? zeroHash),
        // Empty until a real mint receipt is present (no fabricated txHash).
        "txHash": receipt?.txHash ?? "",
        "chainId": receipt?.chainId ?? Int(ODPChain.chainId),
        "contract": receipt?.contract ?? zeroAddress,
        "creatorId": receipt?.creatorId ?? "",
      ],
      "files": files,
    ]
    manifest["originals"] = originals

    let manifestData = (try? JSONSerialization.data(withJSONObject: manifest, options: [.sortedKeys, .prettyPrinted])) ?? Data()
    entries.insert(ZipArchive.Entry(path: "manifest.json", data: manifestData), at: 1)

    return ZipArchive.archive(entries: entries)
  }

  public struct ParseOutcome {
    public var passport: ODPPassport?
    public var imageData: Data?
    public var detailImages: [Data] = []
    public var result: VerifyResult
  }

  public static func parse(_ data: Data) -> ParseOutcome {
    guard let entries = ZipArchive.extract(data),
          let passportData = entries["passport.json"] else {
      return ParseOutcome(passport: nil, imageData: nil, result: .tampered)
    }
    // A pre-mint bundle carries `passportId: null`, so fall back to the ID the
    // manifest records.
    var manifestId: String?
    if let manifestData = entries["manifest.json"],
       let manifest = try? JSONSerialization.jsonObject(with: manifestData) as? [String: Any] {
      manifestId = manifest["passportId"] as? String
    }
    guard let object = try? JSONSerialization.jsonObject(with: passportData) as? [String: Any],
          let passport = ODPPassport.fromJSONObject(object, fallbackId: manifestId) else {
      return ParseOutcome(passport: nil, imageData: nil, result: .tampered)
    }

    var imageData: Data?
    if let manifestData = entries["manifest.json"],
       let manifest = try? JSONSerialization.jsonObject(with: manifestData) as? [String: Any],
       let originals = manifest["originals"] as? [String: String],
       let imagePath = originals["imageHash"],
       imagePath.lowercased().hasPrefix("originals/"), !imagePath.contains("..") {
      imageData = entries[imagePath]
    }
    if imageData == nil {
      imageData = entries.first { $0.key.lowercased().hasPrefix("originals/image") }?.value
    }

    // The extra shots, in the order the anchors were hashed in: the manifest
    // names them photo2, photo3 … and the file names sort the same way.
    var detailImages: [Data] = []
    if let manifestData = entries["manifest.json"],
       let manifest = try? JSONSerialization.jsonObject(with: manifestData) as? [String: Any],
       let originals = manifest["originals"] as? [String: String] {
      let ordered = originals
        .filter { $0.key.hasPrefix("photo") }
        .sorted { (Int($0.key.dropFirst(5)) ?? 0) < (Int($1.key.dropFirst(5)) ?? 0) }
      for (_, path) in ordered
      where path.lowercased().hasPrefix("originals/") && !path.contains("..") {
        if let bytes = entries[path] { detailImages.append(bytes) }
      }
    }

    // Structural validity against required v0.6 fields. Necessary, not
    // sufficient — the hash check below is what actually detects an edit.
    let requiredKeys = ["version", "passportId", "title", "shortDescription", "anchors", "domain", "objectType", "status", "contentClass", "aiStatus", "verificationMethod", "edition"]
    let hasAll = requiredKeys.allSatisfy { object[$0] != nil }
    let idValid = Identity.isValidPassportId(passport.passportId)
    guard hasAll, idValid else {
      return ParseOutcome(
        passport: passport,
        imageData: imageData,
        detailImages: detailImages,
        result: .tampered
      )
    }

    let manifest = entries["manifest.json"].flatMap {
      try? JSONSerialization.jsonObject(with: $0) as? [String: Any]
    }
    let result: VerifyResult = matchesOwnHashes(
      passport: passport,
      imageData: imageData,
      detailImages: detailImages,
      manifest: manifest
    ) ? .verified : .tampered

    return ParseOutcome(
      passport: passport,
      imageData: imageData,
      detailImages: detailImages,
      result: result
    )
  }

  /// Re-derives `dataHash` and `anchorsHash` from what the bundle actually
  /// contains and compares them with what its manifest claims.
  ///
  /// Without this, `parse` returned `.verified` for anything whose JSON had
  /// the right keys — so a bundle with an edited title, author or swapped
  /// photo showed as verified, which is the one thing this format exists to
  /// prevent. This is still a self-consistency check: it proves the bundle
  /// was not edited after it was built. Whether those hashes are the ones the
  /// registry holds is a separate question, answered by `ODPContract.status`.
  private static func matchesOwnHashes(
    passport: ODPPassport,
    imageData: Data?,
    detailImages: [Data],
    manifest: [String: Any]?
  ) -> Bool {
    // A bundle with no manifest carries nothing to check against. Older
    // bundles predate the block, so absence is not evidence of tampering.
    guard let onChain = manifest?["onChain"] as? [String: Any] else { return true }

    if let claimed = (onChain["dataHash"] as? String)?.lowercased(), !claimed.isEmpty,
       claimed != zeroHashHex {
      let local = passport.dataHashHex(imageData: imageData, detailImages: detailImages)
      guard local?.lowercased() == claimed else { return false }
    }

    if let claimed = (onChain["anchorsHash"] as? String)?.lowercased(), !claimed.isEmpty,
       claimed != zeroHashHex {
      let local = passport.anchorsHashHex(imageData: imageData, detailImages: detailImages)
      guard local?.lowercased() == claimed else { return false }
    }

    if let claimed = onChain["anchorTypesMask"] as? UInt32 {
      let local = passport.anchorTypesMask(imageData: imageData, detailImages: detailImages)
      guard local == claimed else { return false }
    }

    return true
  }

  private static let zeroHashHex = "0x" + String(repeating: "0", count: 64)
}
