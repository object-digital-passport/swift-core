import Foundation

/// Maps the spec's string dictionaries onto the uint8 codes the contract
/// validates (see ODPPassportLib.validate*). Every enum is 1-based and the
/// order is normative — it comes from `schema/passport-0.5.schema.json`.
public enum ODPCodes {
  public static func contentClass(_ value: String) -> UInt8 {
    switch value {
    case "static": return 1
    case "time_based": return 2
    case "spatial": return 3
    case "textual": return 4
    case "composite": return 5
    case "executable": return 6
    default: return 1
    }
  }

  public static func lifecycleStatus(_ value: String) -> UInt8 {
    switch value {
    case "concept": return 1
    case "prototype": return 2
    case "produced_object": return 3
    case "archived": return 4
    default: return 3
    }
  }

  /// Reverse of `lifecycleStatus` — the spec's string for a code read back from
  /// the chain (a status event carries the new code as its value).
  public static func lifecycleStatusName(_ code: UInt8) -> String {
    switch code {
    case 1: return "concept"
    case 2: return "prototype"
    case 3: return "produced_object"
    case 4: return "archived"
    default: return ""
    }
  }

  public static func aiStatus(_ value: String) -> UInt8 {
    switch value {
    case "none": return 1
    case "assisted": return 2
    case "generated": return 3
    default: return 1
    }
  }

  /// Accepts both the spec values and the form's chip labels.
  public static func verificationMethod(_ value: String) -> UInt8 {
    switch value {
    case "self_asserted", "self asserted": return 1
    case "institutional": return 2
    case "nfc", "nfc seal": return 3
    case "c2pa": return 4
    case "hybrid": return 5
    default: return 1
    }
  }

  public static func editionModel(_ value: String) -> UInt8 {
    switch value {
    case "unique": return 1
    case "limited": return 2
    case "open": return 3
    case "dynamic": return 4
    default: return 1
    }
  }
}

/// Bits for `anchorTypesMask` (ODPPassportTypes.ODPAnchorBits). The contract
/// enforces a hard identification minimum per object type at mint.
public enum ODPAnchorBit {
  public static let photo: UInt32 = 1
  public static let dimensions: UInt32 = 2
  public static let materials: UInt32 = 4
  public static let distinguishingFeatures: UInt32 = 8
  public static let marks: UInt32 = 16
  public static let fileHash: UInt32 = 32
  public static let perceptualHash: UInt32 = 64
  public static let c2pa: UInt32 = 128
  public static let nfc: UInt32 = 256
  public static let numberedSeal: UInt32 = 512
  public static let fingerprint: UInt32 = 1024
  public static let dna: UInt32 = 2048

  /// photo + dimensions + materials + distinguishing_features
  public static let physicalRequired: UInt32 = photo | dimensions | materials | distinguishingFeatures
  public static let digitalRequired: UInt32 = fileHash
}
