import Foundation

/// Canonical JSON bytes for the values `dataHash` / `anchorsHash` commit to.
///
/// Why not `JSONSerialization` with `.sortedKeys`, which is what this replaced:
/// that option fixes the key order and nothing else. Foundation still escapes
/// `/` as `\/`, and `Double` formatting is Foundation's, not ECMAScript's — so
/// a title like "Портрет 1/25", or a width of 25.0, hashes differently here
/// than in any verifier built on `JSON.stringify` or `json.dumps`. Those
/// hashes go into the registry and are immutable, so the serializer has to be
/// specified rather than inherited.
///
/// The rules below are RFC 8785 (JCS) restricted to the shapes `passport.json`
/// actually uses. Anything outside them throws rather than guessing.
public enum CanonicalJSON {
  public enum Failure: LocalizedError, Equatable {
    /// A type with no defined canonical form reached the serializer.
    case unsupportedValue(String)
    /// NaN, an infinity, or a magnitude outside the range where ECMAScript
    /// writes plain decimal (1e-6 ..< 1e21).
    case numberOutOfRange(Double)

    public var errorDescription: String? {
      switch self {
      case .unsupportedValue(let type):
        return "no canonical form for \(type)"
      case .numberOutOfRange(let value):
        return "number \(value) has no plain decimal form"
      }
    }
  }

  public static func data(from value: Any) throws -> Data {
    var out = Data()
    try write(value, into: &out)
    return out
  }

  // MARK: - Values

  private static func write(_ value: Any, into out: inout Data) throws {
    // Order matters, and the first case is the one that bites.
    //
    // Once `JSONSerialization` has parsed a document, a JSON boolean and the
    // integers 0 and 1 are all `NSNumber`, and `as? Bool` accepts any of them —
    // so matching `Bool` first turned `"number": 1` into `true`. The spec's own
    // `schema/examples/physical.json` contains exactly that, which is how it was
    // caught. `CFBoolean` is the only reliable discriminator, and it covers a
    // native Swift `Bool` too, since that bridges to one.
    switch value {
    case is NSNull:
      out.append(ascii: "null")

    // This one case covers both a parsed JSON boolean and a native Swift
    // `Bool`, since the latter bridges to a CFBoolean. There is deliberately no
    // separate `case let flag as Bool` — put one anywhere above the numeric
    // cases and it swallows `NSNumber(1)` again, which is the original bug.
    case let number as NSNumber where CFGetTypeID(number) == CFBooleanGetTypeID():
      out.append(ascii: number.boolValue ? "true" : "false")

    // Native Swift integers, before the NSNumber case below: they print their
    // exact digits with no trip through Double.
    case let number as any BinaryInteger:
      out.append(ascii: String(number))

    case let number as Double:
      out.append(ascii: try plainDecimal(number))

    case let number as Float:
      out.append(ascii: try plainDecimal(Double(number)))

    case let number as NSNumber:
      // A parsed JSON number. `objCType` says whether it is integral, so a
      // value past 2^53 keeps its digits instead of being rounded by Double.
      switch String(cString: number.objCType) {
      case "c", "C", "s", "S", "i", "I", "l", "L", "q":
        out.append(ascii: String(number.int64Value))
      case "Q":
        out.append(ascii: String(number.uint64Value))
      default:
        out.append(ascii: try plainDecimal(number.doubleValue))
      }

    case let string as String:
      // SPEC §10 step 1: string *values* are normalized to NFC. Keys are not —
      // the reference verifier's `normalizeNFC` maps `[k, normalizeNFC(v)]`,
      // leaving the key untouched, and matching it byte for byte is the whole
      // point of this type. Keys reach here already normalized, because the
      // only one built from user text (`extraParameterKey`) derives from a
      // field normalized on the way in.
      write(string.precomposedStringWithCanonicalMapping, into: &out)

    case let array as [Any]:
      out.append(ascii: "[")
      for (index, element) in array.enumerated() {
        if index > 0 { out.append(ascii: ",") }
        try write(element, into: &out)
      }
      out.append(ascii: "]")

    case let object as [String: Any]:
      // JCS orders keys by their UTF-16 code units.
      let keys = object.keys.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
      out.append(ascii: "{")
      for (index, key) in keys.enumerated() {
        if index > 0 { out.append(ascii: ",") }
        write(key, into: &out)
        out.append(ascii: ":")
        try write(object[key]!, into: &out)
      }
      out.append(ascii: "}")

    default:
      throw Failure.unsupportedValue(String(describing: type(of: value)))
    }
  }

  // MARK: - Strings

  /// Escapes exactly what `JSON.stringify` escapes: the quote, the backslash
  /// and the C0 controls. Notably *not* `/`, and not non-ASCII — those travel
  /// as literal UTF-8.
  private static func write(_ string: String, into out: inout Data) {
    out.append(ascii: "\"")
    for scalar in string.unicodeScalars {
      switch scalar {
      case "\"": out.append(ascii: #"\""#)
      case "\\": out.append(ascii: #"\\"#)
      case "\u{08}": out.append(ascii: #"\b"#)
      case "\u{09}": out.append(ascii: #"\t"#)
      case "\u{0A}": out.append(ascii: #"\n"#)
      case "\u{0C}": out.append(ascii: #"\f"#)
      case "\u{0D}": out.append(ascii: #"\r"#)
      case let control where control.value < 0x20:
        out.append(ascii: String(format: #"\u%04x"#, control.value))
      default:
        out.append(contentsOf: Array(String(scalar).utf8))
      }
    }
    out.append(ascii: "\"")
  }

  // MARK: - Numbers

  /// ECMAScript's plain-decimal form of a double.
  ///
  /// Swift's `description` already yields the shortest digit string that round
  /// trips, which is the same digit string ECMAScript picks — the difference
  /// is only where the point goes: Swift writes `25.0` and `1e-05` where
  /// ECMAScript writes `25` and `0.00001`. So the digits are reused and only
  /// re-placed.
  ///
  /// Outside 1e-6 ..< 1e21 ECMAScript switches to exponent notation with its
  /// own rules. Nothing in a passport reaches those magnitudes — dimensions
  /// and weights are typed in by a person — so that range throws instead of
  /// growing a second code path that no test would ever exercise.
  public static func plainDecimal(_ value: Double) throws -> String {
    guard value.isFinite else { throw Failure.numberOutOfRange(value) }
    if value == 0 { return "0" }

    let magnitude = abs(value)
    guard magnitude >= 1e-6, magnitude < 1e21 else {
      throw Failure.numberOutOfRange(value)
    }

    var mantissa = magnitude.description
    var exponent = 0
    if let marker = mantissa.firstIndex(where: { $0 == "e" || $0 == "E" }) {
      exponent = Int(mantissa[mantissa.index(after: marker)...]) ?? 0
      mantissa = String(mantissa[..<marker])
    }

    var digits = Array(mantissa)
    // Where the decimal point sits, counted in digits from the left.
    var pointIndex = digits.count
    if let dot = digits.firstIndex(of: ".") {
      pointIndex = dot
      digits.remove(at: dot)
    }
    pointIndex += exponent

    var text: String
    if pointIndex <= 0 {
      text = "0." + String(repeating: "0", count: -pointIndex) + String(digits)
    } else if pointIndex >= digits.count {
      text = String(digits) + String(repeating: "0", count: pointIndex - digits.count)
    } else {
      text = String(digits[..<pointIndex]) + "." + String(digits[pointIndex...])
    }

    // `25.0` and `0.5000` are the same number as `25` and `0.5`; ECMAScript
    // writes the short form.
    if text.contains(".") {
      while text.hasSuffix("0") { text.removeLast() }
      if text.hasSuffix(".") { text.removeLast() }
    }
    return value < 0 ? "-" + text : text
  }
}

private extension Data {
  mutating func append(ascii string: String) {
    append(contentsOf: Array(string.utf8))
  }
}
