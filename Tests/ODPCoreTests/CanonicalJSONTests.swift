import Foundation
import Testing
@testable import ODPCore

// Правила канонизации переехали сюда вместе с самим сериализатором: они про
// него, а не про паспорт. Золотые хеши паспорта остались в приложении —
// они про то, что именно приложение кладёт в документ.

@Suite("Canonical JSON")
struct CanonicalJSONTests {
  static let q = "\""
  static let backslash = "\\"

  static func text(_ value: Any) throws -> String {
    String(decoding: try CanonicalJSON.data(from: value), as: UTF8.self)
  }

  @Test("Keys are emitted in sorted order regardless of insertion order")
  func keysAreSorted() throws {
    let object: [String: Any] = ["b": 1, "a": 2, "C": 3, "aa": 4]
    #expect(try Self.text(object) == #"{"C":3,"a":2,"aa":4,"b":1}"#)
  }

  @Test("A forward slash is not escaped")
  func slashIsNotEscaped() throws {
    // JSONSerialization writes "1\/25" here, JSON.stringify writes "1/25".
    // A title like this is ordinary — edition 1 of 25.
    #expect(try Self.text(["t": "Портрет 1/25"]) == #"{"t":"Портрет 1/25"}"#)
  }

  @Test("Non-ASCII travels as literal UTF-8, not as \\u escapes")
  func nonASCIIIsLiteral() throws {
    #expect(try Self.text(["t": "Тест"]) == #"{"t":"Тест"}"#)
  }

  @Test("Quotes, backslashes and control characters are escaped")
  func controlCharactersAreEscaped() throws {
    let control = String(UnicodeScalar(0x01)!)
    let input = "a" + Self.q + "b" + Self.backslash + "c\nd\te" + control
    let expected = "{" + Self.q + "t" + Self.q + ":" + Self.q
      + "a" + Self.backslash + Self.q + "b" + Self.backslash + Self.backslash + "c"
      + Self.backslash + "n" + "d" + Self.backslash + "t" + "e"
      + Self.backslash + "u0001" + Self.q + "}"
    #expect(try Self.text(["t": input]) == expected)
  }

  @Test("null, booleans and nested containers")
  func containersAndLiterals() throws {
    let object: [String: Any] = ["n": NSNull(), "f": false, "l": [1, "x"], "o": ["k": true]]
    #expect(try Self.text(object) == #"{"f":false,"l":[1,"x"],"n":null,"o":{"k":true}}"#)
  }

  @Test("Doubles print the way ECMAScript prints them")
  func doublesMatchECMAScript() throws {
    // The two on the right are why this class exists. JSONSerialization
    // prints them with 17 significant digits — 0.1 becomes
    // "0.10000000000000001" — so a dimension of 0.1 hashed by this app
    // matched nothing produced anywhere else.
    #expect(try CanonicalJSON.plainDecimal(0.1) == "0.1")
    #expect(try CanonicalJSON.plainDecimal(1234567.891) == "1234567.891")
    #expect(try CanonicalJSON.plainDecimal(25.0) == "25")
    #expect(try CanonicalJSON.plainDecimal(25.5) == "25.5")
    #expect(try CanonicalJSON.plainDecimal(-0.75) == "-0.75")
    #expect(try CanonicalJSON.plainDecimal(0) == "0")
    #expect(try CanonicalJSON.plainDecimal(0.001) == "0.001")
    #expect(try CanonicalJSON.plainDecimal(0.00001) == "0.00001")
    #expect(try CanonicalJSON.plainDecimal(1.5e20) == "150000000000000000000")
    #expect(try CanonicalJSON.plainDecimal(100) == "100")
  }

  @Test("A magnitude with no plain decimal form is refused, not guessed at")
  func outOfRangeNumbersThrow() {
    #expect(throws: CanonicalJSON.Failure.self) { try CanonicalJSON.plainDecimal(1e21) }
    #expect(throws: CanonicalJSON.Failure.self) { try CanonicalJSON.plainDecimal(1e-7) }
    #expect(throws: CanonicalJSON.Failure.self) { try CanonicalJSON.plainDecimal(.nan) }
    #expect(throws: CanonicalJSON.Failure.self) { try CanonicalJSON.plainDecimal(.infinity) }
  }

  @Test("A parsed JSON 1 stays a number and does not become true")
  func parsedIntegersAreNotBooleans() throws {
    // Once JSONSerialization has parsed a document, a JSON boolean and the
    // integers 0 and 1 are all NSNumber, and `as? Bool` accepts any of them.
    // Matching Bool before the numeric cases turned `"number": 1` into `true`,
    // which is how the spec's own physical.json example failed to reproduce.
    let raw = Data(#"{"number":1,"zero":0,"yes":true,"no":false,"big":9007199254740993}"#.utf8)
    let object = try #require(try JSONSerialization.jsonObject(with: raw) as? [String: Any])
    #expect(
      try Self.text(object)
        == #"{"big":9007199254740993,"no":false,"number":1,"yes":true,"zero":0}"#
    )
  }

  @Test("An integer past 2^53 keeps its digits")
  func largeIntegersAreExact() throws {
    // Going through Double would round this to …92.
    let raw = Data(#"{"n":9007199254740993}"#.utf8)
    let object = try #require(try JSONSerialization.jsonObject(with: raw) as? [String: Any])
    #expect(try Self.text(object) == #"{"n":9007199254740993}"#)
  }

  @Test("A type with no canonical form is refused")
  func unsupportedValuesThrow() {
    #expect(throws: CanonicalJSON.Failure.self) { try CanonicalJSON.data(from: ["d": Date()]) }
  }
}
