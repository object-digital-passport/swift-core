import Foundation
import CryptoKit
import CommonCrypto

// BIP-39 mnemonic generation, validation and seed derivation. The English
// wordlist ships as a resource of this package.
//
// `Bundle.module`, not `Bundle.main`: inside a package, `Bundle.main` is the
// host application's bundle. Reading the wordlist from there worked while this
// file lived in the app and would have returned an empty list here, silently —
// every mnemonic operation failing without an error.
public enum BIP39 {
  static let words: [String] = {
    guard let url = Bundle.module.url(forResource: "bip39-english", withExtension: "txt"),
          let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
    return text.split(whereSeparator: \.isNewline).map(String.init)
  }()

  // `let`, not `var`: it is built once from the bundled word list and never
  // written to. As a `var` it counted as mutable global state.
  private static let wordIndex: [String: Int] = {
    Dictionary(uniqueKeysWithValues: words.enumerated().map { ($1, $0) })
  }()

  /// Generates a fresh mnemonic. strength 128 → 12 words, 256 → 24 words.
  public static func generateMnemonic(strength: Int = 128) -> [String] {
    var entropy = [UInt8](repeating: 0, count: strength / 8)
    _ = SecRandomCopyBytes(kSecRandomDefault, entropy.count, &entropy)
    return mnemonic(fromEntropy: Data(entropy))
  }

  static func mnemonic(fromEntropy entropy: Data) -> [String] {
    guard words.count == 2048 else { return [] }
    let hash = Data(SHA256.hash(data: entropy))
    let checksumBits = entropy.count * 8 / 32

    var bits = ""
    for byte in entropy { bits += byte.binaryString() }
    bits += String(hash[0].binaryString().prefix(checksumBits))

    var result: [String] = []
    var i = 0
    while i < bits.count {
      let start = bits.index(bits.startIndex, offsetBy: i)
      let end = bits.index(start, offsetBy: 11)
      if let idx = Int(bits[start..<end], radix: 2) { result.append(words[idx]) }
      i += 11
    }
    return result
  }

  public static func isValid(_ mnemonic: [String]) -> Bool {
    guard [12, 15, 18, 21, 24].contains(mnemonic.count), words.count == 2048 else { return false }
    var bits = ""
    for word in mnemonic {
      guard let idx = wordIndex[word] else { return false }
      bits += String(String(idx, radix: 2).leftPadded(to: 11))
    }
    let checksumBits = mnemonic.count / 3
    let entropyBits = bits.count - checksumBits
    let entropyString = String(bits.prefix(entropyBits))

    var entropy = [UInt8]()
    var i = 0
    while i < entropyBits {
      let start = entropyString.index(entropyString.startIndex, offsetBy: i)
      let end = entropyString.index(start, offsetBy: 8)
      if let byte = UInt8(entropyString[start..<end], radix: 2) { entropy.append(byte) }
      i += 8
    }
    let hash = Data(SHA256.hash(data: Data(entropy)))
    let expected = String(hash[0].binaryString().prefix(checksumBits))
    return String(bits.suffix(checksumBits)) == expected
  }

  /// BIP-39 seed: PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic"+passphrase.
  public static func seed(mnemonic: [String], passphrase: String = "") -> Data {
    let password = mnemonic.joined(separator: " ")
    let salt = "mnemonic" + passphrase
    return pbkdf2SHA512(password: password, salt: salt, rounds: 2048, keyLength: 64)
  }

  private static func pbkdf2SHA512(password: String, salt: String, rounds: Int, keyLength: Int) -> Data {
    let passwordData = Data(password.utf8)
    let saltData = Data(salt.utf8)
    var derived = Data(count: keyLength)

    let status = derived.withUnsafeMutableBytes { derivedPtr in
      saltData.withUnsafeBytes { saltPtr in
        passwordData.withUnsafeBytes { passwordPtr in
          CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            passwordPtr.bindMemory(to: Int8.self).baseAddress, passwordData.count,
            saltPtr.bindMemory(to: UInt8.self).baseAddress, saltData.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
            UInt32(rounds),
            derivedPtr.bindMemory(to: UInt8.self).baseAddress, keyLength
          )
        }
      }
    }
    return status == kCCSuccess ? derived : Data()
  }
}

private extension UInt8 {
  func binaryString() -> String { String(String(self, radix: 2).leftPadded(to: 8)) }
}

private extension String {
  func leftPadded(to length: Int) -> String {
    count >= length ? self : String(repeating: "0", count: length - count) + self
  }
}
