import Foundation
import Testing
@testable import ODPCore

// Known-answer vectors from the specifications that define these primitives,
// not from our own output. A test written against what the code currently
// returns proves only that it still returns it.

@Suite("Keccak-256")
struct Keccak256Tests {
  // Keccak-256, not SHA3-256. The two differ in padding and produce different
  // digests for the same input; Ethereum uses Keccak-256, and using a SHA3
  // implementation here is the classic way to get addresses that look right
  // and are wrong.
  @Test("empty input")
  func empty() {
    #expect(Keccak256.hash(Data()).hexEncodedString()
      == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
  }

  @Test("abc")
  func abc() {
    #expect(Keccak256.hash(Data("abc".utf8)).hexEncodedString()
      == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
  }
}

@Suite("BIP-39")
struct BIP39Tests {
  // Trezor's reference vectors, the set every implementation is checked against.
  static let allZeroMnemonic = Array(repeating: "abandon", count: 11) + ["about"]

  @Test("the wordlist loaded at all")
  func wordlistPresent() {
    // Guards the extraction mistake this package was nearly shipped with:
    // reading the resource from Bundle.main returns an empty list inside a
    // package, and every check below would then fail for the wrong reason.
    #expect(BIP39.words.count == 2048)
    #expect(BIP39.words.first == "abandon")
    #expect(BIP39.words.last == "zoo")
  }

  @Test("the all-zero entropy vector is a valid mnemonic")
  func validates() {
    #expect(BIP39.isValid(Self.allZeroMnemonic))
  }

  @Test("a wrong checksum is rejected")
  func rejectsBadChecksum() {
    var bad = Self.allZeroMnemonic
    bad[11] = "abandon"   // valid word, wrong checksum
    #expect(!BIP39.isValid(bad))
  }

  @Test("seed derivation with the TREZOR passphrase")
  func seed() {
    #expect(BIP39.seed(mnemonic: Self.allZeroMnemonic, passphrase: "TREZOR").hexEncodedString()
      == "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
  }

  @Test("a generated mnemonic validates and has the right length")
  func generated() {
    let twelve = BIP39.generateMnemonic(strength: 128)
    #expect(twelve.count == 12)
    #expect(BIP39.isValid(twelve))

    let twentyFour = BIP39.generateMnemonic(strength: 256)
    #expect(twentyFour.count == 24)
    #expect(BIP39.isValid(twentyFour))
  }
}

@Suite("HD derivation and addresses")
struct HDWalletTests {
  // The address every Ethereum tool derives from the all-zero-entropy mnemonic
  // at m/44'/60'/0'/0/0. If this passes, the seed, the HMAC chain, the
  // secp256k1 tweak, and the Keccak address hash all agree with the ecosystem.
  @Test("m/44'/60'/0'/0/0 from the all-zero mnemonic")
  func knownAddress() throws {
    let seed = BIP39.seed(mnemonic: BIP39Tests.allZeroMnemonic)
    let node = try #require(HDWallet.derivePath(seed: seed, path: HDWallet.ethereumPath))
    let address = try #require(EthereumAddress.from(privateKey: node.privateKey))
    #expect(address == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
  }

  @Test("the derived private key is 32 bytes")
  func keyLength() throws {
    let seed = BIP39.seed(mnemonic: BIP39Tests.allZeroMnemonic)
    let node = try #require(HDWallet.derivePath(seed: seed, path: HDWallet.ethereumPath))
    #expect(node.privateKey.count == 32)
    #expect(node.chainCode.count == 32)
  }
}

@Suite("Hex")
struct DataHexTests {
  @Test("round trip, with and without the 0x prefix")
  func roundTrip() throws {
    let bytes = try #require(Data(hexString: "0x00ff10"))
    #expect(Array(bytes) == [0x00, 0xff, 0x10])
    #expect(bytes.hexEncodedString() == "00ff10")
    #expect(Data(hexString: "00ff10") == bytes)
  }

  @Test("odd length and non-hex are rejected")
  func rejects() {
    #expect(Data(hexString: "abc") == nil)
    #expect(Data(hexString: "zz") == nil)
  }
}
