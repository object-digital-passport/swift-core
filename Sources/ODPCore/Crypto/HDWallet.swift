import Foundation
import CryptoKit

// BIP-32 hierarchical deterministic key derivation over secp256k1, plus the
// BIP-44 Ethereum account path and EIP-55 address formatting.
public struct HDNode {
  public var privateKey: Data // 32 bytes
  public var chainCode: Data  // 32 bytes
}

public enum HDWallet {
  // Ethereum / Polygon account: m/44'/60'/0'/0/0
  public static let ethereumPath: [(index: UInt32, hardened: Bool)] = [
    (44, true), (60, true), (0, true), (0, false), (0, false),
  ]

  static func masterNode(seed: Data) -> HDNode? {
    let key = SymmetricKey(data: Data("Bitcoin seed".utf8))
    let i = Data(HMAC<SHA512>.authenticationCode(for: seed, using: key))
    let il = Data(i.prefix(32))
    let ir = Data(i.suffix(32))
    guard Secp256k1Context.shared.verifySeckey(il) else { return nil }
    return HDNode(privateKey: il, chainCode: ir)
  }

  static func derive(_ node: HDNode, index: UInt32, hardened: Bool) -> HDNode? {
    var data = Data()
    let childIndex: UInt32 = hardened ? (index | 0x8000_0000) : index

    if hardened {
      data.append(0x00)
      data.append(node.privateKey)
    } else {
      guard let pub = Secp256k1Context.shared.publicKey(privateKey: node.privateKey, compressed: true) else { return nil }
      data.append(pub)
    }
    data.append(contentsOf: [
      UInt8((childIndex >> 24) & 0xff),
      UInt8((childIndex >> 16) & 0xff),
      UInt8((childIndex >> 8) & 0xff),
      UInt8(childIndex & 0xff),
    ])

    let key = SymmetricKey(data: node.chainCode)
    let i = Data(HMAC<SHA512>.authenticationCode(for: data, using: key))
    let il = Data(i.prefix(32))
    let ir = Data(i.suffix(32))

    guard let childKey = Secp256k1Context.shared.tweakAdd(privateKey: node.privateKey, tweak: il) else { return nil }
    return HDNode(privateKey: childKey, chainCode: ir)
  }

  public static func derivePath(seed: Data, path: [(index: UInt32, hardened: Bool)]) -> HDNode? {
    guard var node = masterNode(seed: seed) else { return nil }
    for step in path {
      guard let next = derive(node, index: step.index, hardened: step.hardened) else { return nil }
      node = next
    }
    return node
  }
}

public enum EthereumAddress {
  /// Derives the checksummed 0x address from a 32-byte private key.
  public static func from(privateKey: Data) -> String? {
    guard let pub = Secp256k1Context.shared.publicKey(privateKey: privateKey, compressed: false) else { return nil }
    let body = Data(pub.dropFirst()) // strip 0x04 prefix → 64 bytes X‖Y
    let hash = Keccak256.hash(body)
    return checksummed(Data(hash.suffix(20)))
  }

  /// EIP-55 mixed-case checksum encoding.
  static func checksummed(_ address: Data) -> String {
    let hex = address.hexEncodedString()
    let hashHex = Keccak256.hash(Data(hex.utf8)).hexEncodedString()
    var result = "0x"
    for (i, char) in hex.enumerated() {
      if char.isLetter {
        let hashChar = hashHex[hashHex.index(hashHex.startIndex, offsetBy: i)]
        if let value = hashChar.hexDigitValue, value >= 8 {
          result.append(Character(char.uppercased()))
        } else {
          result.append(char)
        }
      } else {
        result.append(char)
      }
    }
    return result
  }
}
