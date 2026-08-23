import Foundation
import secp256k1

// Thin Swift wrapper over the libsecp256k1 C API (Boilertalk 0.1.7). The heavy
// elliptic-curve math is the audited bitcoin-core C library, not hand-rolled.
/// The context is immutable after `init` and libsecp256k1 documents signing
/// and verification against a shared context as thread-safe, so the singleton
/// crosses isolation boundaries safely.
final class Secp256k1Context: @unchecked Sendable {
  static let shared = Secp256k1Context()

  private let ctx: OpaquePointer

  private init() {
    guard let ctx = secp256k1_context_create(
      UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
    ) else {
      // The only documented failure is allocation. Nothing in this app has a
      // meaningful answer to "no wallet crypto", so say so rather than
      // signing with a half-built context.
      preconditionFailure("libsecp256k1 context could not be created")
    }
    self.ctx = ctx
    randomize()
  }

  /// Blinds the context against side-channel recovery of the key during
  /// signing. libsecp256k1 recommends this for anything holding real funds;
  /// a failure here is not fatal, it just leaves the default blinding.
  private func randomize() {
    var seed = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, seed.count, &seed) == errSecSuccess else { return }
    _ = secp256k1_context_randomize(ctx, seed)
  }

  func verifySeckey(_ key: Data) -> Bool {
    let bytes = [UInt8](key)
    guard bytes.count == 32 else { return false }
    return secp256k1_ec_seckey_verify(ctx, bytes) == 1
  }

  /// Serialized public key: 65 bytes uncompressed (0x04‖X‖Y) or 33 compressed.
  func publicKey(privateKey: Data, compressed: Bool) -> Data? {
    let priv = [UInt8](privateKey)
    guard priv.count == 32 else { return nil }
    var pub = secp256k1_pubkey()
    guard secp256k1_ec_pubkey_create(ctx, &pub, priv) == 1 else { return nil }
    var outLen = compressed ? 33 : 65
    var out = [UInt8](repeating: 0, count: outLen)
    let flags = UInt32(compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)
    guard secp256k1_ec_pubkey_serialize(ctx, &out, &outLen, &pub, flags) == 1 else { return nil }
    return Data(out[0..<outLen])
  }

  /// ECDSA recoverable signature over a 32-byte message hash. Returns the
  /// 32-byte r and s components plus the recovery id (0…3), which Ethereum
  /// transactions fold into the `v` value. Used to sign EIP-155 transactions.
  func signRecoverable(hash: Data, privateKey: Data) -> (r: Data, s: Data, recid: Int)? {
    let msg = [UInt8](hash)
    let priv = [UInt8](privateKey)
    guard msg.count == 32, priv.count == 32 else { return nil }
    var sig = secp256k1_ecdsa_recoverable_signature()
    guard secp256k1_ecdsa_sign_recoverable(ctx, &sig, msg, priv, nil, nil) == 1 else { return nil }
    var output = [UInt8](repeating: 0, count: 64)
    var recid: Int32 = 0
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &output, &recid, &sig)
    return (Data(output[0..<32]), Data(output[32..<64]), Int(recid))
  }

  /// (privateKey + tweak) mod n, validated. Used for BIP-32 child derivation.
  func tweakAdd(privateKey: Data, tweak: Data) -> Data? {
    var key = [UInt8](privateKey)
    let t = [UInt8](tweak)
    guard key.count == 32, t.count == 32 else { return nil }
    guard secp256k1_ec_privkey_tweak_add(ctx, &key, t) == 1 else { return nil }
    return Data(key)
  }
}
