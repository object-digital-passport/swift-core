import CryptoKit
import Foundation

/// The two AES-128 keys an NTAG 424 DNA seal needs, derived from the issuer's
/// recovery phrase instead of being stored anywhere.
///
/// SPEC §6 requires the issuer to keep key `00h` — the AppMasterKey — and
/// forbids publishing it, because a successful authentication with it
/// authorises `ChangeKey` over all five keys: anyone who reads the passport
/// could re-key a genuine tag and lock its holder out permanently. What gets
/// published is a non-master application key, `01h`.
///
/// "Retained by the issuer" is satisfied here without a second secret to lose.
/// Both keys are derived from the seed the wallet already has, so restoring
/// the recovery phrase restores control of every seal ever provisioned, and
/// there is nothing extra to back up.
///
/// The construction is the one §20.5 already fixes for edition units —
/// HKDF-SHA256 with an empty salt and a labelled `info` — so the project has
/// one derivation rule rather than two.
///
/// Keys are per-tag: the UID goes into the context, so a published key opens
/// exactly one seal. Nothing else varies, and nothing needs to: a TagTamper
/// chip that is removed reports `TAMPERED` permanently, so a tag cannot be
/// quietly moved to another object and re-used.
public enum SealKeys: Sendable {
  /// The key that authorises re-keying. Never leaves the device.
  public static func appMaster(seed: Data, chainId: UInt64, uid: String) -> Data {
    derive(seed: seed, label: "ODP-SEAL-MASTER-v1", chainId: chainId, uid: uid)
  }

  /// The key written into the `nfc` anchor and published with the passport.
  /// A verifier authenticates against key `01h` with this.
  public static func published(seed: Data, chainId: UInt64, uid: String) -> Data {
    derive(seed: seed, label: "ODP-SEAL-READ-v1", chainId: chainId, uid: uid)
  }

  /// Key number the published key is written to. `00h` is the master and is
  /// deliberately not it.
  public static let publishedKeyNumber: UInt8 = 0x01

  /// `utf8(chainId) || 0x00 || utf8(uid)` — the chain is in the context so the
  /// same tag on a testnet passport never derives the mainnet key. The UID is
  /// lowercased so the case a reader happens to print cannot change the key.
  static func context(chainId: UInt64, uid: String) -> Data {
    var out = Data(String(chainId).utf8)
    out.append(0x00)
    out.append(contentsOf: Data(uid.lowercased().utf8))
    return out
  }

  private static func derive(seed: Data, label: String, chainId: UInt64, uid: String) -> Data {
    var info = Data(label.utf8)
    info.append(contentsOf: context(chainId: chainId, uid: uid))
    let key = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: SymmetricKey(data: seed),
      salt: Data(),
      info: info,
      outputByteCount: 16
    )
    return key.withUnsafeBytes { Data($0) }
  }
}
