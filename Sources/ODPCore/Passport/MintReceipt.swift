import Foundation

/// Result of anchoring a passport on-chain. Written into the `.odpass`
/// manifest's `onChain` block so verifiers can locate the transaction.
///
/// The passport ID is assigned by the contract during the mint, not by the
/// app — which is why it is read back from the transaction rather than
/// guessed from a list.
public struct MintReceipt: Equatable, Sendable {
  public var txHash: String
  public var chainId: Int
  public var contract: String
  public var passportId: String
  public var creatorId: String

  public init(
    txHash: String,
    chainId: Int,
    contract: String,
    passportId: String,
    creatorId: String
  ) {
    self.txHash = txHash
    self.chainId = chainId
    self.contract = contract
    self.passportId = passportId
    self.creatorId = creatorId
  }
}
