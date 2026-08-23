import Foundation

/// How a write to the registry gets signed. The mint flow talks to this, so it
/// works the same whether the key lives in this app's vault or in a wallet the
/// user connected over WalletConnect.
public protocol TransactionSender: Sendable {
  /// Signs, broadcasts and waits for the receipt. Returns the transaction hash.
  func send(calldata: Data, from address: String) async throws -> String
}


