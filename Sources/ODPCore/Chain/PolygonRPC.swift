import Foundation


// Thin JSON-RPC client for Polygon PoS. Provides the primitives a real mint
// needs — nonce, gas price and raw-transaction broadcast — over the public
// endpoint. The minting flow itself stays stubbed until the ODP contract is
// deployed, but these calls are live and ready to wire.
public struct PolygonRPC: Sendable {
  // Tried in order; on a transport failure (a dead or rate-limited endpoint) the
  // client falls through to the next. A remote/JSON-RPC error — including an
  // eth_call revert — is returned immediately, since retrying won't change it.
  public var endpoints: [URL]
  public var chainId: UInt64 = 137

  init(endpoints: [URL], chainId: UInt64 = 137) {
    self.endpoints = endpoints
    self.chainId = chainId
  }

  init(endpoint: URL, chainId: UInt64 = 137) {
    self.init(endpoints: [endpoint], chainId: chainId)
  }

  public static let mainnet = PolygonRPC(endpoints: [
    URL(string: "https://polygon-bor-rpc.publicnode.com")!,
    URL(string: "https://polygon.llamarpc.com")!,
    URL(string: "https://rpc.ankr.com/polygon")!,
    URL(string: "https://polygon-rpc.com")!,
  ])

  public enum RPCError: Error {
    case transport
    case decode
    case remote(String)

    /// True when a remote error is an EVM revert (as opposed to a node problem).
    var isRevert: Bool {
      if case .remote(let message) = self {
        return message.lowercased().contains("revert")
      }
      return false
    }
  }

  private func call(method: String, params: [Any]) async throws -> Any {
    let body: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": method, "params": params]
    let payload = try JSONSerialization.data(withJSONObject: body)

    var lastError: Error = RPCError.transport
    for endpoint in endpoints {
      do {
        return try await callOnce(endpoint: endpoint, payload: payload)
      } catch let error as RPCError {
        // A revert or other remote error is authoritative — don't retry it.
        if case .remote = error { throw error }
        lastError = error
      } catch {
        lastError = error
      }
    }
    throw lastError
  }

  private func callOnce(endpoint: URL, payload: Data) async throws -> Any {
    var request = URLRequest(url: endpoint)
    request.httpMethod = "POST"
    request.timeoutInterval = 15
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = payload

    let (data, response) = try await URLSession.shared.data(for: request)
    guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
      throw RPCError.transport
    }
    guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw RPCError.decode
    }
    if let error = json["error"] as? [String: Any] {
      throw RPCError.remote(error["message"] as? String ?? "rpc error")
    }
    guard let result = json["result"] else { throw RPCError.decode }
    return result
  }

  /// Pending nonce for an address, as a decimal count.
  public func transactionCount(address: String) async throws -> UInt64 {
    let result = try await call(method: "eth_getTransactionCount", params: [address, "pending"])
    guard let hex = result as? String, let value = UInt64(hexQuantity: hex) else { throw RPCError.decode }
    return value
  }

  /// Current gas price as minimal big-endian wei bytes.
  public func gasPrice() async throws -> Data {
    let result = try await call(method: "eth_gasPrice", params: [])
    guard let hex = result as? String else { throw RPCError.decode }
    return Data(hexQuantity: hex)
  }

  /// Executes a read-only contract call (`eth_call`) and returns the raw ABI
  /// return bytes.
  public func ethCall(to: String, data: Data) async throws -> Data {
    let params: [Any] = [["to": to, "data": "0x" + data.hexEncodedString()], "latest"]
    let result = try await call(method: "eth_call", params: params)
    guard let hex = result as? String, let bytes = Data(hexString: hex) else { throw RPCError.decode }
    return bytes
  }

  /// Current head block number.
  public func blockNumber() async throws -> UInt64 {
    let result = try await call(method: "eth_blockNumber", params: [])
    guard let hex = result as? String, let value = UInt64(hexQuantity: hex) else { throw RPCError.decode }
    return value
  }

  /// Raw `eth_getLogs` entries. A position in `topics` takes a `String` to match
  /// exactly, a `[String]` to match any of several values, or `nil` for
  /// anything; `toBlock` defaults to the head of the chain.
  public func logs(
    address: String,
    topics: [Any?],
    fromBlock: UInt64,
    toBlock: UInt64? = nil
  ) async throws -> [[String: Any]] {
    var filter: [String: Any] = [
      "address": address,
      "fromBlock": "0x" + String(fromBlock, radix: 16),
      "toBlock": toBlock.map { "0x" + String($0, radix: 16) } ?? "latest",
    ]
    if !topics.isEmpty {
      filter["topics"] = topics.map { $0 ?? (NSNull() as Any) }
    }
    let result = try await call(method: "eth_getLogs", params: [filter])
    guard let entries = result as? [[String: Any]] else { throw RPCError.decode }
    return entries
  }

  /// Estimates gas for a transaction to `to` from `from` with `data`.
  public func estimateGas(from: String, to: String, data: Data) async throws -> UInt64 {
    let params: [Any] = [["from": from, "to": to, "data": "0x" + data.hexEncodedString()]]
    let result = try await call(method: "eth_estimateGas", params: params)
    guard let hex = result as? String, let value = UInt64(hexQuantity: hex) else { throw RPCError.decode }
    return value
  }

  /// Native POL (MATIC) balance of an address as minimal big-endian wei bytes.
  public func balance(address: String) async throws -> Data {
    let result = try await call(method: "eth_getBalance", params: [address, "latest"])
    guard let hex = result as? String else { throw RPCError.decode }
    return Data(hexQuantity: hex)
  }

  /// Broadcasts a signed transaction, returning its hash.
  public func sendRawTransaction(_ raw: Data) async throws -> String {
    let result = try await call(method: "eth_sendRawTransaction", params: ["0x" + raw.hexEncodedString()])
    guard let hash = result as? String else { throw RPCError.decode }
    return hash
  }

  /// The whole receipt, or nil while the transaction is still pending. The
  /// logs it carries are the only record of what a transaction actually did —
  /// reading them is how a mint learns which passport ID the contract chose.
  public func transactionReceipt(hash: String) async throws -> [String: Any]? {
    let result = try await call(method: "eth_getTransactionReceipt", params: [hash])
    return result as? [String: Any]
  }

  /// nil while the transaction is still pending; `true` once mined with
  /// status 0x1, `false` if it reverted on-chain.
  public func transactionSucceeded(hash: String) async throws -> Bool? {
    guard let receipt = try await transactionReceipt(hash: hash) else { return nil }
    guard let status = receipt["status"] as? String else { return nil }
    return status == "0x1" || status == "0x01"
  }

  /// Polls until the transaction is mined. Throws `.transport` on timeout.
  public func waitForReceipt(hash: String, timeout: Duration = .seconds(180)) async throws -> Bool {
    let deadline = ContinuousClock.now.advanced(by: timeout)
    while ContinuousClock.now < deadline {
      if let success = try? await transactionSucceeded(hash: hash) {
        return success
      }
      try? await Task.sleep(for: .seconds(3))
    }
    throw RPCError.transport
  }
}

private extension UInt64 {
  init?(hexQuantity hex: String) {
    var string = hex
    if string.hasPrefix("0x") || string.hasPrefix("0X") { string.removeFirst(2) }
    guard let value = UInt64(string, radix: 16) else { return nil }
    self = value
  }
}

private extension Data {
  init(hexQuantity hex: String) {
    var string = hex
    if string.hasPrefix("0x") || string.hasPrefix("0X") { string.removeFirst(2) }
    if string.count % 2 == 1 { string = "0" + string }
    var bytes: [UInt8] = []
    var index = string.startIndex
    while index < string.endIndex {
      let next = string.index(index, offsetBy: 2)
      if let byte = UInt8(string[index..<next], radix: 16) { bytes.append(byte) }
      index = next
    }
    // Drop leading zero bytes to keep a minimal quantity representation.
    while bytes.first == 0 && bytes.count > 1 { bytes.removeFirst() }
    self = Data(bytes)
  }
}
