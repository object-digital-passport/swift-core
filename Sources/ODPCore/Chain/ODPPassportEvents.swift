import Foundation

/// The seven event kinds of the append-only layer (`ODPEventKinds` in
/// `chain/contracts/ODPPassportTypes.sol`). The card minted on chain never
/// changes; everything that happens to the object afterwards is an event, and
/// the current value of any mutable aspect is the latest event of that kind.
public enum ODPEventKind: UInt8, CaseIterable, Identifiable, Sendable {
  case status = 1
  case location = 2
  case rights = 3
  case condition = 4
  case damage = 5
  case restoration = 6
  case custom = 7

  public var id: UInt8 { rawValue }

  public var symbol: String {
    switch self {
    case .status: return "flag"
    case .location: return "mappin.and.ellipse"
    case .rights: return "signature"
    case .condition: return "heart.text.square"
    case .damage: return "exclamationmark.triangle"
    case .restoration: return "wrench.and.screwdriver"
    case .custom: return "square.dashed"
    }
  }

  public func title(russian: Bool) -> String {
    switch self {
    case .status: return russian ? "Статус" : "Status"
    case .location: return russian ? "Локация" : "Location"
    case .rights: return russian ? "Права" : "Rights"
    case .condition: return russian ? "Состояние" : "Condition"
    case .damage: return russian ? "Повреждение" : "Damage"
    case .restoration: return russian ? "Реставрация" : "Restoration"
    case .custom: return russian ? "Своё событие" : "Custom"
    }
  }

  /// Only a status event carries a numeric value — the new lifecycle status.
  /// Every other kind must send 0.
  public var carriesValue: Bool { self == .status }
}

/// One entry of a passport's history, read back from the contract's log.
public struct ODPPassportEvent: Identifiable, Equatable, Sendable {
  public enum Payload: Equatable, Sendable {
    case recorded(ODPEventKind)
    case transferred(from: String, to: String)
  }

  public var payload: Payload
  /// The log carries only `keccak(passportId)`, so this is filled in from the
  /// ID we asked about rather than decoded.
  public var passportId: String = ""
  public var value: UInt8 = 0
  public var note: String = ""
  public var attachmentHash: String = ""
  public var attachmentUrl: String = ""
  /// Who signed the transaction — `recordedBy` for an event, the previous
  /// owner for a transfer.
  public var actor: String = ""
  public var date: Date?
  public var txHash: String = ""
  public var blockNumber: UInt64 = 0
  public var logIndex: UInt64 = 0

  public var id: String { "\(txHash)-\(logIndex)" }

  public var hasAttachment: Bool {
    !attachmentHash.isEmpty && attachmentHash != ODPChain.zeroHash
  }
}

/// Reads and writes the passport events layer on the main registry.
/// Signatures come from `chain/contracts/ObjectDigitalPassport.sol`:
///
///     function recordPassportEvent(string, uint8, uint8, string, bytes32, string)
///     event PassportEventRecorded(string indexed, uint8 indexed, uint8, string,
///                                 bytes32, string, address, uint256)
///     event PassportTransferred(string indexed, address indexed, address indexed, uint256)
///
/// On-chain storage keeps only a summary (`eventCount`, `lastEventKind`,
/// `lastEventAt`, `lifecycleStatus`); the history itself lives in the log.
public struct ODPPassportEventLog: Sendable {
  public var rpc: PolygonRPC = ODPChain.rpc
  public var logRpc: PolygonRPC = ODPChain.logRpc
  public var address: String = ODPChain.contract

  /// По умолчанию — боевой реестр; подменяется в тестах и на другой сети.
  public init(
    rpc: PolygonRPC = ODPChain.rpc,
    logRpc: PolygonRPC = ODPChain.logRpc,
    address: String = ODPChain.contract
  ) {
    self.rpc = rpc
    self.logRpc = logRpc
    self.address = address
  }

  /// A free-tier node that caps `eth_getLogs` ranges still gives us the recent
  /// past: 30 windows of 9 500 blocks is roughly a week of Polygon.
  private static let window: UInt64 = 9_500
  private static let windowBudget = 30

  public static let recordedTopic = topic(
    "PassportEventRecorded(string,uint8,uint8,string,bytes32,string,address,uint256)"
  )
  public static let transferredTopic = topic("PassportTransferred(string,address,address,uint256)")

  private static let eventsKind: ABI.Kind = .tuple([.uint, .uint, .uint, .uint])

  // MARK: - Reads

  /// The cheap summary every passport screen can afford: one `eth_call`.
  public struct Summary: Equatable {
    public var eventCount: UInt32 = 0
    public var lastEventKind: UInt8 = 0
    public var lastEventAt: Date?
    public var lifecycleStatus: UInt8 = 0

    public var isEmpty: Bool { eventCount == 0 }
  }

  public func summary(passportId: String) async -> Summary? {
    let call = ABI.encodeCall("getPassportEvents(string)", [.string(passportId)])
    guard let ret = try? await rpc.ethCall(to: address, data: call),
          let decoded = ABI.decode([Self.eventsKind], from: ret),
          case .tuple(let f) = decoded.first, f.count >= 4 else { return nil }
    let seconds = f[2].uintValue
    return Summary(
      eventCount: UInt32(truncatingIfNeeded: f[0].uintValue),
      lastEventKind: UInt8(f[1].uintValue & 0xFF),
      lastEventAt: seconds > 0 ? Date(timeIntervalSince1970: TimeInterval(seconds)) : nil,
      lifecycleStatus: UInt8(f[3].uintValue & 0xFF)
    )
  }

  /// Full history for one passport, oldest first. Both event families are
  /// fetched in one request: `topics[0]` is left open and the kind is decided
  /// locally, since a passport ID is the indexed second topic of either.
  public func events(passportId: String) async -> [ODPPassportEvent] {
    await events(passportIds: [passportId])
  }

  /// History for a whole collection in one request: the indexed passport ID
  /// takes a list of values, so the node returns only these passports' logs and
  /// each entry is matched back to its ID by hash.
  public func events(passportIds: [String]) async -> [ODPPassportEvent] {
    let ids = passportIds.filter { !$0.isEmpty }
    guard !ids.isEmpty else { return [] }

    var idByTopic: [String: String] = [:]
    for id in ids { idByTopic[Self.hashedTopic(id)] = id }

    let raw = await rawLogs(idTopics: Array(idByTopic.keys))
    return raw
      .compactMap { log -> ODPPassportEvent? in
        guard var event = Self.parse(log),
              let topics = log["topics"] as? [String], topics.count >= 2,
              let id = idByTopic[topics[1].lowercased()] else { return nil }
        event.passportId = id
        return event
      }
      .sorted { ($0.blockNumber, $0.logIndex) < ($1.blockNumber, $1.logIndex) }
  }

  private func rawLogs(idTopics: [String]) async -> [[String: Any]] {
    // One value stays a plain topic; several become an OR-list.
    let filter: Any = idTopics.count == 1 ? idTopics[0] : idTopics

    if let full = try? await logRpc.logs(
      address: address,
      topics: [nil, filter],
      fromBlock: 0
    ) {
      return full
    }

    // Range-capped node: walk a bounded window back from the head, so a recent
    // history still shows rather than nothing at all.
    guard let head = try? await logRpc.blockNumber() else { return [] }
    var found: [[String: Any]] = []
    var upper = head
    for _ in 0..<Self.windowBudget {
      let lower = upper > Self.window ? upper - Self.window : 0
      let page = (try? await logRpc.logs(
        address: address,
        topics: [nil, filter],
        fromBlock: lower,
        toBlock: upper
      )) ?? []
      found.append(contentsOf: page)
      if lower == 0 { break }
      upper = lower - 1
    }
    return found
  }

  // MARK: - Writes

  /// `recordPassportEvent` calldata. Callable by the creator, the current owner
  /// or governance; a revoked passport rejects it.
  public static func recordCalldata(
    passportId: String,
    kind: ODPEventKind,
    value: UInt8,
    note: String,
    attachmentHash: String,
    attachmentUrl: String
  ) -> Data {
    let hash = ODPProofRegistry.bytes32(attachmentHash)
    // The contract requires an empty URL when no attachment is hashed.
    let url = hash.allSatisfy { $0 == 0 } ? "" : attachmentUrl
    return ABI.encodeCall(
      "recordPassportEvent(string,uint8,uint8,string,bytes32,string)",
      [
        .string(passportId),
        ABI.uint(UInt64(kind.rawValue)),
        ABI.uint(UInt64(kind.carriesValue ? value : 0)),
        .string(note),
        .fixedBytes(hash),
        .string(url),
      ]
    )
  }

  /// `transferPassport` calldata. Callable only by the current owner, and the
  /// contract rejects the zero address. Emits `PassportTransferred`, which is
  /// how a change of hands enters the history.
  public static func transferCalldata(passportId: String, newOwner: String) -> Data {
    ABI.encodeCall(
      "transferPassport(string,address)",
      [.string(passportId), .address(newOwner)]
    )
  }

  /// A 20-byte hex address that isn't the zero address.
  public static func isUsableOwner(_ address: String) -> Bool {
    let text = address.trimmingCharacters(in: .whitespacesAndNewlines)
    guard text.count == 42, text.hasPrefix("0x") || text.hasPrefix("0X"),
          let bytes = Data(hexString: text), bytes.count == 20 else { return false }
    return !bytes.allSatisfy { $0 == 0 }
  }

  /// The contract caps a note at 256 bytes, so trim by UTF-8 length rather than
  /// by character count.
  public static func trimNote(_ note: String) -> String {
    var text = note.trimmingCharacters(in: .whitespacesAndNewlines)
    while text.utf8.count > 256 { text.removeLast() }
    return text
  }

  // MARK: - Log parsing

  private static func parse(_ log: [String: Any]) -> ODPPassportEvent? {
    guard let topics = log["topics"] as? [String], let topic0 = topics.first?.lowercased(),
          let data = Data(hexString: log["data"] as? String ?? "") else { return nil }

    let txHash = log["transactionHash"] as? String ?? ""
    let block = quantity(log["blockNumber"] as? String)
    let index = quantity(log["logIndex"] as? String)

    switch topic0 {
    case recordedTopic:
      guard topics.count >= 3,
            let kind = ODPEventKind(rawValue: UInt8(quantity(topics[2]) & 0xFF)),
            let f = ABI.decode([.uint, .string, .bytes32, .string, .address, .uint], from: data),
            f.count >= 6 else { return nil }
      let seconds = f[5].uintValue
      return ODPPassportEvent(
        payload: .recorded(kind),
        value: UInt8(f[0].uintValue & 0xFF),
        note: f[1].stringValue ?? "",
        attachmentHash: f[2].hexValue ?? "",
        attachmentUrl: f[3].stringValue ?? "",
        actor: f[4].addressValue ?? "",
        date: seconds > 0 ? Date(timeIntervalSince1970: TimeInterval(seconds)) : nil,
        txHash: txHash,
        blockNumber: block,
        logIndex: index
      )

    case transferredTopic:
      guard topics.count >= 4 else { return nil }
      let from = address(fromTopic: topics[2])
      let to = address(fromTopic: topics[3])
      let seconds = ABI.decode([.uint], from: data)?.first?.uintValue ?? 0
      return ODPPassportEvent(
        payload: .transferred(from: from, to: to),
        actor: from,
        date: seconds > 0 ? Date(timeIntervalSince1970: TimeInterval(seconds)) : nil,
        txHash: txHash,
        blockNumber: block,
        logIndex: index
      )

    default:
      // The registry emits mint and revocation events on the same passport ID;
      // those already have their own places in the interface.
      return nil
    }
  }

  /// keccak256 of a canonical event signature — `topics[0]` of its logs.
  private static func topic(_ signature: String) -> String {
    "0x" + Keccak256.hash(Data(signature.utf8)).hexEncodedString()
  }

  /// An indexed `string` argument is stored as its keccak hash, not its text.
  public static func hashedTopic(_ value: String) -> String {
    "0x" + Keccak256.hash(Data(value.utf8)).hexEncodedString()
  }

  /// Numeric value of a 32-byte topic word (or any hex quantity).
  private static func quantity(_ hex: String?) -> UInt64 {
    var text = hex ?? ""
    if text.hasPrefix("0x") || text.hasPrefix("0X") { text.removeFirst(2) }
    // A full word is 64 hex chars — more than UInt64 holds, and the values we
    // read from topics (a uint8 kind, a log index) live in the low bytes.
    if text.count > 16 { text = String(text.suffix(16)) }
    return UInt64(text, radix: 16) ?? 0
  }

  private static func address(fromTopic topic: String) -> String {
    var text = topic
    if text.hasPrefix("0x") || text.hasPrefix("0X") { text.removeFirst(2) }
    guard text.count >= 40 else { return "" }
    return "0x" + String(text.suffix(40))
  }
}
