import Foundation

public enum Identity {
  public static func randomProfileId(type: String) -> String {
    let groups = (0..<4).map { _ in String(format: "%03d", Int.random(in: 0...999)) }
    return "\(type)-\(groups.joined(separator: "-"))"
  }

  public static func randomPassportId(date: Date = Date()) -> String {
    var calendar = Calendar(identifier: .gregorian)
    calendar.timeZone = TimeZone(identifier: "UTC")!
    let year = calendar.component(.year, from: date)
    let month = calendar.component(.month, from: date)
    let number = String(format: "%09d", Int.random(in: 0..<1_000_000_000))
    return String(format: "ODP-%04d-%02d-%@", year, month, number)
  }

  /// `Regex` is not `Sendable` because in general it can carry a custom
  /// consuming component with state of its own. This one is a literal with no
  /// such component — a compiled program that is never written to after it is
  /// built, and matching does not mutate it. Making it computed instead would
  /// rebuild that program on every call, and this runs once per passport while
  /// collections render.
  nonisolated(unsafe) static let passportIdRegex = /^ODP-[0-9]{4}-(0[1-9]|1[0-2])-[0-9]{9}$/

  public static func isValidPassportId(_ id: String) -> Bool {
    id.wholeMatch(of: passportIdRegex) != nil
  }

  public static func normalizePassportId(_ raw: String) -> String {
    raw.uppercased().filter { !$0.isWhitespace && $0 != "–" && $0 != "—" }
  }

  public static func shortenAddress(_ address: String) -> String {
    guard address.count > 12 else { return address }
    return "\(address.prefix(6))...\(address.suffix(4))"
  }
}
