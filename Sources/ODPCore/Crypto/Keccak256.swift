import Foundation

// Keccak-256 (the pre-standard SHA-3 variant Ethereum uses: 0x01 domain
// padding, not the 0x06 of FIPS-202 SHA3-256). Pure Swift, verified against
// the empty-input vector c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470.
public enum Keccak256 {
  public static func hash(_ input: Data) -> Data {
    let rate = 136 // 1088-bit rate for 256-bit output
    var state = [UInt64](repeating: 0, count: 25)

    var message = [UInt8](input)
    message.append(0x01)
    while message.count % rate != 0 { message.append(0) }
    message[message.count - 1] |= 0x80

    var offset = 0
    while offset < message.count {
      for i in 0..<(rate / 8) {
        var lane: UInt64 = 0
        for j in 0..<8 {
          lane |= UInt64(message[offset + i * 8 + j]) << (8 * UInt64(j))
        }
        state[i] ^= lane
      }
      permute(&state)
      offset += rate
    }

    var out = [UInt8]()
    out.reserveCapacity(32)
    for i in 0..<4 {
      let lane = state[i]
      for j in 0..<8 { out.append(UInt8((lane >> (8 * UInt64(j))) & 0xff)) }
    }
    return Data(out)
  }

  private static let rho: [UInt64] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
    25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
  ]

  private static let rc: [UInt64] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
  ]

  private static func rotl(_ x: UInt64, _ n: UInt64) -> UInt64 {
    n == 0 ? x : (x << n) | (x >> (64 - n))
  }

  private static func permute(_ a: inout [UInt64]) {
    for round in 0..<24 {
      // θ
      var c = [UInt64](repeating: 0, count: 5)
      for x in 0..<5 { c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] }
      var d = [UInt64](repeating: 0, count: 5)
      for x in 0..<5 { d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1) }
      for x in 0..<5 { for y in 0..<5 { a[x + 5 * y] ^= d[x] } }

      // ρ and π
      var b = [UInt64](repeating: 0, count: 25)
      for x in 0..<5 {
        for y in 0..<5 {
          let idx = x + 5 * y
          let newIdx = y + 5 * ((2 * x + 3 * y) % 5)
          b[newIdx] = rotl(a[idx], rho[idx])
        }
      }

      // χ
      for x in 0..<5 {
        for y in 0..<5 {
          a[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        }
      }

      // ι
      a[0] ^= rc[round]
    }
  }
}
