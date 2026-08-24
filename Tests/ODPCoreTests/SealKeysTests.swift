import Foundation
import Testing
@testable import ODPCore

// Эти ключи попадают на физическую метку, приклеенную к вещи. Ошибка здесь
// не чинится обновлением приложения: перепрошить пломбу можно только тем
// ключом, который уже на ней, а снять её с объекта — значит убить её.
@Suite("Seal key derivation")
struct SealKeysTests {
  let seed = Data(repeating: 0xAB, count: 64)
  let uid = "04a3f912cc8b4e"

  @Test("Both keys are AES-128 length")
  func length() {
    #expect(SealKeys.appMaster(seed: seed, chainId: 137, uid: uid).count == 16)
    #expect(SealKeys.published(seed: seed, chainId: 137, uid: uid).count == 16)
  }

  /// Самое важное свойство: опубликованный ключ не должен ничего говорить
  /// о мастере. Разные метки `info` в HKDF — ровно то, ради чего он взят.
  @Test("The published key is not the master key")
  func mastersStaySecret() {
    let master = SealKeys.appMaster(seed: seed, chainId: 137, uid: uid)
    let published = SealKeys.published(seed: seed, chainId: 137, uid: uid)
    #expect(master != published)
  }

  @Test("Every tag gets its own key")
  func perTag() {
    let a = SealKeys.published(seed: seed, chainId: 137, uid: "04a3f912cc8b4e")
    let b = SealKeys.published(seed: seed, chainId: 137, uid: "04ffffffffffff")
    #expect(a != b)
  }

  /// Одна и та же метка на тестовой сети не должна давать боевой ключ.
  @Test("The chain is part of the context")
  func chainSeparates() {
    let mainnet = SealKeys.published(seed: seed, chainId: 137, uid: uid)
    let amoy = SealKeys.published(seed: seed, chainId: 80_002, uid: uid)
    #expect(mainnet != amoy)
  }

  /// Читатель может отдать UID в любом регистре — ключ обязан совпасть,
  /// иначе исправная пломба прочитается как чужая.
  @Test("UID case cannot change the key")
  func uidCaseInsensitive() {
    let lower = SealKeys.published(seed: seed, chainId: 137, uid: "04a3f912cc8b4e")
    let upper = SealKeys.published(seed: seed, chainId: 137, uid: "04A3F912CC8B4E")
    #expect(lower == upper)
  }

  /// Восстановление по фразе обязано вернуть управление каждой пломбой.
  @Test("The same seed reproduces the same keys")
  func deterministic() {
    let once = SealKeys.appMaster(seed: seed, chainId: 137, uid: uid)
    let again = SealKeys.appMaster(seed: Data(repeating: 0xAB, count: 64), chainId: 137, uid: uid)
    #expect(once == again)
  }

  @Test("A different phrase gives different keys")
  func seedSeparates() {
    let other = Data(repeating: 0xCD, count: 64)
    #expect(SealKeys.published(seed: seed, chainId: 137, uid: uid)
            != SealKeys.published(seed: other, chainId: 137, uid: uid))
  }

  @Test("The published key never goes to key 00h")
  func notTheMasterSlot() {
    #expect(SealKeys.publishedKeyNumber != 0x00)
  }
}
