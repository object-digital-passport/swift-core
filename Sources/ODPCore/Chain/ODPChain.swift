import Foundation

/// The live ODP deployment on Polygon PoS (chain 137), from the repository's
/// `deployments/polygon.json`. Reads and mints go through `contract`; the
/// satellites are addressed directly only for their specific features.
public enum ODPChain {
  public static let network = "polygon"
  public static let chainId: UInt64 = 137

  /// Пустой bytes32. Реестр возвращает его там, где значения нет, и
  /// отличать «нет записи» от «запись с нулём» приходится всем читателям.
  public static let zeroHash = "0x" + String(repeating: "0", count: 64)

  /// Пустой адрес — та же роль, что у `zeroHash`, но для адресных полей.
  public static let zeroAddress = "0x" + String(repeating: "0", count: 40)
  public static let contractVersion: UInt8 = 6
  public static let rpc = PolygonRPC.mainnet

  /// Reading the append-only event log needs a node that serves `eth_getLogs`
  /// over the whole chain. The endpoints behind `rpc` refuse it on their free
  /// tiers ("archive requests require a token"), so log reads go here instead.
  public static let logRpc = PolygonRPC(endpoints: [
    URL(string: "https://polygon.gateway.tenderly.co")!,
    URL(string: "https://polygon.drpc.org")!,
  ])

  public static let contract = "0x012aC6393464A73EC16131D701ff2e000695b91b"
  public static let passportLib = "0xB7D7B8485eeb385c375ABd91035F5a6914171ccE"
  public static let walletDocumentAnchor = "0x35df3773919D9F10e5F8838abaa453DE120e6Cb4"
  public static let counterfeitConcern = "0x692935d6c1532b47cE0459bF1E9549991d0eD2C9"
  public static let relations = "0x2ea6f05a050973afa14E61b1Ea19De92621e3661"
  public static let proofRegistry = "0x990FCc2E587d9f2cDb9c73083E9f90793CeF7F49"
  public static let extensionRouter = "0x3fa8f213399a2A9f7Da4bF7D8a9D7D42E8AEF822"
  public static let deployedBy = "0xefB9f9Fa39965Ab1df3D244ecAEDef23D5242587"
}
