# swift-core

The parts of [Object Digital Passport](https://github.com/object-digital-passport/specifications) that decide whether a passport verifies: canonical form and hashes, registry reads, and the wallet cryptography underneath them.

**MIT.** The standard is open, and the code that decides whether something conforms to it should be readable by anyone implementing against it. Cryptography you cannot read is not cryptography, it is a promise.

## What is here

| Module | Contains | Builds on |
|---|---|---|
| `ODPCore` | Canonical form, `dataHash` / `anchorsHash`, ABI and registry access, BIP-39, HD derivation, Keccak-256, RLP, transaction signing | anywhere Swift runs |

A second module for the NTAG 424 seal check will follow. It needs CoreNFC and therefore only builds for Apple platforms, which is why it is kept apart: canonical form and hashing should be testable in CI without a simulator.

## Use it

```swift
.package(url: "https://github.com/object-digital-passport/swift-core", from: "0.1.0")
```

## The normative text is elsewhere

`SPEC.md` in the [specifications repository](https://github.com/object-digital-passport/specifications) defines what a passport is and what verification must check. **This package is one implementation of that.** Where the two disagree, the specification is right and this is the bug — including in the conformance vectors, which are published there and asserted against Solidity.

## Status

Early. Extracted from the ODP app for Apple platforms, which is where it has been running; the split exists so that the verification path can be read and reused without the app around it.
