## Overview

WireKey is an SDK for E2E encryption based on Signal protocol. The SDK comes in multiple languages and targeting multiple platforms. The SDK helps developers to easily integrate E2E encryption in their applications, abstracting away cryptographic complexity. 

The SDK will communicate with the server, which will take care of encryption key rotation/distribution and basic authentication/authorization. Both SDK and server will be open-source, but we also want to offer a paid version of the server, hosted on a cloud, so that paying customers won't have to deploy the open-source server on their infrastructure. The cloud server will also offer some additional features, like audit logs, charts, UI for group management, …. The open-source server will only have a command line interface.

---

## Architecture

WireKey consists of following logical components:

- **Core SDK:**
  - Written in Rust.
  - Implements all core Signal protocol logic, session/key management, crypto primitives, serialization, and most networking logic.
  - Provides abstractions for local storage and websocket functionality, which would be implemented in the wrapping SDKs.
  - Exposes a clear, idiomatic API for wrapping.
  - Think of it as a shared package that is used by all other SDKs.

- **Rust SDK:**
  - Wraps **Core SDK**
  - Provides native Rust-based implementations for storage and websockets
  - Exposes the API for end-users, everything else is not public

- **Other native SDKs:**
  - **Rust, Go, C#, Java, Python**
  - Wrap **Rust SDK**
  - Only thin wrappers around Rust SDK that expose SDK's API in the respective languages

- **JavaScript SDK:**
  - Both for browser and NodeJS
  - Wraps **Core SDK**
  - Implements its own local storage and WebSocket transport (not relying on Rust for these), but delegates crypto/session logic to Rust via WASM.

- **Server**
  - Written in Rust
  - Handles key rotation/distribution, authentication/authorization
  - SDKs running in client applications will synchronize with the server using websocket connections

WireKey is managed as a monorepo, where each component is defined in a separate folder.

---

## API Design

WireKey will be using Signal group protocol for encryption. Core SDK will internally be using encryption sessions which represent groups in Signal protocol. A session can have one or more participants that share encryption keys. When a participant is added to an encryption session, he will start receiving new group encryption keys when key rotation happens. When a participant is removed, he will stop receiving new encryption keys. Encryption keys are rotated every time someone joins or leaves an encryption session. In addition, periodic key rotation can also be implemented.

The core SDK will manage sessions internally, I would like to expose only simple functions from the core SDK via C and WASM bindings. I don't want to use any complex objects in the bindings.

---

## Key Guidelines

### 1. API & Usability

- The public SDK API in every language must be minimal, idiomatic, and easy to use.
- API should expose only simple functions (no complex structs/classes, only primitives, byte arrays, and strings as arguments/results).
- Provide clear, documented methods for core E2E operations:
    - **Session management**: create, open, close, add/remove participants.
    - **Message encryption/decryption**.
    - **Group key distribution** (where applicable).
- Prefer simple, safe defaults; require explicit opt-in for any advanced/unsafe features.

### 2. Security

- All cryptographic operations must strictly follow the Signal protocol spec.
- Never expose, log, or persist sensitive material in plaintext.
- Enforce strong key/identity validation everywhere.
- Use up-to-date, vetted cryptographic primitives only.
- Never leak implementation details through error messages.

### 3. Wrapper Design

- Rust and JS SDKs will wrap core SDK package, implementing their own platform-specific storage and websocket functionality.
- All other SDKs (Go, C#, Java, Python) are thin wrappers around the Rust SDK and do not implement storage or websocket logic.


### 4. Testing & Consistency

- Reuse test vectors and cross-language test cases to ensure consistent encryption/decryption across all SDKs.
- Every language binding must pass conformance tests for all public APIs.
- Security tests are mandatory for all cryptographic routines.
- Focus on testing behavior, not implementations details (i.e., try to minimize usage of mocking)
- Organize complex tests into // Arrange, // Act and // Assert sections
- Try not to use shared initialization logic, each unit test should be independent of others
- If part of test initialization is complex (at least 5 lines) and repeated often in multiple tests, consider creating a test helper function
- Each test case should be defined in a separate unit test
- Use `function_under_test_condition_expected_result` pattern for unit test names
- When testing that a `Result` returned from the system under test is successful, use `.expect(...)` with a descriptive message instead of `assert!(result.is_ok())`.

### 5. Documentation

- All public APIs must be documented with concise usage examples.
- Clearly document any platform-specific behaviors or deviations.
- Documentation must highlight E2E security guarantees, limitations, and intended use cases.

### 6. Simplicity

- Avoid exposing low-level protocol details; only expose what app developers need.
- The SDK must be “batteries included” for common use cases: secure chat, group messaging, etc.
- Favor clear, maintainable implementations over clever or nonstandard designs.

---

## Additional Notes

- Never assume a particular storage, networking, or runtime environment—always validate platform constraints in each wrapper.
- Prefer compile-time or build-time errors over runtime surprises.
- All contributions must be reviewed for cryptographic hygiene and cross-language consistency.

---