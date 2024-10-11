# Rust JWT Library

A simple Rust library for encoding, decoding, and validating JSON Web Tokens (JWTs) implemented using Rust Crypto libraries. This library supports HMAC, RSA, and ECDSA and it can be compiled as Rust library or WebAssembly.

## Getting Started

Add this library to your `Cargo.toml` dependencies:

```toml
[dependencies]
jwt-rustcrypto = "0.1.0"
```

### Example: Encoding and Decoding a JWT

```rust
use serde_json::json;
use rust_jwt::{Algorithm, Header, SigningKey, VerifyingKey, encode, decode, ValidationOptions};

fn main() {
    let header = Header::new(Algorithm::HS256);
    let payload = json!({
        "sub": "1234567890",
        "name": "John Doe",
        "iat": 1516239022
    });

    let signing_key = SigningKey::from_secret(b"mysecret");

    let jwt = encode(&header, &signing_key, &payload).expect("Failed to encode JWT");
    println!("Encoded JWT: {}", jwt);

    let verifying_key = VerifyingKey::from_secret(b"mysecret");

    let validation_options = ValidationOptions::default().with_algorithm(Algorithm::HS256);

    let decoded = decode(&jwt, &verifying_key, &validation_options)
        .expect("Failed to decode or validate JWT");

    println!("Decoded Header: {:?}", decoded.header);
    println!("Decoded Payload: {:?}", decoded.payload);
}
```

### Example: Decoding Only (No Signature Verification)

```rust
use rust_jwt::{decode_only};

fn main() {
    let token = "your_jwt_here";
    let decoded = decode_only(token).expect("Failed to decode JWT");

    println!("Decoded Header: {:?}", decoded.header);
    println!("Decoded Payload: {:?}", decoded.payload);
}
```

## Supported Algorithms

The library supports the following signing and verifying algorithms:

- **HMAC**: `HS256`, `HS384`, `HS512`
- **RSA**: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`
- **ECDSA**: `ES256`, `ES256K`, `ES384`, `ES512`

## Installation and Setup

To use this library, simply add it to your project's dependencies as shown in the [Getting Started](#getting-started) section.

### WebAssembly Support

To compile this library to WebAssembly, first install the target:

```bash
rustup target add wasm32-unknown-unknown
```

Then, build the library for the WebAssembly target:

```bash
cargo build --target wasm32-unknown-unknown --release
```

### Building

To build the Rust library:

```bash
cargo build --release
```

### Testing

To run the test suite:

```bash
cargo test
```

## Documentation

### Encoding a JWT

To create a signed JWT, you need a header, payload, and a signing key. Use the `encode` function to generate a signed JWT:

```rust
use rust_jwt::{Header, SigningKey, encode};
use serde_json::json;

let header = Header::new(Algorithm::HS256);
let payload = json!({
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
});
let signing_key = SigningKey::from_secret(b"mysecret");

let token = encode(&header, &signing_key, &payload).expect("Failed to encode JWT");
```

### Decoding a JWT

To decode and validate a JWT, use the `decode` function along with the verification key and validation options:

```rust
use rust_jwt::{decode, VerifyingKey, ValidationOptions, Algorithm};

let verification_key = VerifyingKey::from_secret(b"mysecret");
let validation_options = ValidationOptions::default().with_algorithm(Algorithm::HS256);

let decoded = decode(&token, &verification_key, &validation_options).expect("Failed to decode JWT");
println!("Decoded Header: {:?}", decoded.header);
println!("Decoded Payload: {:?}", decoded.payload);
```

### Encoding a JWT with RSA Key

To create a signed JWT using an RSA key, you need to load the private key and use it for signing:

```rust
use rust_jwt::{Algorithm, Header, SigningKey, encode};
use serde_json::json;
use std::fs;

let rsa_private_key = fs::read_to_string("path/to/rsa_private_key.pem")
    .expect("Failed to read RSA private key");

let header = Header::new(Algorithm::RS256);
let payload = json!({
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
});
let signing_key = SigningKey::from_rsa_pem(rsa_private_key.as_bytes())
    .expect("Failed to create signing key from RSA private key");

let token = encode(&header, &signing_key, &payload)
    .expect("Failed to encode JWT with RSA key");
println!("Encoded JWT with RSA Key: {}", token);
```

### Decoding a JWT with RSA Key

To decode and verify a JWT using an RSA public key, use the decode function along with the verification key and validation options:

```rust
use rust_jwt::{decode, VerifyingKey, ValidationOptions, Algorithm};
use std::fs;

let rsa_public_key = fs::read_to_string("path/to/rsa_public_key.pem")
    .expect("Failed to read RSA public key");

let verification_key = VerifyingKey::from_rsa_pem(rsa_public_key.as_bytes())
    .expect("Failed to create verifying key from RSA public key");

let validation_options = ValidationOptions::default().with_algorithm(Algorithm::RS256);

let decoded = decode(&token, &verification_key, &validation_options)
    .expect("Failed to decode or validate JWT with RSA key");

println!("Decoded Header: {:?}", decoded.header);
println!("Decoded Payload: {:?}", decoded.payload);
```

### Error Handling

Errors in this library are represented by the `Error` enum, which provides detailed messages for various failure cases, such as invalid signatures, expired tokens, and unsupported algorithms.

## Contributing

Contributions are welcome! Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

