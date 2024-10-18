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
use jwt_rustcrypto::{Algorithm, Header, SigningKey, VerifyingKey, encode, decode, ValidationOptions};

let header = Header::new(Algorithm::HS256);
let signing_key = SigningKey::from_secret(b"mysecret");
let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

let encoded = encode(&header, &signing_key, &payload);
assert!(encoded.is_ok());
println!("JWT {}", encoded.unwrap());
```

### Example: Decoding Only (No Signature Verification)

```rust
use jwt_rustcrypto::{decode_only};

let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
let decoded = decode_only(token).expect("Failed to decode JWT");

println!("Decoded Header: {:?}", decoded.header);
println!("Decoded Payload: {:?}", decoded.payload);
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
use jwt_rustcrypto::{Algorithm, Header, SigningKey, encode, decode};
use serde_json::json;

let header = Header::new(Algorithm::HS256);
let payload = json!({
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022
});
let signing_key = SigningKey::from_secret(b"mysecret");
let header = Header::new(Algorithm::HS256);
let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

let token = encode(&header, &signing_key, &payload).expect("Failed to encode JWT");
```

### Decoding a JWT

To decode and validate a JWT, use the `decode` function along with the verification key and validation options:

```rust
use jwt_rustcrypto::{decode, encode, Header, SigningKey, VerifyingKey, ValidationOptions, Algorithm};
use serde_json::json;

let signing_key = SigningKey::from_secret(b"mysecret");
let verification_key = VerifyingKey::from_secret(b"mysecret");
let validation_options = ValidationOptions::default().with_algorithm(Algorithm::HS256).without_expiry();
let header = Header::new(Algorithm::HS256);
let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

let token = encode(&header, &signing_key, &payload).expect("Failed to encode JWT");
let decoded = decode(&token, &verification_key, &validation_options).expect("Failed to decode JWT");
println!("Decoded Header: {:?}", decoded.header);
println!("Decoded Payload: {:?}", decoded.payload);
```

### Encoding a JWT with RSA Key

To create a signed JWT using an RSA key, you need to load the private key and use it for signing:

```rust
use jwt_rustcrypto::{Algorithm, Header, SigningKey, encode};
use serde_json::json;
use std::fs;

let rsa_private_key = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCU72wNWzLQool2
+VviuF4rKaCFJurXyMKY2CDOY3WP+99cEG9rTvDRBQq6bnkb3bUDmz+hncVHLJiP
+eQqOLMVNuJ0dEMrbkQ8gbEviB4TScmlpqDbQ+qJTx+3cqMTnX99StTJ4yTTaVdP
nId6rNOo3qwngl/DXuvCoQ1mregh1KQe8PaFsmlxmQ2SrPE/qnw0q6eM0CSRsEIg
p0zOU8tFgnaNbcQ3LXgpz1+cku7WzJV8S90Fxw1IKPRR/8xzeGtyzSRyKpVlNje6
8GlCg8bBnrpQnmb02MRrQi28Jdarh07rDhlRkU1WT71EL/tS6EvtNYXdD76sBCVJ
TmXhlnyVAgMBAAECggEAAxAb2152LUV0D3oejwtJn7IFQ7FcM3N4HqdhoInGsvjA
5czOVDLVNjpxt3A3YppTQBXv36wCxAb0kEMMYGeDT1SUoN58CMDSYggsxuFFKEWX
m9keBirGADlPWd95ErMys9BXj46LUfAg3cATWgBQTgqRfpjqZtzLez8Cq1gfDDfV
eMINKyxJHFABSSAX1NAfcJm/2vuBYN2oNNv+JdI1qlgL2onHFQmuOQl+H1SX2JEl
IY7H1ATA39PRg8dTSYBo42qQ8jDmvVzgLVXOaOtWZJvZL8RalZVkqAPY8NncxyGF
NlmzqfMCta6MCuxydB91ZXpAwuZnKuUz5CMPA9a4FQKBgQDGLlybTFckhXFZ0VXg
fEn51quOMkvlMrRgd8F4JMI79+pq0KHaSM0EpCjOv3NqAectGQmbMQB8LuISreso
ZuRyg2ScJSowbDu379ku/wOZpm5vSmBsfzHWas2jT1x4/6PYGnNMQKv1IkD9K4Eg
0ewejTv4avU+ZZW30HMmV0iHJwKBgQDAYwNyWp+hprD9lC02DA5yDAZRgzWBltt2
0NxyRXDV+CNZAfdn7xFPo6OcSzCeLVVglKjnJ4RCqFJJ6wjGsFz3ymXXql3bjvOY
yYlQxEBfkHMAJb7N6We/lD8GNWZTffFNbsOsWUla9XsbI8vhbF/VrFIrtkKt6vZZ
xJNiZQNT4wKBgQDAAlsm+6fScpeH9hHGFaV2sk40zvZJcf7hGCYSSUsG3wP3yXuH
CdHZFVOUPFmN85oPT5rHCYr2xlWy015rHoVnjXYE8t0VXUfexjseFWVfkKiemukh
NXsLyx7BgzqM4OHVloru7hmsvytIHsZVDg4+64eW/8nsUm/kT8nA9AAJMQKBgEBA
EQOczlkPMWbOmLbHGf/ukiGg3zqzJgItSKIFHOTopO1x4a1dQvvE27wzxD3fR/ck
TrA8G0ijrC+xhdHNTo8WkiKPbB8KQ8JP9EL797+ynyV6dZmRDKwHl3C8XrsdgXvp
tQGXJA9zkjSDJPDY37ydeyfMC8LHiJR8OPiQYacfAoGBAKu0smpwESWQ1NrRMji0
OUVLYDPyQqybgdYS6PAQiJYpKCCDNofCO676XqYC35ss4RweabgTL7VLsEL5Xz1x
pt/agClszuk33DxAk7uqRgbZzVo5PBMhxA1AA9Xc9aho4f8tavTZWf9ARjncmYZd
g/81VtrJi19YiFd+h0JnATsq
-----END PRIVATE KEY-----"#;

let header = Header::new(Algorithm::RS256);
let signing_key =
    SigningKey::from_rsa_pem(rsa_private_key.as_bytes()).unwrap();
let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

let encoded = encode(&header, &signing_key, &payload);
println!("JWT {}", encoded.unwrap());
```

### Decoding a JWT with RSA Key

To decode and verify a JWT using an RSA public key, use the decode function along with the verification key and validation options:

```rust
use jwt_rustcrypto::{decode, encode, Header, SigningKey, VerifyingKey, ValidationOptions, Algorithm};
use serde_json::json;

let rsa_private_key = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCU72wNWzLQool2
+VviuF4rKaCFJurXyMKY2CDOY3WP+99cEG9rTvDRBQq6bnkb3bUDmz+hncVHLJiP
+eQqOLMVNuJ0dEMrbkQ8gbEviB4TScmlpqDbQ+qJTx+3cqMTnX99StTJ4yTTaVdP
nId6rNOo3qwngl/DXuvCoQ1mregh1KQe8PaFsmlxmQ2SrPE/qnw0q6eM0CSRsEIg
p0zOU8tFgnaNbcQ3LXgpz1+cku7WzJV8S90Fxw1IKPRR/8xzeGtyzSRyKpVlNje6
8GlCg8bBnrpQnmb02MRrQi28Jdarh07rDhlRkU1WT71EL/tS6EvtNYXdD76sBCVJ
TmXhlnyVAgMBAAECggEAAxAb2152LUV0D3oejwtJn7IFQ7FcM3N4HqdhoInGsvjA
5czOVDLVNjpxt3A3YppTQBXv36wCxAb0kEMMYGeDT1SUoN58CMDSYggsxuFFKEWX
m9keBirGADlPWd95ErMys9BXj46LUfAg3cATWgBQTgqRfpjqZtzLez8Cq1gfDDfV
eMINKyxJHFABSSAX1NAfcJm/2vuBYN2oNNv+JdI1qlgL2onHFQmuOQl+H1SX2JEl
IY7H1ATA39PRg8dTSYBo42qQ8jDmvVzgLVXOaOtWZJvZL8RalZVkqAPY8NncxyGF
NlmzqfMCta6MCuxydB91ZXpAwuZnKuUz5CMPA9a4FQKBgQDGLlybTFckhXFZ0VXg
fEn51quOMkvlMrRgd8F4JMI79+pq0KHaSM0EpCjOv3NqAectGQmbMQB8LuISreso
ZuRyg2ScJSowbDu379ku/wOZpm5vSmBsfzHWas2jT1x4/6PYGnNMQKv1IkD9K4Eg
0ewejTv4avU+ZZW30HMmV0iHJwKBgQDAYwNyWp+hprD9lC02DA5yDAZRgzWBltt2
0NxyRXDV+CNZAfdn7xFPo6OcSzCeLVVglKjnJ4RCqFJJ6wjGsFz3ymXXql3bjvOY
yYlQxEBfkHMAJb7N6We/lD8GNWZTffFNbsOsWUla9XsbI8vhbF/VrFIrtkKt6vZZ
xJNiZQNT4wKBgQDAAlsm+6fScpeH9hHGFaV2sk40zvZJcf7hGCYSSUsG3wP3yXuH
CdHZFVOUPFmN85oPT5rHCYr2xlWy015rHoVnjXYE8t0VXUfexjseFWVfkKiemukh
NXsLyx7BgzqM4OHVloru7hmsvytIHsZVDg4+64eW/8nsUm/kT8nA9AAJMQKBgEBA
EQOczlkPMWbOmLbHGf/ukiGg3zqzJgItSKIFHOTopO1x4a1dQvvE27wzxD3fR/ck
TrA8G0ijrC+xhdHNTo8WkiKPbB8KQ8JP9EL797+ynyV6dZmRDKwHl3C8XrsdgXvp
tQGXJA9zkjSDJPDY37ydeyfMC8LHiJR8OPiQYacfAoGBAKu0smpwESWQ1NrRMji0
OUVLYDPyQqybgdYS6PAQiJYpKCCDNofCO676XqYC35ss4RweabgTL7VLsEL5Xz1x
pt/agClszuk33DxAk7uqRgbZzVo5PBMhxA1AA9Xc9aho4f8tavTZWf9ARjncmYZd
g/81VtrJi19YiFd+h0JnATsq
-----END PRIVATE KEY-----"#;
let rsa_public_key = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlO9sDVsy0KKJdvlb4rhe
KymghSbq18jCmNggzmN1j/vfXBBva07w0QUKum55G921A5s/oZ3FRyyYj/nkKjiz
FTbidHRDK25EPIGxL4geE0nJpaag20PqiU8ft3KjE51/fUrUyeMk02lXT5yHeqzT
qN6sJ4Jfw17rwqENZq3oIdSkHvD2hbJpcZkNkqzxP6p8NKunjNAkkbBCIKdMzlPL
RYJ2jW3ENy14Kc9fnJLu1syVfEvdBccNSCj0Uf/Mc3hrcs0kciqVZTY3uvBpQoPG
wZ66UJ5m9NjEa0ItvCXWq4dO6w4ZUZFNVk+9RC/7UuhL7TWF3Q++rAQlSU5l4ZZ8
lQIDAQAB
-----END PUBLIC KEY-----"#;

let signing_key = SigningKey::from_rsa_pem(rsa_private_key.as_bytes())
    .expect("Failed to create signing key from RSA private key");
let verification_key = VerifyingKey::from_rsa_pem(rsa_public_key.as_bytes())
    .expect("Failed to create verifying key from RSA public key");

let header = Header::new(Algorithm::RS256);
let validation_options = ValidationOptions::default().with_algorithm(Algorithm::RS256).without_expiry();
let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

let token = encode(&header, &signing_key, &payload)
    .expect("Failed to encode JWT with RSA key");
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

