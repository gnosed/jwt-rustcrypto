use jwt_rustcrypto::{encode, Algorithm, Header, SigningKey};
use serde_json::json;
use std::fs;
use std::path::Path;

const TEST_KEYS_DIR: &str = "tests/keys";

fn load_key(file_name: &str) -> String {
    let path = Path::new(TEST_KEYS_DIR).join(file_name);
    fs::read_to_string(path).expect("Failed to read key file")
}

#[test]
fn test_signing_key_from_secret() {
    let secret = b"mysecret";
    let signing_key = SigningKey::from_secret(secret);

    let signing_key = match signing_key {
        SigningKey::Secret(secret_key) => secret_key,
        _ => panic!("Expected SecretKey"),
    };
    assert_eq!(signing_key.inner(), secret);
}

#[test]
fn test_signing_key_from_rsa_pem_valid_key() {
    let signing_key = SigningKey::from_rsa_pem(load_key("rsa_private_key_pkcs8.pem").as_bytes());
    assert!(signing_key.is_ok());
}

#[test]
fn test_signing_key_from_rsa_pem_invalid_key() {
    let invalid_key = b"invalid key";
    let signing_key_result = SigningKey::from_rsa_pem(invalid_key);
    if signing_key_result.is_err() {
        println!(
            "Error: {:?}",
            signing_key_result.as_ref().unwrap_err().to_string()
        );
    }
    assert!(signing_key_result.is_err());
}

#[test]
fn test_sign_rsa_with_valid_key() {
    let header = Header::new(Algorithm::RS256);
    let signing_key =
        SigningKey::from_rsa_pem(load_key("rsa_private_key_pkcs8.pem").as_bytes()).unwrap();
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

    let encoded = encode(&header, &signing_key, &payload);
    assert!(encoded.is_ok());
    println!("JWT {}", encoded.unwrap());
}

#[test]
fn test_sign_with_unsupported_algorithm() {
    let header = Header::new(Algorithm::ES256);
    let signing_key =
        SigningKey::from_rsa_pem(load_key("rsa_private_key_pkcs8.pem").as_bytes()).unwrap();
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

    let encoded = encode(&header, &signing_key, &payload);
    assert!(encoded.is_err());
    assert_eq!(encoded.unwrap_err().to_string(), "Unsupported algorithm");
}

#[test]
fn test_sign_hmac_hs256() {
    let header = Header::new(Algorithm::HS256);
    let signing_key = SigningKey::from_secret(b"mysecret");
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

    let encoded = encode(&header, &signing_key, &payload);
    assert!(encoded.is_ok());
    println!("JWT {}", encoded.unwrap());
}

#[test]
fn test_sign_rsa_with_pkcs1_key() {
    let header = Header::new(Algorithm::RS256);
    let signing_key =
        SigningKey::from_rsa_pem(load_key("rsa_private_key_pkcs1.pem").as_bytes()).unwrap();
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

    let encoded = encode(&header, &signing_key, &payload);
    assert!(encoded.is_ok());
    println!("JWT {}", encoded.unwrap());
}

#[test]
fn test_sign_rsa_ps_alg() {
    let header = Header::new(Algorithm::PS256);
    let signing_key =
        SigningKey::from_rsa_pem(load_key("rsa_private_key_pkcs8.pem").as_bytes()).unwrap();
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

    let encoded = encode(&header, &signing_key, &payload);
    assert!(encoded.is_ok());
    println!("JWT {}", encoded.unwrap());
}

#[test]
fn test_sign_rsa_pkcs1_ps_alg() {
    let header = Header::new(Algorithm::PS512);
    let signing_key =
        SigningKey::from_rsa_pem(load_key("rsa_private_key_pkcs1.pem").as_bytes()).unwrap();
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

    let encoded = encode(&header, &signing_key, &payload);
    assert!(encoded.is_ok());
    println!("JWT {}", encoded.unwrap());
}

#[test]
fn test_sign_ec_es256() {
    let header = Header::new(Algorithm::ES256);
    let signing_key =
        SigningKey::from_ec_pem(load_key("ec_private_key_p256_pkcs8.pem").as_bytes()).unwrap();
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

    let encoded = encode(&header, &signing_key, &payload);
    assert!(encoded.is_ok(), "ES256 signing failed: {:?}", encoded.err());
    println!("JWT (ES256): {}", encoded.unwrap());
}

#[test]
fn test_sign_ec_es256k() {
    let header = Header::new(Algorithm::ES256K);
    let signing_key =
        SigningKey::from_ec_pem(load_key("ec_private_key_p256k_pkcs8.pem").as_bytes()).unwrap();
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

    let encoded = encode(&header, &signing_key, &payload);
    assert!(
        encoded.is_ok(),
        "ES256K signing failed: {:?}",
        encoded.err()
    );
    println!("JWT (ES256K): {}", encoded.unwrap());
}

#[test]
fn test_sign_ec_es384() {
    let header = Header::new(Algorithm::ES384);
    let signing_key =
        SigningKey::from_ec_pem(load_key("ec_private_key_p384_pkcs8.pem").as_bytes()).unwrap();
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

    let encoded = encode(&header, &signing_key, &payload);
    assert!(encoded.is_ok(), "ES384 signing failed: {:?}", encoded.err());
    println!("JWT (ES384): {}", encoded.unwrap());
}

#[test]
fn test_sign_ec_es512() {
    let header = Header::new(Algorithm::ES512);
    let signing_key =
        SigningKey::from_ec_pem(load_key("ec_private_key_p512_pkcs8.pem").as_bytes()).unwrap();
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

    let encoded = encode(&header, &signing_key, &payload);
    assert!(encoded.is_ok(), "ES512 signing failed: {:?}", encoded.err());
    println!("JWT (ES512): {}", encoded.unwrap());
}
