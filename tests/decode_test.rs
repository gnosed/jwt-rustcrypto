use base64::Engine;
use jwt_rustcrypto::{
    decode, decode_only, encode, Algorithm, Error, Header, SigningKey, ValidationOptions,
    VerifyingKey,
};
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use serde_json::{json, to_value, value::Value as JsonValue};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_KEYS_DIR: &str = "tests/keys";

fn load_key(file_name: &str) -> String {
    let path = Path::new(TEST_KEYS_DIR).join(file_name);
    fs::read_to_string(path).expect("Failed to read key file")
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime before UNIX EPOCH")
        .as_secs()
}

#[test]
fn test_decode_hs256_valid_signature() {
    let header = Header::new(Algorithm::HS256);
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022, "exp": to_value(current_timestamp() + 3600).unwrap()  });
    let signing_key = SigningKey::from_secret(b"mysecret");
    let verifying_key = VerifyingKey::from_secret(b"mysecret");

    let encoded = encode(&header, &signing_key, &payload).unwrap();
    let validation_options = ValidationOptions::default().with_algorithm(Algorithm::HS256);

    let result = decode(&encoded, &verifying_key, &validation_options);
    assert!(result.is_ok(), "HS256 decoding failed: {:?}", result.err());

    let decoded = result.unwrap();
    assert_eq!(decoded.header.alg, Algorithm::HS256);
    assert_eq!(decoded.payload["sub"], "1234567890");
}

#[test]
fn test_decode_hs256_invalid_signature() {
    let header = Header::new(Algorithm::HS256);
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022, "exp": to_value(current_timestamp() + 3600).unwrap() });
    let signing_key = SigningKey::from_secret(b"mysecret");
    let verifying_key = VerifyingKey::from_secret(b"mysecret");

    let encoded = encode(&header, &signing_key, &payload).unwrap();

    // Modify the JWT to invalidate the signature
    let mut parts: Vec<&str> = encoded.split('.').collect();
    parts[2] = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let tampered_token = parts.join(".");

    let validation_options = ValidationOptions::default().with_algorithm(Algorithm::HS256);
    let result = decode(&tampered_token, &verifying_key, &validation_options);

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidSignature));
}

#[test]
fn test_decode_rsa_valid_signature() {
    let rsa_private_key = load_key("rsa_private_key_pkcs8.pem");
    let rsa_public_key = load_key("rsa_public_key_pkcs8.pem");

    let signing_key = SigningKey::from_rsa_pem(rsa_private_key.as_bytes()).unwrap();
    let verifying_key = VerifyingKey::from_rsa_pem(rsa_public_key.as_bytes()).unwrap();

    let header = Header::new(Algorithm::RS256);
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022, "exp": to_value(current_timestamp() + 3600).unwrap() });

    let encoded = encode(&header, &signing_key, &payload).unwrap();
    println!("THAT JWT {}", encoded);

    let validation_options = ValidationOptions::default().with_algorithm(Algorithm::RS256);
    let result = decode(&encoded, &verifying_key, &validation_options);
    assert!(result.is_ok(), "RSA256 decoding failed: {:?}", result.err());

    let decoded = result.unwrap();
    assert_eq!(decoded.header.alg, Algorithm::RS256);
    assert_eq!(decoded.payload["sub"], "1234567890");
}

#[test]
fn test_decode_rsa_invalid_signature() {
    let rsa_public_key = load_key("rsa_public_key_pkcs8.pem");
    let verifying_key = VerifyingKey::from_rsa_pem(rsa_public_key.as_bytes()).unwrap();

    let tampered_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";

    let validation_options = ValidationOptions::default().with_algorithm(Algorithm::RS256);
    let result = decode(tampered_token, &verifying_key, &validation_options);

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidSignature));
}

#[test]
fn test_decode_ec_valid_signature() {
    let ec_private_key = load_key("ec_private_key_p256_pkcs8.pem");
    let ec_public_key = load_key("ec_public_key_p256_pkcs8.pem");

    let signing_key = SigningKey::from_ec_pem(ec_private_key.as_bytes()).unwrap();
    let verifying_key = VerifyingKey::from_ec_pem(ec_public_key.as_bytes()).unwrap();

    let header = Header::new(Algorithm::ES256);
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022, "exp": to_value(current_timestamp() + 3600).unwrap() });

    let encoded = encode(&header, &signing_key, &payload).unwrap();
    println!("THIS JWT {}", encoded);
    let validation_options = ValidationOptions::default().with_algorithm(Algorithm::ES256);

    let result = decode(&encoded, &verifying_key, &validation_options);
    assert!(result.is_ok(), "ES256 decoding failed: {:?}", result.err());

    let decoded = result.unwrap();
    assert_eq!(decoded.header.alg, Algorithm::ES256);
    assert_eq!(decoded.payload["sub"], "1234567890");
}

#[test]
fn test_decode_with_expired_validation() {
    let rsa_private_key = load_key("rsa_private_key_pkcs8.pem");
    let rsa_public_key = load_key("rsa_public_key_pkcs8.pem");

    let signing_key = SigningKey::from_rsa_pem(rsa_private_key.as_bytes()).unwrap();
    let verifying_key = VerifyingKey::from_rsa_pem(rsa_public_key.as_bytes()).unwrap();

    let header = Header::new(Algorithm::RS256);
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022, "exp": to_value(current_timestamp() - 3600).unwrap() });

    let encoded = encode(&header, &signing_key, &payload).unwrap();
    let validation_options = ValidationOptions::default().with_algorithm(Algorithm::RS256);

    let result = decode(&encoded, &verifying_key, &validation_options);

    assert!(matches!(result, Err(Error::ExpiredSignature)));
}

#[test]
fn test_decode_with_issuer_validation() {
    let rsa_private_key = load_key("rsa_private_key_pkcs8.pem");
    let rsa_public_key = load_key("rsa_public_key_pkcs8.pem");

    let signing_key = SigningKey::from_rsa_pem(rsa_private_key.as_bytes()).unwrap();
    let verifying_key = VerifyingKey::from_rsa_pem(rsa_public_key.as_bytes()).unwrap();

    let header = Header::new(Algorithm::RS256);
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022, "iss": "trusted_issuer", "exp": to_value(current_timestamp() + 3600).unwrap() });

    let encoded = encode(&header, &signing_key, &payload).unwrap();
    let validation_options = ValidationOptions::default()
        .with_algorithm(Algorithm::RS256)
        .with_issuer("trusted_issuer");

    let result = decode(&encoded, &verifying_key, &validation_options);
    assert!(
        result.is_ok(),
        "Issuer validation failed: {:?}",
        result.err()
    );
}

#[test]
fn test_decode_with_issuer_validation_fail() {
    let rsa_private_key = load_key("rsa_private_key_pkcs8.pem");
    let rsa_public_key = load_key("rsa_public_key_pkcs8.pem");

    let signing_key = SigningKey::from_rsa_pem(rsa_private_key.as_bytes()).unwrap();
    let verifying_key = VerifyingKey::from_rsa_pem(rsa_public_key.as_bytes()).unwrap();

    let header = Header::new(Algorithm::RS256);
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022, "iss": "untrusted_issuer", "exp": to_value(current_timestamp() + 3600).unwrap() });

    let encoded = encode(&header, &signing_key, &payload).unwrap();
    let validation_options = ValidationOptions::default()
        .with_algorithm(Algorithm::RS256)
        .with_issuer("trusted_issuer");

    let result = decode(&encoded, &verifying_key, &validation_options);
    assert!(matches!(result, Err(Error::InvalidIssuer)));
}

#[test]
fn test_decode_with_audience_validation() {
    let rsa_private_key = load_key("rsa_private_key_pkcs8.pem");
    let rsa_public_key = load_key("rsa_public_key_pkcs8.pem");

    let signing_key = SigningKey::from_rsa_pem(rsa_private_key.as_bytes()).unwrap();
    let verifying_key = VerifyingKey::from_rsa_pem(rsa_public_key.as_bytes()).unwrap();

    let header = Header::new(Algorithm::RS256);
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022, "aud": "trusted_audience", "exp": to_value(current_timestamp() + 3600).unwrap() });

    let encoded = encode(&header, &signing_key, &payload).unwrap();
    let validation_options = ValidationOptions::default()
        .with_algorithm(Algorithm::RS256)
        .with_audience("trusted_audience");

    let result = decode(&encoded, &verifying_key, &validation_options);
    assert!(
        result.is_ok(),
        "Audience validation failed: {:?}",
        result.err()
    );
}

#[test]
fn test_decode_with_audience_validation_fail() {
    let rsa_private_key = load_key("rsa_private_key_pkcs8.pem");
    let rsa_public_key = load_key("rsa_public_key_pkcs8.pem");

    let signing_key = SigningKey::from_rsa_pem(rsa_private_key.as_bytes()).unwrap();
    let verifying_key = VerifyingKey::from_rsa_pem(rsa_public_key.as_bytes()).unwrap();

    let header = Header::new(Algorithm::RS256);
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022, "aud": "untrusted_audience", "exp": to_value(current_timestamp() + 3600).unwrap() });

    let encoded = encode(&header, &signing_key, &payload).unwrap();
    let validation_options = ValidationOptions::default()
        .with_algorithm(Algorithm::RS256)
        .with_audience("trusted_audience");

    let result = decode(&encoded, &verifying_key, &validation_options);
    assert!(matches!(result, Err(Error::InvalidAudience)));
}

#[test]
fn test_decode_only() {
    let header = Header::new(Algorithm::HS256);
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022, "exp": to_value(current_timestamp() + 3600).unwrap() });
    let signing_key = SigningKey::from_secret(b"mysecret");

    let encoded = encode(&header, &signing_key, &payload).unwrap();
    let result = decode_only(&encoded);

    assert!(result.is_ok(), "Decoding failed: {:?}", result.err());

    let decoded = result.unwrap();
    assert_eq!(decoded.header.alg, Algorithm::HS256);
    assert_eq!(decoded.payload["sub"], "1234567890");
}

#[test]
fn test_decode_with_rsa_from_components() {
    let jwk_pub_key = |pem: &str| -> JsonValue {
        let rsa_public_key = RsaPublicKey::from_public_key_pem(pem).unwrap();
        let n = rsa_public_key.n().to_bytes_be();
        let e = rsa_public_key.e().to_bytes_be();

        json!({
            "kty": "RSA",
            "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n),
            "e": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(e),
            "alg": "RS256",
            "use": "sig",
        })
    };

    let rsa_private_key = load_key("rsa_private_key_pkcs8.pem");
    let rsa_public_key = load_key("rsa_public_key_pkcs8.pem");

    let jwk = jwk_pub_key(&rsa_public_key);

    let signing_key = SigningKey::from_rsa_pem(rsa_private_key.as_bytes()).unwrap();
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwk["n"].as_str().unwrap())
        .unwrap();
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwk["e"].as_str().unwrap())
        .unwrap();
    let verifying_key = VerifyingKey::from_rsa_components(&n, &e).unwrap();

    let header = Header::new(Algorithm::RS256);
    let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022, "exp": to_value(current_timestamp() + 3600).unwrap() });

    let encoded = encode(&header, &signing_key, &payload).unwrap();
    let validation_options = ValidationOptions::default().with_algorithm(Algorithm::RS256);

    let result = decode(&encoded, &verifying_key, &validation_options);
    assert!(result.is_ok(), "RSA256 decoding failed: {:?}", result.err());

    let decoded = result.unwrap();
    assert_eq!(decoded.header.alg, Algorithm::RS256);
    assert_eq!(decoded.payload["sub"], "1234567890");
}

#[test]
fn test_existing_rsa_signed_jwt() {
    let pubkey_str = load_key("test_pub_rsa_pkcs1.pem");
    let test_jwt: &str = "eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsiVFhsUEt1RjM1cDQ3ZW9XTlpEcklxS0w0R0JFaDBFWXJEQnBjNmFCWjUyQSIsIkdYWlpyVUlsdnBtaDB4b0h4WURadzFOZ211WXJrd1VVS09rNG1XTHZKYUEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJhZGRyZXNzIjp7Il9zZCI6WyJiUjVKM21ULXQ0a05pZ0V0dDJ5RVd1MU92b0hVMzBmSTZ1RVdJd2ozZWJBIiwiczhicTVKeUtJaFFwcVR1Vl9hcVNtd090UVN5UHV1TUlUU2xINXg1UWI5RSJdLCJjb3VudHJ5IjoiVVMiLCJyZWdpb24iOiJBbnlzdGF0ZSJ9LCJiaXJ0aGRhdGUiOiIxOTQwLTAxLTAxIiwiY25mIjp7ImFsZyI6IlJTMjU2IiwiZSI6IkFRQUIiLCJrdHkiOiJSU0EiLCJuIjoiNS1EZDU0WHNNQU5UWm9KMllCcHVpWmFfYXpyMzJIcEJ3MUZjanA1d1UwWFBqbW9NQTdKVllDSk4wU05maDZ0dFhyWHhhYWhFNXdmUzd4S1E0N1ZvWXhYTjlLa3kxMzdDSUx0Q0xPWUJDZkdULWFRRXJKS0FJWUVORWtzbVNpU3k0VnVWRk1yTzlMOV9KTzViZk02QjZ6X3pickJYX2MxU2s0UFRLTnBqRTcxcTJHenU4ak5GdTR0c0JaOFFSdmtJVldxNGdxVklQNTFQQmZEcmNfTm53dk1aallGN2pfc0Z5eGg2ZExTVV96QkRrZjJOVWo4VXQ0M25vcW9YMGJoaE96aGdyTlpadGpFMTlrZGFlZTJYbjBweG0td3QzRjBxUjZxd2F2TFRJT21LVHE0OFdXSGxvUk5QWXpGbEo4OHNOaVNLeW9Ta0hXMG9SVDlscUhGX3ZRIiwidXNlIjoic2lnIn0sImVtYWlsIjoiam9obmRvZUBleGFtcGxlLmNvbSIsIm5hdGlvbmFsaXRpZXMiOlt7Ii4uLiI6InhnU2FMYS1CNk03OWpwVWZtaE9Hb0pkSHdNS0RNR0s3eUVKdC0tX0xScDAifSx7Ii4uLiI6Im5vNWxNSkVJSmRWdHozS3lDMVRXVkk2T2tsQnZIMjFCOExOOVEzWkxWRmMifV0sInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwic3ViIjoidXNlcl80MiIsInVwZGF0ZWRfYXQiOjE1NzAwMDAwMDB9.K2h-DNDgnq6q61tSxm1Gv-Hfo46SD8rEcP7yLFxcAlQNKBY-l1-bpXCJcqVZ7jugs2lqng0Cf9e34tM1OPkU3R6Pi5kUMGSyJ2y2ifsaZhGLCgxzNKk5W2ZxdkehzZQ6nHy6iu4flbT92Szv0eBR0hmS3hYTCtHlE4xib9G2dKWTQigB4ylPMkoRzbiKjgkucGkxSLN5ZQRXdxkez19bk5Q9BwuNLQMKG0lanq4ZJWq1C4LPt_K0WhEntyTL6SxVxGfR5HaUSxeYPCCOWSz9AVyZ46DWZGRx48PbuXGgLDH1UJYIsMej2F89CU-3QkWUrFq9b-DCYCQMxbBBekeLog";

    let verifying_key = VerifyingKey::from_rsa_pem(pubkey_str.as_bytes()).unwrap();
    let validation_options = ValidationOptions::default()
        .with_algorithm(Algorithm::RS256)
        .without_expiry();
    let result = decode(test_jwt, &verifying_key, &validation_options);
    assert!(result.is_ok(), "RSA256 decoding failed: {:?}", result.err());

    let decoded = result.unwrap();
    assert_eq!(decoded.header.alg, Algorithm::RS256);
}

#[test]
fn test_existing_hmac_signed_jwt() {
    let verifying_key = VerifyingKey::from_secret(b"your-256-bit-secret");
    let validation_options = ValidationOptions::default()
        .with_algorithm(Algorithm::HS256)
        .without_expiry();
    let test_jwt: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let result = decode(test_jwt, &verifying_key, &validation_options);
    assert!(result.is_ok(), "RSA256 decoding failed: {:?}", result.err());

    let decoded = result.unwrap();
    assert_eq!(decoded.header.alg, Algorithm::HS256);
}

#[test]
fn test_existing_es256_signed_jwt() {
    let pubkey_str = load_key("test_pub_es256_pkcs8.pem");
    let test_jwt: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
    let verifying_key = VerifyingKey::from_ec_pem(pubkey_str.as_bytes()).unwrap();
    let validation_options = ValidationOptions::default()
        .with_algorithm(Algorithm::ES256)
        .without_expiry();
    let result = decode(test_jwt, &verifying_key, &validation_options);
    assert!(result.is_ok(), "ES256 decoding failed: {:?}", result.err());
}

#[test]
fn test_existing_es384_signed_jwt() {
    let pubkey_str = load_key("test_pub_es384_pkcs8.pem");
    let test_jwt: &str = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj";
    let verifying_key = VerifyingKey::from_ec_pem(pubkey_str.as_bytes()).unwrap();
    let validation_options = ValidationOptions::default()
        .with_algorithm(Algorithm::ES384)
        .without_expiry();
    let result = decode(test_jwt, &verifying_key, &validation_options);
    assert!(result.is_ok(), "ES384 decoding failed: {:?}", result.err());
}

#[test]
fn test_existing_es512_signed_jwt() {
    let pubkey_str = load_key("test_pub_es512_pkcs8.pem");
    let test_jwt: &str = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9Tksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk";
    let verifying_key = VerifyingKey::from_ec_pem(pubkey_str.as_bytes()).unwrap();
    let validation_options = ValidationOptions::default()
        .with_algorithm(Algorithm::ES512)
        .without_expiry();
    let result = decode(test_jwt, &verifying_key, &validation_options);
    assert!(result.is_ok(), "ES512 decoding failed: {:?}", result.err());
}
