use crate::validation::validate_header;
use crate::{
    pem::PemEncodedKey, validation::validate, Algorithm, Error, Header, SecretKey,
    ValidationOptions, VerifyingKey,
};
use base64::Engine;
use ecdsa::der::Signature as EcdsaDerSignature;
use hmac::{Hmac, Mac};
use k256::ecdsa::VerifyingKey as K256VerifyingKey;
use p256::ecdsa::VerifyingKey as P256VerifyingKey;
use p384::ecdsa::VerifyingKey as P384VerifyingKey;
use p521::ecdsa::VerifyingKey as P521VerifyingKey;
use rsa::signature::Verifier as RsaVerifier;
use rsa::{
    pkcs1v15::Signature as Pkcs1v15Signature, pkcs1v15::VerifyingKey as Pkcs1v15VerifyingKey,
    pss::VerifyingKey as PssVerifyingKey,
};
use serde_json::Value as JsonValue;
use sha2::{Sha256, Sha384, Sha512};
use simple_asn1::{to_der, ASN1Block, BigUint};

#[derive(Debug, Clone)]
pub struct DecodedJwt {
    pub header: Header,
    pub payload: JsonValue,
}

/// Decodes and validates a JWT using the provided verification key and validation options.
///
/// # Arguments
///
/// * `token` - The encoded JWT string.
/// * `verifying_key` - The key to be used for signature verification.
/// * `options` - The validation options for the claims within the JWT.
///
/// # Returns
///
/// Returns a `DecodedJwt` structure containing the header, payload, and signature if successful,
/// or an `Error` if decoding or validation fails.
pub fn decode(
    token: &str,
    verifying_key: &VerifyingKey,
    validation_options: &ValidationOptions,
) -> Result<DecodedJwt, Error> {
    let (header, payload, signature) = split_jwt(token)?;

    validate_header(&header, validation_options)?;

    let signing_input = format!(
        "{}.{}",
        token.split('.').collect::<Vec<&str>>()[0],
        token.split('.').collect::<Vec<&str>>()[1]
    );
    verify_signature(&signing_input, &signature, &header.alg, verifying_key)
        .map_err(|_| Error::InvalidSignature)?;
    validate(
        payload.as_object().ok_or(Error::InvalidKeyFormat)?,
        validation_options,
    )?;

    Ok(DecodedJwt { header, payload })
}

/// Decodes a JWT without verifying the signature.
/// This is useful when you only need to read the claims from the JWT.
///
/// # Arguments
///
/// * `token` - The encoded JWT string.
///
/// # Returns
///
/// Returns a `DecodedJwt` structure containing the header and payload if successful,
/// or an `Error` if decoding fails.
pub fn decode_only(token: &str) -> Result<DecodedJwt, Error> {
    let (header, payload, _) = split_jwt(token)?;
    Ok(DecodedJwt { header, payload })
}

fn split_jwt(token: &str) -> Result<(Header, JsonValue, Vec<u8>), Error> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::InvalidKeyFormat);
    }

    let header_data = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0])?;
    let payload_data = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?;
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2])?;

    let header: Header = serde_json::from_slice(&header_data)?;
    let payload: JsonValue = serde_json::from_slice(&payload_data)?;

    Ok((header, payload, signature))
}

/// Verifies the signature of the JWT.
///
/// # Arguments
///
/// * `signing_input` - The input string to be signed (typically header.payload).
/// * `signature` - The actual signature from the JWT.
/// * `alg` - The algorithm specified in the JWT header.
/// * `verifying_key` - The key to be used for verification.
///
/// # Returns
///
/// Returns `Ok(())` if the signature is valid, or an `Error` otherwise.
fn verify_signature(
    signing_input: &str,
    signature: &[u8],
    alg: &Algorithm,
    verifying_key: &VerifyingKey,
) -> Result<(), Error> {
    match verifying_key {
        VerifyingKey::Secret(secret) => match alg {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                verify_hmac(signing_input, signature, secret, alg)
            }
            _ => Err(Error::UnsupportedAlgorithm),
        },
        VerifyingKey::RsaKey(rsa_key) => match alg {
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                verify_rsa(signing_input, signature, rsa_key, alg)
            }
            Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
                verify_pss(signing_input, signature, rsa_key, alg)
            }
            _ => Err(Error::UnsupportedAlgorithm),
        },
        VerifyingKey::EcKey(ec_key) => match alg {
            Algorithm::ES256 | Algorithm::ES256K | Algorithm::ES384 | Algorithm::ES512 => {
                verify_ecdsa(signing_input, signature, ec_key, alg)
            }
            _ => Err(Error::UnsupportedAlgorithm),
        },
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

/// Verifies an RSA PKCS#1 signature.
fn verify_rsa(
    signing_input: &str,
    signature: &[u8],
    rsa_key: &PemEncodedKey,
    alg: &Algorithm,
) -> Result<(), Error> {
    let rsa_public_key = rsa_key.as_rsa_public_key()?;
    let pkcs1_signature = Pkcs1v15Signature::try_from(signature)?;
    match alg {
        Algorithm::RS256 => {
            let verifying_key = Pkcs1v15VerifyingKey::<sha2::Sha256>::new(rsa_public_key);
            verifying_key.verify(signing_input.as_bytes(), &pkcs1_signature)?;
        }
        Algorithm::RS384 => {
            let verifying_key = Pkcs1v15VerifyingKey::<sha2::Sha384>::new(rsa_public_key);
            verifying_key.verify(signing_input.as_bytes(), &pkcs1_signature)?;
        }
        Algorithm::RS512 => {
            let verifying_key = Pkcs1v15VerifyingKey::<sha2::Sha512>::new(rsa_public_key);
            verifying_key.verify(signing_input.as_bytes(), &pkcs1_signature)?;
        }
        _ => return Err(Error::UnsupportedAlgorithm),
    };

    Ok(())
}

/// Verifies an RSA-PSS signature.
fn verify_pss(
    signing_input: &str,
    signature: &[u8],
    rsa_key: &PemEncodedKey,
    alg: &Algorithm,
) -> Result<(), Error> {
    let rsa_public_key = rsa_key.as_rsa_public_key()?;
    let pss_signature = rsa::pss::Signature::try_from(signature)?;

    match alg {
        Algorithm::PS256 => {
            let verifying_key = PssVerifyingKey::<sha2::Sha256>::new(rsa_public_key);
            verifying_key.verify(signing_input.as_bytes(), &pss_signature)?
        }
        Algorithm::PS384 => {
            let verifying_key = PssVerifyingKey::<sha2::Sha384>::new(rsa_public_key);
            verifying_key.verify(signing_input.as_bytes(), &pss_signature)?
        }
        Algorithm::PS512 => {
            let veryfing_key = PssVerifyingKey::<sha2::Sha512>::new(rsa_public_key);
            veryfing_key.verify(signing_input.as_bytes(), &pss_signature)?
        }
        _ => {
            return Err(Error::UnsupportedAlgorithm);
        }
    };

    Ok(())
}

/// Verifies an HMAC signature.
fn verify_hmac(
    signing_input: &str,
    signature: &[u8],
    secret: &SecretKey,
    alg: &Algorithm,
) -> Result<(), Error> {
    let key = secret.inner();
    let computed_signature = match alg {
        Algorithm::HS256 => {
            let mut hmac = Hmac::<Sha256>::new_from_slice(key)?;
            hmac.update(signing_input.as_bytes());
            hmac.finalize().into_bytes().to_vec()
        }
        Algorithm::HS384 => {
            let mut hmac = Hmac::<Sha384>::new_from_slice(key)?;
            hmac.update(signing_input.as_bytes());
            hmac.finalize().into_bytes().to_vec()
        }
        Algorithm::HS512 => {
            let mut hmac = Hmac::<Sha512>::new_from_slice(key)?;
            hmac.update(signing_input.as_bytes());
            hmac.finalize().into_bytes().to_vec()
        }
        _ => return Err(Error::UnsupportedAlgorithm),
    };

    if computed_signature == signature {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// Verifies an ECDSA signature using the specified curve and algorithm.
fn verify_ecdsa(
    signing_input: &str,
    signature: &[u8],
    ec_key: &PemEncodedKey,
    alg: &Algorithm,
) -> Result<(), Error> {
    let public_key_bytes = ec_key.as_ec_public_key()?;

    match alg {
        Algorithm::ES256 => {
            let verifying_key = P256VerifyingKey::from_sec1_bytes(public_key_bytes)
                .map_err(|_| Error::InvalidEcdsaKey)?;
            let ecdsa_signature_vec = determine_signature_type(signature, 64);
            let ecdsa_signature = EcdsaDerSignature::from_bytes(&ecdsa_signature_vec)?;
            verifying_key
                .verify(signing_input.as_bytes(), &ecdsa_signature)
                .map_err(|_| Error::InvalidSignature)
        }
        Algorithm::ES256K => {
            let verifying_key = K256VerifyingKey::from_sec1_bytes(public_key_bytes)
                .map_err(|_| Error::InvalidEcdsaKey)?;
            let ecdsa_signature_vec = determine_signature_type(signature, 64);
            let ecdsa_signature = EcdsaDerSignature::from_bytes(&ecdsa_signature_vec)?;
            verifying_key
                .verify(signing_input.as_bytes(), &ecdsa_signature)
                .map_err(|_| Error::InvalidSignature)
        }
        Algorithm::ES384 => {
            let verifying_key = P384VerifyingKey::from_sec1_bytes(public_key_bytes)
                .map_err(|_| Error::InvalidEcdsaKey)?;
            let ecdsa_signature_vec = determine_signature_type(signature, 96);
            let ecdsa_signature = EcdsaDerSignature::from_bytes(&ecdsa_signature_vec)?;
            verifying_key
                .verify(signing_input.as_bytes(), &ecdsa_signature)
                .map_err(|_| Error::InvalidSignature)
        }
        Algorithm::ES512 => {
            let verifying_key = P521VerifyingKey::from_sec1_bytes(public_key_bytes)
                .map_err(|_| Error::InvalidEcdsaKey)?;
            let ecdsa_signature_vec = determine_signature_type(signature, 132);
            let ecdsa_signature = EcdsaDerSignature::from_bytes(&ecdsa_signature_vec)?;
            verifying_key
                .verify(signing_input.as_bytes(), &ecdsa_signature.try_into()?)
                .map_err(|_| Error::InvalidSignature)
        }
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

fn determine_signature_type(signature: &[u8], signature_len: usize) -> Vec<u8> {
    // convert signature to DER format if already not in DER format
    if signature.len() == signature_len {
        let r = &signature[..signature_len / 2];
        let s = &signature[signature_len / 2..];

        let asn1_signature = ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::Integer(0, BigUint::from_bytes_be(r).into()),
                ASN1Block::Integer(0, BigUint::from_bytes_be(s).into()),
            ],
        );

        to_der(&asn1_signature).unwrap()
    } else {
        signature.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode, Algorithm, Header, SigningKey, ValidationOptions};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPublicKey;
    use serde_json::{json, to_value};
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
}
