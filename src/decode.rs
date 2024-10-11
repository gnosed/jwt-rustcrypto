use crate::validation::validate_header;
use crate::{
    pem::PemEncodedKey, validation::validate, Algorithm, Error, Header, SecretKey,
    ValidationOptions, VerifyingKey,
};
use base64::Engine;
use ecdsa::signature::Verifier as EcdsaVerifier;
use k256::{ecdsa::Signature as K256Signature, ecdsa::VerifyingKey as K256VerifyingKey};
use p256::{ecdsa::Signature as P256Signature, ecdsa::VerifyingKey as P256VerifyingKey};
use p384::{ecdsa::Signature as P384Signature, ecdsa::VerifyingKey as P384VerifyingKey};
use p521::{ecdsa::Signature as P521Signature, ecdsa::VerifyingKey as P521VerifyingKey};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{
    pkcs1v15::Signature as Pkcs1v15Signature, pkcs1v15::VerifyingKey as Pkcs1v15VerifyingKey,
    pss::VerifyingKey as PssVerifyingKey, RsaPublicKey,
};
use serde_json::Value as JsonValue;

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

/// Computes the digest of the input based on the algorithm.
fn compute_digest(alg: &Algorithm, data: &str) -> Result<Vec<u8>, Error> {
    use sha2::{Digest, Sha256, Sha384, Sha512};

    let digest = match alg {
        Algorithm::RS256 | Algorithm::PS256 | Algorithm::ES256 | Algorithm::ES256K => {
            Sha256::digest(data.as_bytes()).to_vec()
        }
        Algorithm::RS384 | Algorithm::PS384 | Algorithm::ES384 => {
            Sha384::digest(data.as_bytes()).to_vec()
        }
        Algorithm::RS512 | Algorithm::PS512 | Algorithm::ES512 => {
            Sha512::digest(data.as_bytes()).to_vec()
        }
        _ => return Err(Error::UnsupportedAlgorithm),
    };

    Ok(digest)
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
    let rsa_public_key = RsaPublicKey::from_pkcs1_der(rsa_key.as_rsa_key()?)?;
    let verifying_key = Pkcs1v15VerifyingKey::<sha2::Sha256>::new(rsa_public_key);

    let digest = compute_digest(alg, signing_input)?;

    let pkcs1_signature = Pkcs1v15Signature::try_from(signature)?;
    verifying_key.verify(digest.as_slice(), &pkcs1_signature)?;
    Ok(())
}

/// Verifies an RSA-PSS signature.
fn verify_pss(
    signing_input: &str,
    signature: &[u8],
    rsa_key: &PemEncodedKey,
    alg: &Algorithm,
) -> Result<(), Error> {
    let rsa_public_key = RsaPublicKey::from_pkcs1_der(rsa_key.as_rsa_key()?)?;
    let verifying_key =
        PssVerifyingKey::<sha2::Sha256>::new_with_salt_len(rsa_public_key, signature.len());

    let digest = compute_digest(alg, signing_input)?;

    let pss_signature = rsa::pss::Signature::try_from(signature)?;
    verifying_key.verify(digest.as_slice(), &pss_signature)?;
    Ok(())
}

/// Verifies an HMAC signature.
fn verify_hmac(
    signing_input: &str,
    signature: &[u8],
    secret: &SecretKey,
    alg: &Algorithm,
) -> Result<(), Error> {
    use hmac::{Hmac, Mac};
    use sha2::{Sha256, Sha384, Sha512};

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
    let digest = compute_digest(alg, signing_input)?;

    match alg {
        Algorithm::ES256 => {
            let verifying_key = P256VerifyingKey::from_sec1_bytes(public_key_bytes)
                .map_err(|_| Error::InvalidEcdsaKey)?;
            let ecdsa_signature =
                P256Signature::from_der(signature).map_err(|_| Error::InvalidSignature)?;
            verifying_key
                .verify(digest.as_slice(), &ecdsa_signature)
                .map_err(|_| Error::InvalidSignature)
        }
        Algorithm::ES256K => {
            let verifying_key = K256VerifyingKey::from_sec1_bytes(public_key_bytes)
                .map_err(|_| Error::InvalidEcdsaKey)?;
            let ecdsa_signature =
                K256Signature::from_der(signature).map_err(|_| Error::InvalidSignature)?;
            verifying_key
                .verify(digest.as_slice(), &ecdsa_signature)
                .map_err(|_| Error::InvalidSignature)
        }
        Algorithm::ES384 => {
            let verifying_key = P384VerifyingKey::from_sec1_bytes(public_key_bytes)
                .map_err(|_| Error::InvalidEcdsaKey)?;
            let ecdsa_signature =
                P384Signature::from_der(signature).map_err(|_| Error::InvalidSignature)?;
            verifying_key
                .verify(digest.as_slice(), &ecdsa_signature)
                .map_err(|_| Error::InvalidSignature)
        }
        Algorithm::ES512 => {
            let verifying_key = P521VerifyingKey::from_sec1_bytes(public_key_bytes)
                .map_err(|_| Error::InvalidEcdsaKey)?;
            let ecdsa_signature =
                P521Signature::from_der(signature).map_err(|_| Error::InvalidSignature)?;
            verifying_key
                .verify(digest.as_slice(), &ecdsa_signature)
                .map_err(|_| Error::InvalidSignature)
        }
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode, Algorithm, Header, SigningKey, ValidationOptions};
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
}
