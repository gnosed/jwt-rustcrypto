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
