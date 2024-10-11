use crate::{Algorithm, Error, PemType, SigningKey, Standard as PemStandard};
use base64::Engine;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::RandomizedSigner;
use rsa::signature::SignatureEncoding;
use rsa::{pkcs1v15::SigningKey as Pkcs1SigningKey, pss::SigningKey as PssSigningKey};
use sha2::{Digest, Sha256, Sha384, Sha512};

#[derive(Debug)]
enum SigningSchema {
    Pkcs1Sha256(Pkcs1SigningKey<Sha256>),
    Pkcs1Sha384(Pkcs1SigningKey<Sha384>),
    Pkcs1Sha512(Pkcs1SigningKey<Sha512>),
    PssSha256(PssSigningKey<Sha256>),
    PssSha384(PssSigningKey<Sha384>),
    PssSha512(PssSigningKey<Sha512>),
}

impl SigningSchema {
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, Error> {
        let mut rng = rand::thread_rng();
        let signature_bytes = match self {
            SigningSchema::Pkcs1Sha256(signer) => signer.sign_with_rng(&mut rng, digest).to_vec(),
            SigningSchema::Pkcs1Sha384(signer) => signer.sign_with_rng(&mut rng, digest).to_vec(),
            SigningSchema::Pkcs1Sha512(signer) => signer.sign_with_rng(&mut rng, digest).to_vec(),
            SigningSchema::PssSha256(signer) => signer.sign_with_rng(&mut rng, digest).to_vec(),
            SigningSchema::PssSha384(signer) => signer.sign_with_rng(&mut rng, digest).to_vec(),
            SigningSchema::PssSha512(signer) => signer.sign_with_rng(&mut rng, digest).to_vec(),
        };

        Ok(signature_bytes)
    }
}

fn compute_digest(alg: &Algorithm, data: &str) -> Result<Vec<u8>, Error> {
    let digest = match alg {
        Algorithm::RS256 | Algorithm::PS256 => Sha256::digest(data.as_bytes()).to_vec(),
        Algorithm::RS384 | Algorithm::PS384 => Sha384::digest(data.as_bytes()).to_vec(),
        Algorithm::RS512 | Algorithm::PS512 => Sha512::digest(data.as_bytes()).to_vec(),
        _ => return Err(Error::UnsupportedAlgorithm),
    };

    Ok(digest)
}

fn create_signing_scheme(
    alg: &Algorithm,
    signing_key: &SigningKey,
) -> Result<SigningSchema, Error> {
    let rsa_key = match signing_key {
        SigningKey::RsaKey(key) => key,
        _ => return Err(Error::UnsupportedAlgorithm),
    };

    if rsa_key.pem_type != PemType::RsaPrivate {
        return Err(Error::InvalidRsaKeyType("Expected RsaPrivate".to_string()));
    }

    let rsa_key = match rsa_key.standard {
        PemStandard::Pkcs1 => rsa::RsaPrivateKey::from_pkcs1_pem(&pem::encode(&rsa_key.content))?,
        PemStandard::Pkcs8 => rsa::RsaPrivateKey::from_pkcs8_pem(&pem::encode(&rsa_key.content))?,
    };

    let signing_schema = match alg {
        Algorithm::RS256 => SigningSchema::Pkcs1Sha256(Pkcs1SigningKey::<Sha256>::new(rsa_key)),
        Algorithm::RS384 => SigningSchema::Pkcs1Sha384(Pkcs1SigningKey::<Sha384>::new(rsa_key)),
        Algorithm::RS512 => SigningSchema::Pkcs1Sha512(Pkcs1SigningKey::<Sha512>::new(rsa_key)),
        Algorithm::PS256 => SigningSchema::PssSha256(PssSigningKey::<Sha256>::new(rsa_key)),
        Algorithm::PS384 => SigningSchema::PssSha384(PssSigningKey::<Sha384>::new(rsa_key)),
        Algorithm::PS512 => SigningSchema::PssSha512(PssSigningKey::<Sha512>::new(rsa_key)),
        _ => return Err(Error::UnsupportedAlgorithm),
    };

    Ok(signing_schema)
}

pub(crate) fn sign_rsa(
    data: &str,
    signing_key: &SigningKey,
    alg: &Algorithm,
) -> Result<String, Error> {
    let digest = compute_digest(alg, data)?;

    let signing_schema = create_signing_scheme(alg, signing_key)?;
    let signature = signing_schema.sign(&digest)?;

    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    const TEST_KEYS_DIR: &str = "tests/keys";

    fn load_key(file_name: &str) -> String {
        let path = Path::new(TEST_KEYS_DIR).join(file_name);
        fs::read_to_string(path).expect("Failed to read key file")
    }

    #[test]
    fn test_create_signing_scheme_rsa() {
        let signing_key =
            SigningKey::from_rsa_pem(load_key("rsa_private_key_pkcs8.pem").as_bytes()).unwrap();
        let alg = Algorithm::RS256;

        let signing_scheme = create_signing_scheme(&alg, &signing_key);
        if signing_scheme.is_err() {
            println!(
                "Error: {:?}",
                signing_scheme.as_ref().unwrap_err().to_string()
            );
        }
        assert!(signing_scheme.is_ok());
    }

    #[test]
    fn test_create_signing_scheme_invalid_algorithm() {
        let signing_key =
            SigningKey::from_rsa_pem(load_key("rsa_private_key_pkcs8.pem").as_bytes()).unwrap();
        let invalid_alg = Algorithm::ES512;

        let signing_scheme = create_signing_scheme(&invalid_alg, &signing_key);
        assert!(signing_scheme.is_err());
    }
}
