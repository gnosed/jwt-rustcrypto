use crate::Standard as PemStandard;
use crate::{Algorithm, Error, SigningKey};
use base64::Engine;
use ecdsa::signature::Signer;
use k256::pkcs8::DecodePrivateKey;
use k256::{ecdsa::Signature as K256Signature, ecdsa::SigningKey as K256SigningKey};
use p256::{ecdsa::Signature as P256Signature, ecdsa::SigningKey as P256SigningKey};
use p384::{ecdsa::Signature as P384Signature, ecdsa::SigningKey as P384SigningKey};
use p521::{ecdsa::Signature as P521Signature, ecdsa::SigningKey as P521SigningKey};

enum EcSigningSchema {
    Es256(P256SigningKey),
    Es256k(K256SigningKey),
    Es384(P384SigningKey),
    Es512(P521SigningKey),
}

impl EcSigningSchema {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let signature_bytes = match self {
            EcSigningSchema::Es256(signer) => {
                let signature: P256Signature = signer.sign(data);
                signature.to_der().as_bytes().to_vec()
            }
            EcSigningSchema::Es256k(signer) => {
                let signature: K256Signature = signer.sign(data);
                signature.to_der().as_bytes().to_vec()
            }
            EcSigningSchema::Es384(signer) => {
                let signature: P384Signature = signer.sign(data);
                signature.to_der().as_bytes().to_vec()
            }
            EcSigningSchema::Es512(signer) => {
                let signature: P521Signature = signer.sign(data);
                signature.to_der().as_bytes().to_vec()
            }
        };
        Ok(signature_bytes)
    }
}

fn create_ec_signing_scheme(
    alg: &Algorithm,
    signing_key: &SigningKey,
) -> Result<EcSigningSchema, Error> {
    let ec_key = match signing_key {
        SigningKey::EcKey(key) => key,
        _ => return Err(Error::UnsupportedAlgorithm),
    };

    match alg {
        Algorithm::ES256 => {
            let key = P256SigningKey::from_pkcs8_der(ec_key.as_ec_private_key()?)?;
            Ok(EcSigningSchema::Es256(key))
        }
        Algorithm::ES256K => {
            let key = K256SigningKey::from_pkcs8_der(ec_key.as_ec_private_key()?)?;
            Ok(EcSigningSchema::Es256k(key))
        }
        Algorithm::ES384 => {
            let key = P384SigningKey::from_pkcs8_der(ec_key.as_ec_private_key()?)?;
            Ok(EcSigningSchema::Es384(key))
        }
        Algorithm::ES512 => {
            let key = match ec_key.standard {
                PemStandard::Pkcs8 => {
                    let decoded_key: p521::elliptic_curve::SecretKey<p521::NistP521> =
                        p521::elliptic_curve::SecretKey::from_pkcs8_der(ec_key.content.contents())?;
                    let key_bytes = decoded_key.to_bytes();
                    let key_slice: &[u8] = key_bytes.as_slice();
                    P521SigningKey::from_slice(key_slice)?
                }
                // PemStandard::Pkcs1 => {
                //     let decoded_key: p521::elliptic_curve::SecretKey<p521::NistP521> =
                //         p521::elliptic_curve::SecretKey::from_pkcs1_der(ec_key.content.contents())?;
                //     let key_bytes = decoded_key.to_bytes();
                //     let key_slice: &[u8] = key_bytes.as_slice();
                //     P521SigningKey::from_slice(key_slice)?
                // }
                _ => return Err(Error::UnsupportedAlgorithm),
            };
            Ok(EcSigningSchema::Es512(key))
        }
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

pub(crate) fn sign_es(
    data: &str,
    signing_key: &SigningKey,
    alg: &Algorithm,
) -> Result<String, Error> {
    let signing_schema = create_ec_signing_scheme(alg, signing_key)?;
    let signature = signing_schema.sign(data.as_bytes())?;

    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature))
}
