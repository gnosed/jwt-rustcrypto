use crate::{Error, PemEncodedKey, SecretKey};
use base64::Engine;

/// A verification key used to verify the signature of a JWT.
#[derive(Debug, Clone)]
pub enum VerifyingKey {
    Secret(SecretKey),
    RsaKey(PemEncodedKey),
    EcKey(PemEncodedKey),
    EdKey(PemEncodedKey),
}

impl VerifyingKey {
    pub fn from_secret(secret: &[u8]) -> Self {
        let secret = SecretKey::new(secret.to_vec());
        Self::Secret(secret)
    }

    pub fn from_base64_secret(secret: &str) -> Result<Self, Error> {
        let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(secret.as_bytes())?;
        Ok(Self::from_secret(&secret))
    }

    pub fn from_rsa_pem(key: &[u8]) -> Result<Self, Error> {
        let key = PemEncodedKey::new(key)?;
        Ok(Self::RsaKey(key))
    }

    pub fn from_rsa_components(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        let key = PemEncodedKey::from_rsa_components(n, e)?;
        Ok(Self::RsaKey(key))
    }

    pub fn from_rsa_der(key: &[u8]) -> Result<Self, Error> {
        let key = PemEncodedKey::new(key)?;
        Ok(Self::RsaKey(key))
    }

    pub fn from_ec_pem(key: &[u8]) -> Result<Self, Error> {
        let key = PemEncodedKey::new(key)?;
        Ok(Self::EcKey(key))
    }

    pub fn from_ec_der(key: &[u8]) -> Result<Self, Error> {
        let key = PemEncodedKey::new(key)?;
        Ok(Self::EcKey(key))
    }

    pub fn from_ed_pem(key: &[u8]) -> Result<Self, Error> {
        let key = PemEncodedKey::new(key)?;
        Ok(Self::EdKey(key))
    }

    pub fn from_ed_der(key: &[u8]) -> Result<Self, Error> {
        let key = PemEncodedKey::new(key)?;
        Ok(Self::EdKey(key))
    }
}
