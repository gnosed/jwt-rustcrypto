use crate::{Error, PemEncodedKey, SecretKey};

/// A verification key used to verify the signature of a JWT.
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

    pub fn from_rsa_pem(key: &[u8]) -> Result<Self, Error> {
        let key = PemEncodedKey::new(key)?;
        Ok(Self::RsaKey(key))
    }

    pub fn from_ec_pem(key: &[u8]) -> Result<Self, Error> {
        let key = PemEncodedKey::new(key)?;
        Ok(Self::EcKey(key))
    }

    pub fn from_ed_pem(key: &[u8]) -> Result<Self, Error> {
        let key = PemEncodedKey::new(key)?;
        Ok(Self::EdKey(key))
    }
}
