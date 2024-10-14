use serde_json as SerdeError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid key format")]
    InvalidKeyFormat,
    #[error("Invalid Ecdsa key")]
    InvalidEcdsaKey,
    #[error("ASN1 decoder error")]
    RsaError(#[from] simple_asn1::ASN1DecodeErr),
    #[error("PEM parser error: {0}")]
    PemError(#[from] pem::PemError),
    #[error("Serde decode error")]
    SerdeEncodeDecodeError(#[from] SerdeError::Error),
    #[error("Base64 decode error")]
    Base64EncodeDecodeError(#[from] base64::DecodeError),
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("Hmac invalid length")]
    HmacInvalidLength(#[from] hmac::digest::InvalidLength),
    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("PKCS8 error: {0}")]
    Pkcs8Error(#[from] rsa::pkcs8::Error),
    #[error("PKCS1 error: {0}")]
    Pkcs1Error(#[from] rsa::pkcs1::Error),
    #[error("RSA error: {0}")]
    InvalidRsaKeyType(String),
    #[error("ECDSA error: {0}")]
    InvalidEcdsaKeyType(#[from] ecdsa::Error),
    #[error("RSA error: {0}")]
    InvalidRsaKey(#[from] rsa::errors::Error),
    #[error("Expired signature")]
    ExpiredSignature,
    #[error("Immature signature")]
    ImmatureSignature,
    #[error("Invalid issuer")]
    InvalidIssuer,
    #[error("Invalid subject")]
    InvalidSubject,
    #[error("Invalid audience")]
    InvalidAudience,
    #[error("Invalid algorithm")]
    InvalidAlgorithm,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid claim: {0}")]
    InvalidClaim(String),
}
