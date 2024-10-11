use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::Algorithm;
use crate::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub alg: Algorithm,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
}

impl Header {
    pub fn new(alg: Algorithm) -> Self {
        Self {
            alg,
            jku: None,
            jwk: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            typ: Some("JWT".to_string()),
            cty: None,
            crit: None,
        }
    }

    pub fn from_encoded(encoded: &[u8]) -> Result<Self, Error> {
        let decoded_from_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded)?;
        serde_json::from_slice(decoded_from_b64.as_slice()).map_err(Error::from)
    }
}

impl Default for Header {
    fn default() -> Self {
        Self::new(Algorithm::HS256)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,

    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub k: Option<String>,
}
