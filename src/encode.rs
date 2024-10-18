use crate::{sign_es, sign_hmac, sign_rsa, Algorithm, Error, Header, SigningKey};
use base64::Engine;
use serde::Serialize;
use serde_json::Value as JsonValue;

/// Encodes a JWT using the provided header, signing key, and payload.
/// Returns the encoded JWT.
/// # Arguments
/// * `header` - The header of the JWT.
/// * `signing_key` - The signing key used to sign the JWT.
/// * `payload` - The payload of the JWT.
/// # Example
/// ```
/// use jwt_rustcrypto::{encode, Algorithm, Header, SigningKey};
/// use serde_json::json;
///
/// let header = Header::new(Algorithm::HS256);
/// let signing_key = SigningKey::from_secret(b"mysecret");
/// let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });
///
/// let encoded = encode(&header, &signing_key, &payload);
/// assert!(encoded.is_ok());
/// ```
pub fn encode<T: Serialize>(
    header: &Header,
    signing_key: &SigningKey,
    payload: &T,
) -> Result<String, Error> {
    let header_json = serde_json::to_value(header)?;
    let payload_json = serde_json::to_value(payload)?;
    let signing_input = get_signing_input(&payload_json, &header_json)?;

    let signature = match header.alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            sign_hmac(&signing_input, signing_key, &header.alg)
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => sign_rsa(&signing_input, signing_key, &header.alg),
        Algorithm::ES256 | Algorithm::ES256K | Algorithm::ES384 | Algorithm::ES512 => {
            sign_es(&signing_input, signing_key, &header.alg)
        }
    }?;

    Ok(format!("{}.{}", signing_input, signature))
}

fn get_signing_input(payload: &JsonValue, header: &JsonValue) -> Result<String, Error> {
    let header_str = serde_json::to_string(header)?;
    let payload_str = serde_json::to_string(payload)?;
    let signing_input = format!(
        "{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_str.as_bytes()),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_str.as_bytes())
    );
    Ok(signing_input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Algorithm;
    use serde_json::json;
    use std::fs;
    use std::path::Path;

    const TEST_KEYS_DIR: &str = "tests/keys";

    fn load_key(file_name: &str) -> String {
        let path = Path::new(TEST_KEYS_DIR).join(file_name);
        fs::read_to_string(path).expect("Failed to read key file")
    }

    #[test]
    fn test_get_signing_input_valid_input() {
        let header = json!({ "alg": "HS256", "typ": "JWT" });
        let payload = json!({ "sub": "1234567890", "name": "John Doe", "iat": 1516239022 });

        let result = get_signing_input(&payload, &header);
        assert!(result.is_ok());
        assert!(result.unwrap().contains('.'));
    }

    #[test]
    fn test_sign_rsa_invalid_digest() {
        let signing_key =
            SigningKey::from_rsa_pem(load_key("rsa_private_key_pkcs8.pem").as_bytes()).unwrap();
        let invalid_alg = Algorithm::ES512; // ES algorithms not supported in RSA signing

        let result = sign_rsa("data", &signing_key, &invalid_alg);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Unsupported algorithm");
    }
}
