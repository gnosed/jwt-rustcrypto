use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::map::Map;
use serde_json::Value;

use crate::Algorithm;
use crate::Error;
use crate::Header;

#[derive(Debug, Clone, PartialEq)]
pub struct ValidationOptions {
    /// General leeway (in seconds) applied to all time-related claims like `exp`, `nbf`, and `iat`.
    pub leeway: u64,
    /// Validate the expiration time (`exp` claim).
    pub validate_exp: bool,
    /// Validate the not-before time (`nbf` claim).
    pub validate_nbf: bool,
    /// Set of acceptable audience members.
    pub audiences: Option<HashSet<String>>,
    /// Expected issuer.
    pub issuer: Option<String>,
    /// Expected subject.
    pub subject: Option<String>,
    /// Allowed signing algorithms for the JWT.
    pub algorithms: HashSet<Algorithm>,
}

impl ValidationOptions {
    /// Create a new set of `ValidationOptions` with a specific algorithm.
    pub fn new(alg: Algorithm) -> Self {
        Self {
            algorithms: HashSet::from([alg]),
            ..Self::default()
        }
    }

    /// Disable expiration (`exp`) validation.
    pub fn without_expiry() -> Self {
        Self {
            validate_exp: false,
            ..Self::default()
        }
    }

    /// Set acceptable audience members as a HashSet of strings.
    pub fn with_audiences<T: ToString>(self, audiences: &[T]) -> Self {
        Self {
            audiences: Some(audiences.iter().map(ToString::to_string).collect()),
            ..self
        }
    }

    /// Set a single audience member as the only acceptable value.
    pub fn with_audience<T: ToString>(self, audience: T) -> Self {
        Self {
            audiences: Some(HashSet::from([audience.to_string()])),
            ..self
        }
    }

    /// Set the issuer claim to validate.
    pub fn with_issuer<T: ToString>(self, issuer: T) -> Self {
        Self {
            issuer: Some(issuer.to_string()),
            ..self
        }
    }

    /// Set the subject claim to validate.
    pub fn with_subject<T: ToString>(self, subject: T) -> Self {
        Self {
            subject: Some(subject.to_string()),
            ..self
        }
    }

    /// Set leeway for time-related claims (`exp`, `nbf`, `iat`).
    pub fn with_leeway(self, leeway: u64) -> Self {
        Self { leeway, ..self }
    }

    /// Add an allowed signing algorithm.
    pub fn with_algorithm(mut self, alg: Algorithm) -> Self {
        self.algorithms.insert(alg);
        self
    }
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            leeway: 0,
            validate_exp: true,
            validate_nbf: false,
            audiences: None,
            issuer: None,
            subject: None,
            algorithms: HashSet::new(),
        }
    }
}

/// Validates the header of a JWT using the given `ValidationOptions`.
pub(crate) fn validate_header(
    header: &Header,
    validation_options: &ValidationOptions,
) -> Result<(), Error> {
    if !validation_options.algorithms.is_empty()
        && !validation_options.algorithms.contains(&header.alg)
    {
        return Err(Error::InvalidAlgorithm);
    }
    Ok(())
}

/// Validates the claims within a JWT using the given `ValidationOptions`.
pub(crate) fn validate(
    claims: &Map<String, Value>,
    options: &ValidationOptions,
) -> Result<(), Error> {
    let now = current_timestamp();

    let validate_time_claim = |claim_value: Option<&Value>,
                               validate: bool,
                               validation_predicate: &dyn Fn(u64) -> bool,
                               validation_error: Error,
                               missing_claim_error: Error|
     -> Result<(), Error> {
        if validate {
            if let Some(value) = claim_value.and_then(|v| v.as_u64()) {
                if !validation_predicate(value) {
                    return Err(validation_error);
                }
            } else {
                // If the claim is required but missing, return a specific error.
                return Err(missing_claim_error);
            }
        }
        Ok(())
    };

    validate_time_claim(
        claims.get("exp"),
        options.validate_exp,
        &|timestamp| now <= timestamp + options.leeway,
        Error::ExpiredSignature,
        Error::InvalidClaim("Missing exp claim".to_string()),
    )?;

    validate_time_claim(
        claims.get("nbf"),
        options.validate_nbf,
        &|timestamp| now >= timestamp - options.leeway,
        Error::ImmatureSignature,
        Error::InvalidClaim("Missing nbf claim".to_string()),
    )?;

    let validate_str_claim = |claim_value: Option<&Value>,
                              expected_value: &Option<String>,
                              validation_error: Error|
     -> Result<(), Error> {
        if let Some(expected) = expected_value {
            if let Some(actual) = claim_value.and_then(|v| v.as_str()) {
                if actual != expected {
                    return Err(validation_error);
                }
            } else {
                return Err(validation_error);
            }
        }
        Ok(())
    };

    validate_str_claim(claims.get("iss"), &options.issuer, Error::InvalidIssuer)?;
    validate_str_claim(claims.get("sub"), &options.subject, Error::InvalidSubject)?;

    let validate_audiences = |aud_claim: Option<&Value>,
                              expected_audiences: &Option<HashSet<String>>|
     -> Result<(), Error> {
        if let Some(expected) = expected_audiences {
            match aud_claim {
                Some(Value::String(aud)) => {
                    if !expected.contains(aud) {
                        return Err(Error::InvalidAudience);
                    }
                }
                Some(Value::Array(aud_array)) => {
                    let provided: HashSet<String> = aud_array
                        .iter()
                        .filter_map(|val| val.as_str().map(String::from))
                        .collect();
                    if provided.is_disjoint(expected) {
                        return Err(Error::InvalidAudience);
                    }
                }
                _ => return Err(Error::InvalidAudience),
            }
        }
        Ok(())
    };

    validate_audiences(claims.get("aud"), &options.audiences)?;

    Ok(())
}

/// Gets the current timestamp in seconds since the UNIX epoch.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime before UNIX EPOCH")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, to_value};

    #[test]
    fn test_expiration_validation() {
        let mut claims = Map::new();
        claims.insert(
            "exp".to_string(),
            to_value(current_timestamp() + 3600).unwrap(),
        );

        let result = validate(&claims, &ValidationOptions::default());
        if result.is_err() {
            println!("{:?}", result);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_expiration_validation_fail() {
        let mut claims = Map::new();
        claims.insert(
            "exp".to_string(),
            to_value(current_timestamp() - 60).unwrap(),
        );

        let result = validate(&claims, &ValidationOptions::default());
        assert!(matches!(result, Err(Error::ExpiredSignature)));
    }

    #[test]
    fn test_not_before_validation() {
        let mut claims = Map::new();
        claims.insert(
            "exp".to_string(),
            to_value(current_timestamp() + 3600).unwrap(),
        );
        claims.insert("nbf".to_string(), to_value(current_timestamp()).unwrap());

        let options = ValidationOptions::default();
        let result = validate(&claims, &options);
        assert!(result.is_ok());
    }

    #[test]
    fn test_issuer_validation() {
        let mut claims = Map::new();
        claims.insert(
            "exp".to_string(),
            to_value(current_timestamp() + 3600).unwrap(),
        );
        claims.insert("iss".to_string(), json!("valid_issuer"));

        let options = ValidationOptions::default().with_issuer("valid_issuer");
        let result = validate(&claims, &options);
        assert!(result.is_ok());
    }

    #[test]
    fn test_issuer_validation_fail() {
        let mut claims = Map::new();
        claims.insert(
            "exp".to_string(),
            to_value(current_timestamp() + 3600).unwrap(),
        );
        claims.insert("iss".to_string(), json!("invalid_issuer"));

        let options = ValidationOptions::default().with_issuer("valid_issuer");
        let result = validate(&claims, &options);
        assert!(matches!(result, Err(Error::InvalidIssuer)));
    }

    #[test]
    fn test_subject_validation() {
        let mut claims = Map::new();
        claims.insert(
            "exp".to_string(),
            to_value(current_timestamp() + 3600).unwrap(),
        );
        claims.insert("sub".to_string(), json!("valid_subject"));

        let options = ValidationOptions::default().with_subject("valid_subject");
        let result = validate(&claims, &options);
        assert!(result.is_ok());
    }

    #[test]
    fn test_subject_validation_fail() {
        let mut claims = Map::new();
        claims.insert(
            "exp".to_string(),
            to_value(current_timestamp() + 3600).unwrap(),
        );
        claims.insert("sub".to_string(), json!("invalid_subject"));

        let options = ValidationOptions::default().with_subject("valid_subject");
        let result = validate(&claims, &options);
        assert!(matches!(result, Err(Error::InvalidSubject)));
    }

    #[test]
    fn test_audience_validation() {
        let mut claims = Map::new();
        claims.insert(
            "exp".to_string(),
            to_value(current_timestamp() + 3600).unwrap(),
        );
        claims.insert("aud".to_string(), json!("valid_audience"));

        let options = ValidationOptions::default().with_audience("valid_audience");
        let result = validate(&claims, &options);
        assert!(result.is_ok());
    }

    #[test]
    fn test_audience_validation_fail() {
        let mut claims = Map::new();
        claims.insert(
            "exp".to_string(),
            to_value(current_timestamp() + 3600).unwrap(),
        );
        claims.insert("aud".to_string(), json!("invalid_audience"));

        let options = ValidationOptions::default().with_audience("valid_audience");
        let result = validate(&claims, &options);
        assert!(matches!(result, Err(Error::InvalidAudience)));
    }

    #[test]
    fn test_audience_validation_array() {
        let mut claims = Map::new();
        claims.insert(
            "exp".to_string(),
            to_value(current_timestamp() + 3600).unwrap(),
        );
        claims.insert(
            "aud".to_string(),
            json!(["valid_audience", "another_audience"]),
        );

        let options = ValidationOptions::default().with_audience("valid_audience");
        let result = validate(&claims, &options);
        assert!(result.is_ok());
    }

    #[test]
    fn test_audience_validation_array_fail() {
        let mut claims = Map::new();
        claims.insert(
            "exp".to_string(),
            to_value(current_timestamp() + 3600).unwrap(),
        );
        claims.insert(
            "aud".to_string(),
            json!(["invalid_audience", "another_audience"]),
        );

        let options = ValidationOptions::default().with_audience("valid_audience");
        let result = validate(&claims, &options);
        assert!(matches!(result, Err(Error::InvalidAudience)));
    }

    #[test]
    fn test_algorithm_validation() {
        let header = Header {
            alg: Algorithm::HS256,
            ..Header::default()
        };
        let mut claims = Map::new();
        claims.insert(
            "exp".to_string(),
            to_value(current_timestamp() + 3600).unwrap(),
        );

        let options = ValidationOptions::default().with_algorithm(Algorithm::HS256);
        let result = validate_header(&header, &options);
        assert!(result.is_ok());
    }

    #[test]
    fn test_algorithm_validation_fail_in_header() {
        let header = Header {
            alg: Algorithm::HS256,
            ..Header::default()
        };
        let mut claims = Map::new();
        claims.insert(
            "exp".to_string(),
            to_value(current_timestamp() + 3600).unwrap(),
        );

        let options = ValidationOptions::default().with_algorithm(Algorithm::HS384);
        let result = validate_header(&header, &options);
        assert!(matches!(result, Err(Error::InvalidAlgorithm)));
    }
}
