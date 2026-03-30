use crate::error::ForgeError;

/// Validate a CA name: non-empty, max 255 chars, `[a-zA-Z0-9_-]` only.
pub fn validate_name(name: &str) -> Result<(), ForgeError> {
    if name.is_empty() {
        return Err(ForgeError::InvalidArgument(
            "CA name cannot be empty".into(),
        ));
    }
    if name.len() > 255 {
        return Err(ForgeError::InvalidArgument(
            "CA name exceeds 255 characters".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ForgeError::InvalidArgument(
            "CA name must contain only alphanumeric characters, hyphens, and underscores".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        assert!(validate_name("internal").is_ok());
        assert!(validate_name("my-ca").is_ok());
        assert!(validate_name("root_ca").is_ok());
        assert!(validate_name("CA123").is_ok());
    }

    #[test]
    fn empty_name() {
        assert!(validate_name("").is_err());
    }

    #[test]
    fn name_too_long() {
        let long = "a".repeat(256);
        assert!(validate_name(&long).is_err());
    }

    #[test]
    fn invalid_chars() {
        assert!(validate_name("has space").is_err());
        assert!(validate_name("has.dot").is_err());
        assert!(validate_name("has/slash").is_err());
    }
}
