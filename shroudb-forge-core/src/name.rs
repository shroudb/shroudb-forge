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

    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            // Any arbitrary string input must never panic validate_name.
            #[test]
            fn arbitrary_string_never_panics(s in "\\PC*") {
                let _ = validate_name(&s);
            }

            // Names matching the allowed alphabet should always be accepted.
            #[test]
            fn valid_alphabet_names_accepted(s in "[a-zA-Z0-9_-]{1,100}") {
                validate_name(&s).expect("valid alphabet name should be accepted");
            }

            // Names exceeding 255 chars must always be rejected.
            #[test]
            fn oversized_names_rejected(s in "[a-zA-Z0-9_-]{256,512}") {
                validate_name(&s).expect_err("oversized name should be rejected");
            }

            // Any name that validate_name accepts must have only allowed chars and length <= 255.
            #[test]
            fn accepted_names_are_safe(s in "\\PC{1,300}") {
                if validate_name(&s).is_ok() {
                    assert!(s.len() <= 255);
                    assert!(!s.is_empty());
                    assert!(s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
                }
            }
        }
    }
}
