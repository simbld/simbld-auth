//! Password validation utilities.
//!
//! Enforces security requirements for passwords, including:
//! - Minimum length
//! - Character complexity requirements
//! - Common password checks

// Constants for password requirements
pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const REQUIRE_UPPERCASE: bool = true;
pub const REQUIRE_LOWERCASE: bool = true;
pub const REQUIRE_DIGIT: bool = true;
pub const REQUIRE_SYMBOL: bool = true;

/// Validates a password against security requirements
///
/// Returns true if the password meets all requirements, false otherwise
pub fn validate_password(password: &str) -> bool {
  // Check password length
  if password.len() < MIN_PASSWORD_LENGTH {
    return false;
  }

  // Check character requirements
  let has_uppercase = !REQUIRE_UPPERCASE || password.chars().any(|c| c.is_uppercase());
  let has_lowercase = !REQUIRE_LOWERCASE || password.chars().any(|c| c.is_lowercase());
  let has_digit = !REQUIRE_DIGIT || password.chars().any(|c| c.is_ascii_digit());
  let has_symbol = !REQUIRE_SYMBOL || password.chars().any(|c| !c.is_alphanumeric());

  // All requirements must be met
  has_uppercase && has_lowercase && has_digit && has_symbol
}

/// Get detailed validation results for a password
///
/// Returns a struct containing validation results for each requirement
pub fn get_password_validation_details(password: &str) -> PasswordValidationDetails {
  PasswordValidationDetails {
    meets_length: password.len() >= MIN_PASSWORD_LENGTH,
    has_uppercase: password.chars().any(|c| c.is_uppercase()),
    has_lowercase: password.chars().any(|c| c.is_lowercase()),
    has_digit: password.chars().any(|c| c.is_ascii_digit()),
    has_symbol: password.chars().any(|c| !c.is_alphanumeric()),
  }
}

/// Detailed password validation results
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordValidationDetails {
  pub meets_length: bool,
  pub has_uppercase: bool,
  pub has_lowercase: bool,
  pub has_digit: bool,
  pub has_symbol: bool,
}

impl PasswordValidationDetails {
  /// Check if all requirements are met
  pub fn is_valid(&self) -> bool {
    self.meets_length &&
        (!REQUIRE_UPPERCASE || self.has_uppercase) &&
        (!REQUIRE_LOWERCASE || self.has_lowercase) &&
        (!REQUIRE_DIGIT || self.has_digit) &&
        (!REQUIRE_SYMBOL || self.has_symbol)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_valid_password() {
    let password = "Test1234!";
    assert!(validate_password(password));
  }

  #[test]
  fn test_short_password() {
    let password = "Abc1!";
    assert!(!validate_password(password));
  }

  #[test]
  fn test_password_without_uppercase() {
    let password = "test1234!";
    assert!(!validate_password(password));
  }

  #[test]
  fn test_password_without_lowercase() {
    let password = "TEST1234!";
    assert!(!validate_password(password));
  }

  #[test]
  fn test_password_without_digit() {
    let password = "TestTest!";
    assert!(!validate_password(password));
  }

  #[test]
  fn test_password_without_symbol() {
    let password = "Test1234";
    assert!(!validate_password(password));
  }

  #[test]
  fn test_validation_details() {
    let details = get_password_validation_details("Test1234!");
    assert!(details.meets_length);
    assert!(details.has_uppercase);
    assert!(details.has_lowercase);
    assert!(details.has_digit);
    assert!(details.has_symbol);
    assert!(details.is_valid());
  }
}