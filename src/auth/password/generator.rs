//! Password generator module
//!
//! This module provides functionality to generate a secure password
//! - `generate_password`: Generates a random password of a specified length
//! - `PASSWORD_LENGTH`: Constant defining the length of the password
//! - `SHARING_SIZE`: Constant defining the size of each character category in the password
//! - `SYMBOLS`: Constant defining the symbols to be used in the password

use rand::rngs::OsRng;
use rand::seq::SliceRandom;

pub const PASSWORD_LENGTH: usize = 24;
pub const SHARING_SIZE: usize = PASSWORD_LENGTH / 4;
pub const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

fn generate_characters(start: char, end: char) -> Vec<u8> {
    (start as u8..=end as u8).collect()
}

pub fn generate_password() -> String {
    let mut rng = OsRng;
    let length = PASSWORD_LENGTH;

    let uppercase = generate_characters('A', 'Z');
    let lowercase = generate_characters('a', 'z');
    let digits = generate_characters('0', '9');

    let mut password = Vec::with_capacity(length);

    for _ in 0..SHARING_SIZE {
        password.push(*uppercase.choose(&mut rng).unwrap());
        password.push(*lowercase.choose(&mut rng).unwrap());
        password.push(*digits.choose(&mut rng).unwrap());
        password.push(*SYMBOLS.choose(&mut rng).unwrap());
    }

    while password.len() < PASSWORD_LENGTH {
        let &category = [uppercase.as_slice(), lowercase.as_slice(), digits.as_slice(), SYMBOLS]
            .choose(&mut rng)
            .unwrap();

        let &next_char = category.choose(&mut rng).unwrap();
        if password.last().map(|&last| last != next_char).unwrap_or(true) {
            password.push(next_char);
        }
    }

    password.shuffle(&mut rng);
    String::from_utf8(password).expect("Error generating password")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_length() {
        let password = generate_password();
        assert_eq!(
            password.len(),
            PASSWORD_LENGTH,
            "Expected password length {}, got {}",
            PASSWORD_LENGTH,
            password.len()
        );
    }

    #[test]
    fn test_password_contains_all_categories() {
        let password = generate_password();

        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_symbol = password.chars().any(|c| SYMBOLS.contains(&(c as u8)));

        assert!(has_uppercase, "Generated password does not contain an uppercase letter");
        assert!(has_lowercase, "Generated password does not contain a lowercase letter");
        assert!(has_digit, "Generated password does not contain a digit");
        assert!(has_symbol, "Generated password does not contain a symbol");
    }

    #[test]
    fn test_password_non_consecutive_characters() {
        let password = generate_password();

        let no_consecutive = password.chars().zip(password.chars().skip(1)).all(|(a, b)| a != b);

        assert!(no_consecutive, "Generated password contains consecutive identical characters");
    }
}
