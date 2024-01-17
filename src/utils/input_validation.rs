use std::ops::Range;
use log::info;
use crate::models::User;
use zxcvbn::zxcvbn;

const MIN_PASSWORD_STRENGTH: u8 = 3;
const MAX_USERNAME_LENGTH: usize = 64;

/// Checks if two provided passwords match.
///
/// # Arguments
/// * `password1` - First password string slice.
/// * `password2` - Second password string slice.
///
/// # Returns
/// * `Ok(())` if passwords match,
/// * `Err(String)` with an error message if they don't.
pub fn do_passwords_match(password1: &str, password2: &str) -> Result<(), String> {
    if password1 == password2 {
        Ok(())
    } else {
        let msg = "Passwords do not match.";
        info!("{}", msg);
        Err(msg.to_string())
    }
}

/// Validates if the password length is within the specified range.
///
/// # Arguments
/// * `password` - Password to validate.
/// * `range` - Optional range for the password length. Defaults to 8..64 if None.
///
/// # Returns
/// * `Ok(())` if the password length is valid,
/// * `Err(String)` with an error message if it's not.
pub fn is_length_valid(input: &str, range: Option<Range<usize>>) -> Result<(), String> {
    let range = range.unwrap_or(8..64);
    if range.contains(&input.len()) {
        Ok(())
    } else {
        let msg = format!("Length is not valid, must be between {} and {} characters.", range.start, range.end);
        info!("{}", msg);
        Err(msg.to_string())
    }
}

/// Computes the strength score of a password using zxcvbn.
///
/// # Arguments
/// * `password` - Password to evaluate.
///
/// # Returns
/// * A score representing the strength of the password.
pub fn get_password_strength(password: &str, username: Option<&[&str]>) -> u8 {
    let username = username.unwrap_or(&[]);
    zxcvbn(password, username).unwrap().score()
}

pub fn validate_passwords(password: &str, password2: &str) -> Result<(), String> {
    do_passwords_match(password, password2)?;
    is_length_valid(password, None)?;

    let password_strength = get_password_strength(password, None);
    if password_strength < MIN_PASSWORD_STRENGTH {
        return Err("Password is too weak.".to_owned());
    }
    info!("Password input valid.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::models::Role;
    use super::*;

    #[test]
    /// Check if the function returns Ok(()) when passwords match.
    fn test_do_passwords_match() {
        assert!(do_passwords_match("password123", "password123").is_ok());
    }

    #[test]
    /// Check for an error when passwords don't match.
    fn test_non_matching_passwords() {
        assert!(do_passwords_match("password123", "different").is_err());
    }

    #[test]
    /// Check if the function returns Ok(()) when the password length is within the specified range.
    fn test_is_password_length_valid() {
        // Within the range
        assert!(is_length_valid("1234", Some(0..8)).is_ok());
        // At the start of the range
        assert!(is_length_valid("12345678", Some(8..64)).is_ok());
        // At the end of the range
        assert!(is_length_valid("1234567", Some(1..8)).is_ok());
        // inversed range
        assert!(is_length_valid("12345", Some(8..1)).is_err());
        // default range
        assert!(is_length_valid("12345678", None).is_ok());
        // out of range
        assert!(is_length_valid("12345678", Some(1..8)).is_err());
        // out of range
        assert!(is_length_valid("1", Some(2..8)).is_err());
    }

    #[test]
    /// Check if a valid user and passwords passes all validations.
    fn test_validate_user_and_passwords() {

        let too_short_pasword = "hello";
        let too_long_password = "myVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryLargePassword";
        let too_weak_password = "password123";
        let valid_password_1 = "MyFirstValidAndStrongAndBeautifulPassword";
        let valid_password_2 = "MySecondValidAndStrongAndBeautifulPassword";
        let valid_username = "validUser";
        let invalid_username = "";


        let invalid_username = User {
            name: valid_username.to_string(),
            password: too_short_pasword.to_string(),
            role: Role::Reviewer,
        };

        let password_too_long = User {
            name: valid_username.to_string(),
            password: too_long_password.to_string(),
            role: Role::Reviewer,
        };

        let password_does_not_match = User {
            name: valid_username.to_string(),
            password: valid_password_1.to_string(),
            role: Role::Reviewer,
        };

        let invalid_email = User {
            name: invalid_username.to_string(),
            password: valid_password_1.to_string(),
            role: Role::Reviewer,
        };

        let valid_username = User {
            name: valid_username.to_string(),
            password: valid_password_1.to_string(),
            role: Role::Reviewer,
        };

        let password_too_weak = User {
            name: valid_username.to_string(),
            password: too_weak_password.to_string(),
            role: Role::Reviewer,
        };

        //valid password
        assert!(validate_passwords(&valid_password_1, &valid_password_1).is_ok());

        // password too short
        assert!(validate_passwords(too_short_pasword, too_short_pasword).is_err());

        // password too long
        assert!(validate_passwords(too_long_password, too_long_password).is_err());

        // passwords do not match
        assert!(validate_passwords(valid_password_1, valid_password_2).is_err());

        //passwords too weak
        assert!(validate_passwords(too_weak_password, too_weak_password).is_err());

        //-----------Users

        //user with valid email
        assert!(is_length_valid(&valid_username.name, None).is_ok());

        //user with valid email
        assert!(is_length_valid(&invalid_username.name, None).is_err());

    }
}
