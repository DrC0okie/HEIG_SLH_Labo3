use std::ops::Range;
use log::info;
use zxcvbn::zxcvbn;

const MIN_PASSWORD_STRENGTH: u8 = 3;

/// Checks if two provided passwords match.
/// # Arguments
/// * `password1` - First password string slice.
/// * `password2` - Second password string slice.
/// # Returns
/// * `Ok(())` if passwords match,
/// * `Err(String)` with an error message if they don't.
pub fn do_passwords_match(password1: &str, password2: &str) -> Result<(), String> {
    if password1 == password2 {
        Ok(())
    } else {
        let msg = "Les mots de passe ne correspondent pas.";
        Err(msg.to_string())
    }
}

/// Validates if the input length is within the specified range.
/// # Arguments
/// * `input` - Input to validate.
/// * `range` - Optional range for the password length. Defaults to 8..64 if None.
/// # Returns
/// * `Ok(())` if the password length is valid,
/// * `Err(String)` with an error message if it's not.
pub fn is_length_valid(input: &str, range: Option<Range<usize>>) -> Result<(), String> {
    let range = range.unwrap_or(8..64);
    if range.contains(&input.len()) {
        Ok(())
    } else {
        let msg = format!("La longueur doit être entre {} et {} caractères.", range.start, range.end);
        Err(msg.to_string())
    }
}

/// Computes the strength score of a password using zxcvbn.
/// # Arguments
/// * `password` - Password to evaluate.
/// * `username` - Optional username to evaluate.
/// # Returns
/// * A score representing the strength of the password.
pub fn get_password_strength(password: &str, username: Option<&str>) -> u8 {
    let mut user_inputs = Vec::new();
    if let Some(u) = username {
        user_inputs.push(u);
    }
    zxcvbn(password, &user_inputs).unwrap().score()
}

/// Validates a password. Checks if it's length is within the specified range and if it's strong enough.
/// # Arguments
/// * `password` - Password to validate.
/// * `username` - Optional username to validate.
/// # Returns
/// * `Ok(())` if the password is valid,
pub fn validate_password(password: &str, username: Option<&str>) -> Result<(), String> {
    is_length_valid(password, None)?;
    let password_strength = get_password_strength(password, username);
    if password_strength < MIN_PASSWORD_STRENGTH {
        return Err("Mot de passe trop faible: ".to_string());
    }
    info!("Password validation success for user {}", username.unwrap_or("not provided"));
    Ok(())
}

#[cfg(test)]
mod tests {
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

        let username = "validUser";
        let too_short_pasword = "hello";
        let too_long_password = "myVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryVeryLargePassword";
        let too_weak_password = "password123";
        let valid_password_1 = "MyFirstValidAndStrongAndBeautifulPassword";
        let valid_password_2 = "validUserPassword";

        // valid password without username
        assert!(validate_password(valid_password_1, None).is_ok());

        // valid password with username
        assert!(validate_password(valid_password_1, Some(username)).is_ok());

        //valid password, but username in it (too weak)
        assert!(validate_password(valid_password_2, Some(username)).is_err());

        // password too long
        assert!(validate_password(too_long_password, None).is_err());

        // password too short
        assert!(validate_password(too_short_pasword, None).is_err());

        // password too weak with username
        assert!(validate_password(too_weak_password, Some(username)).is_err());

        //passwords too weak without username
        assert!(validate_password(too_weak_password, None).is_err());
    }
}
