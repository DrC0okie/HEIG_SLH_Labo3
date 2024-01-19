use argon2::{Argon2, password_hash::{SaltString, PasswordHasher}, PasswordHash, PasswordVerifier};
use lazy_static::lazy_static;
use rand::rngs::OsRng;

/// Hashes a password using the Argon2 algorithm.
/// # Arguments
/// * `password` - A byte slice representing the user's password.
/// # Returns
/// * `Ok(String)` containing the hashed password. The hash includes the Argon2 parameters and salt.
/// * `Err(String)` containing an error message if the password hashing fails.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(password_hash) => Ok(password_hash.to_string()),
        Err(e) => Err(e.to_string())
    }
}

/// Verifies a plaintext password against a hashed password.
/// # Arguments
/// * `hashed_password` - The hashed password (including Argon2 parameters and salt).
/// * `password` - The plaintext password to verify.
/// # Returns
/// * `Ok(bool)` - `true` if the password matches the hash, `false` otherwise.
/// * `Err(String)` - An error message if the verification process fails.
pub fn verify_password(hashed_password: &str, password: &str) -> Result<bool, String> {
    // Parse the string into PasswordHash
    let parsed_hash = PasswordHash::new(hashed_password).map_err(|e| e.to_string())?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    /// Ensure that a valid password is hashed successfully
    fn test_hash_password_success() {
        let password = "example_password";
        match super::hash_password(password) {
            Ok(hash) => assert!(!hash.is_empty(), "Hash should not be empty"),
            Err(_) => panic!("Hashing failed when it should succeed"),
        }
    }

    #[test]
    /// Verify a correct password against its hash.
    fn test_verify_password_success() {
        let password = "example_password";
        let hash = super::hash_password(password).unwrap();
        let result = super::verify_password(&hash, password);
        assert_eq!(result, Ok(true), "Password should verify successfully");
    }

    #[test]
    /// Test the case where the password does not match the hash.
    fn test_verify_password_failure() {
        let password = "example_password";
        let wrong_password = "wrong_password";
        let hash = super::hash_password(password).unwrap();
        let result = super::verify_password(&hash, wrong_password);
        assert_eq!(result, Ok(false), "Password verification should fail");
    }

    #[test]
    /// Test the behavior when there's an error during verification
    fn test_verify_password_error() {
        let result = super::verify_password("invalid_hash_format", "password");
        assert!(result.is_err(), "Should error on invalid hash format");
    }
}