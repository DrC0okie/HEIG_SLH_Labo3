use ansi_term::Color::{Green};
use crate::models::{Action, Review, Role, User};
use derive_more::Display;
use inquire::{Confirm, CustomType, max_length, min_length, Password, PasswordDisplayMode, Select, Text};
use inquire::validator::{MaxLengthValidator, MinLengthValidator, Validation};
use strum::{EnumIter, IntoEnumIterator};
use crate::utils::{input_validation, hashing};
use ansi_term::Colour::Red;
use inquire::error::InquireResult;
use log::{info, warn};
use crate::db::DATABASE;
use crate::utils::enforcer::access;

#[derive(Debug)]
enum ShouldContinue {
    Yes,
    No,
}

const MAX_USERNAME_LENGTH: usize = 64;
const MAX_PASSWORD_LENGTH: usize = 64;
const MAX_ESTA_NAME_LENGTH: usize = 128;
const MAX_COMMENT_LENGTH: usize = 512;

#[macro_export]
macro_rules! internal_error {
    ($($arg:tt)*) => {{
        use ansi_term::Colour::Red;
        use log::error;

        let formatted_msg = format!($($arg)*);
        error!("{}", formatted_msg);
        println!("{}", Red.paint("Erreur interne"));
        return ShouldContinue::Yes;
    }}
}

pub fn start() {
    loop_menu(main_menu);
}

fn loop_menu<F>(menu_handler: F)
    where
        F: Fn() -> ShouldContinue,
{
    loop {
        match menu_handler() {
            ShouldContinue::Yes => continue,
            ShouldContinue::No => break,
        }
    }
}

fn main_menu() -> ShouldContinue {
    #[derive(EnumIter, Display)]
    enum Choice {
        #[display(fmt = "Se connecter")]
        Login,

        #[display(fmt = "S'inscrire")]
        Register,

        #[display(fmt = "Quitter")]
        Exit,
    }

    let choice = Select::new("Que voulez-vous faire ?", Choice::iter().collect())
        .prompt()
        .unwrap();

    match choice {
        Choice::Login => login(),
        Choice::Register => register(),
        Choice::Exit => ShouldContinue::No,
    }
}

fn login() -> ShouldContinue {

    // Prompt the user for a username
    let username = prompt_text("le nom d'utilisateur", MAX_USERNAME_LENGTH)
        .map_err(|e| { internal_error!("Login error in username prompt: {}", e) }).unwrap();

    // Prompt the user for a password
    let password = Password::new("Entrez votre mot de passe : ")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_validator(empty_validator("Le mot de passe"))
        .with_validator(max_length_validator(MAX_PASSWORD_LENGTH, "Le mot de passe"))
        .without_confirmation()
        .prompt()
        .map_err(|e| { internal_error!("Login error in password prompt: {}", e) })
        .unwrap();

    let mut ok = false;
    let user = User::get(&username);
    if user.is_some() {
        let hashed_password = user.clone().unwrap().password;
        ok = hashing::verify_password(&hashed_password, &password)
            .map_err(|e| { internal_error!("Password verification error during login: {}", e) }).unwrap();
    }
    else {
        let _ = hashing::hash_password(&password).map_err(|e| { internal_error!("Dummy hashing error during login: {}", e) });
    }

    if ok {
        println!("{} {}", Green.paint("Bienvenue, "), Green.paint(&username));
        info!("User {} logged in successfully", &username);
        loop_menu(|| user_menu(&user.clone().unwrap()));
    } else {
        println!("{}", Red.paint("Nom d'utilisateur ou mot de passe incorrect"));
        warn!("Failed login attempt for user {}", &username);
    }

    ShouldContinue::Yes
}

fn register() -> ShouldContinue {

    // Checks if the username already exists
    let existing_user_validator = move |input: &str| match User::get(input) {
        // Note: It is mandatory to leak this information to the user,
        //       otherwise they would not understand why the register process fails
        Some(..) => Ok(Validation::Invalid("Ce nom d'utilisateur existe déjà.".into())),
        None => Ok(Validation::Valid)
    };

    // Prompt the user for a username
    let username = Text::new("Entrez votre nom d'utilisateur : ")
        .with_validator(empty_validator("Le nom d'utilisateur"))
        .with_validator(max_length_validator(MAX_USERNAME_LENGTH, "Le nom d'utilisateur"))
        .with_validator(existing_user_validator)
        .prompt()
        .map_err(|e| { internal_error!("Error in username prompt: {}", e) })
        .unwrap();

    // Checks if the password is valid
    let name = username.clone();
    let password_validator = move |input: &str|
        match input_validation::validate_password(input, Some(name.as_str())) {
            Ok(()) => Ok(Validation::Valid),
            Err(e) => Ok(Validation::Invalid(e.into()))
        };

    // Prompt the user for a password
    let password1 = Password::new("Entrez votre mot de passe : ")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_validator(password_validator)
        .without_confirmation()
        .prompt()
        .map_err(|e| { internal_error!("Error in password1 prompt: {}", e) })
        .unwrap();

    // Checks if the passwords match
    let passwords_match_validator = move |p2: &str|
        match input_validation::do_passwords_match(password1.as_str(), p2) {
            Ok(()) => Ok(Validation::Valid),
            Err(e) => Ok(Validation::Invalid(e.into()))
        };

    // Prompt the user for a password confirmation
    let password2 = Password::new("Confirmez votre mot de passe : ")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_validator(passwords_match_validator)
        .without_confirmation()
        .prompt()
        .map_err(|e| { internal_error!("Error in password confirmation prompt: {}", e) })
        .unwrap();

    // Checks if the user is an owner
    let is_owner = Confirm::new("Êtes-vous propriétaire d'un établissement ?")
        .with_default(false)
        .prompt()
        .map_err(|e| { internal_error!("Error in owner prompt: {}", e) })
        .unwrap();

    // Prompt the user for an establishment name
    let role = if is_owner {
        let owned_establishment = Text::new("Entrez le nom de votre établissement : ")
            .with_validator(empty_validator("Le nom de l'établissement"))
            .with_validator(max_length_validator(MAX_ESTA_NAME_LENGTH, "Le nom de l'établissement"))
            .prompt()
            .map_err(|e| { internal_error!("Error in establishment prompt: {}", e) })
            .unwrap();

        Role::Owner {
            owned_establishment,
        }
    } else {
        Role::Reviewer
    };

    // Hash the password
    let hash = hashing::hash_password(&password2)
        .map_err(|e| { internal_error!("Hashing error during registration: {}", e) }).unwrap();

    // Create the user
    let user = User::new(&username, &hash, role);
    let _ = user.save().map_err(|e| { internal_error!("Error saving the user: {}", e) });

    // Save the DB
    let _ = DATABASE.lock().unwrap().save().map_err(|e| { internal_error!("Error saving the database: {}", e) });

    info!("User {} registered successfully", username);
    println!("{}", Green.paint("Inscription réussie."));
    ShouldContinue::Yes
}

// -----------------------------------------------------------------------------------------------

fn user_menu(user: &User) -> ShouldContinue {
    #[derive(EnumIter, Display)]
    enum Choice {
        #[display(fmt = "Mes avis")]
        ListOwnReviews,

        #[display(fmt = "Ajouter un avis")]
        AddReview,

        #[display(fmt = "Avis d'un établissement")]
        ListEstablishmentReviews,

        #[display(fmt = "Supprimer un avis")]
        DeleteReview,

        #[display(fmt = "Se déconnecter")]
        Logout,
    }

    let choice = match Select::new("Que voulez-vous faire ?", Choice::iter().collect()).prompt() {
        Ok(choice) => choice,
        Err(..) => return ShouldContinue::Yes,
    };

    match choice {
        Choice::ListOwnReviews => list_own_reviews(&user),
        Choice::AddReview => add_review(&user),
        Choice::ListEstablishmentReviews => list_establishment_reviews(&user),
        Choice::DeleteReview => delete_review(&user),
        Choice::Logout => ShouldContinue::No,
    }
}

fn list_own_reviews(user: &User) -> ShouldContinue {
    match access(&user, None, Action::ReadOwnReviews) {
        Ok(true) => (),
        Ok(false) => {
            println!("{}", Red.paint("Vous ne pouvez pas voir vos avis."));
            return ShouldContinue::Yes;
        }
        Err(e) => internal_error!("List own reviews error in policy enforcement: {}", e)
    };

    if Review::by(&user.name).is_empty() {
        println!("{}", Green.paint("Vous n'avez pas encore écrit d'avis."));
    }

    for review in Review::by(&user.name) {
        println!("{}", review);
    }

    ShouldContinue::Yes
}

fn add_review(user: &User) -> ShouldContinue {

    //prompt the establishment
    let establishment = prompt_text("le nom de l'établissement", MAX_ESTA_NAME_LENGTH)
        .map_err(|e| { internal_error!("Add review error in establishment prompt: {}", e) }).unwrap();

    // Check if the user has already written a review for this establishment
    if Review::get(&user.name, &establishment).is_some() {
        println!("{}", Red.paint("Vous avez déjà écrit un avis pour cet établissement."));
        return ShouldContinue::Yes;
    }

    // Check if the user can write reviews for this establishment
    match access(&user, Some(&establishment), Action::WriteReview) {
        Ok(true) => (),
        Ok(false) => {
            println!("{}", Red.paint("Impossible d'ajouter un avis sur votre propre établissement."));
            return ShouldContinue::Yes;
        }
        Err(e) => internal_error!("Add review error in policy enforcement: {}", e)
    }

    // Prompt the comment
    let comment = prompt_text("Votre avis", MAX_COMMENT_LENGTH)
        .map_err(|e| { internal_error!("Add review error in comment prompt: {}", e) }).unwrap();

    let range_validator = move |grade: &u8|
        if *grade >= 1u8 && *grade <= 5u8 {
            Ok(Validation::Valid)
        } else {
            Ok(Validation::Invalid("La note doit être comprise entre 1 et 5.".into()))
        };

    // Prompt the grade
    let grade = match CustomType::<u8>::new("Note (1-5) : ")
        .with_error_message("Veuillez entrer un nombre valide.")
        .with_validator(range_validator)
        .prompt() {
        Ok(p) => p,
        Err(e) => internal_error!("Add review error in note prompt: {}", e)
    };

    // Save the review
    let review = Review::new(&establishment, &user.name, &comment, grade);
    let _ = review.save().map_err(|e|{
        println!("{}", Red.paint(e.to_string()));
        return ShouldContinue::Yes;
    });

    // Save the DB
    let _ = DATABASE.lock().unwrap().save().map_err(|e| { internal_error!("Error saving the database: {}", e) });

    println!("{}", Green.paint("Votre avis a été ajouté avec succès."));
    ShouldContinue::Yes
}

fn list_establishment_reviews(user: &User) -> ShouldContinue {
    let establishment = prompt_text("le nom de l'établissement", MAX_ESTA_NAME_LENGTH)
        .map_err(|e| { internal_error!("List establishment reviews error in establishment prompt: {}", e) })
        .unwrap();

    match access(&user, Some(&establishment), Action::ReadEstablishmentReviews) {
        Ok(true) => (),
        Ok(false) => {
            println!("{}", Red.paint("Vous ne pouvez pas voir les avis de cet établissement."));
            return ShouldContinue::Yes;
        },
        Err(e) => internal_error!("List establishment reviews error in policy enforcement: {}", e)
    };

    if Review::of(&establishment).is_empty() {
        println!("{}", Green.paint("Cet établissement n'a pas encore reçu d'avis."));
    }

    for review in Review::of(&establishment) {
        println!("{}", review);
    }

    ShouldContinue::Yes
}

fn delete_review(user: &User) -> ShouldContinue {
    match access(&user, None, Action::DeleteReview) {
        Ok(true) => (),
        Ok(false) => {
            println!("{}", Red.paint("Vous ne pouvez pas supprimer d'avis."));
            return ShouldContinue::Yes;
        },
        Err(e) => internal_error!("Delete review error in policy enforcement: {}", e)
    };

    let establishment = prompt_text("le nom de l'établissement", MAX_ESTA_NAME_LENGTH)
        .map_err(|e| { internal_error!("Delete review error in establishment prompt: {}", e) }).unwrap();

    let name = prompt_text("le nom de l'auteur", MAX_USERNAME_LENGTH)
        .map_err(|e| { internal_error!("Delete review error in name prompt: {}", e) }).unwrap();

    let review = match Review::get(&name, &establishment) {
        Some(r) => r,
        None => {
            println!("{}", Red.paint("Avis ou établissement introuvable."));
            return ShouldContinue::Yes;
        }
    };

    review.delete();

    // Save the DB
    let _ = DATABASE.lock().unwrap().save().map_err(|e| { internal_error!("Error saving the database: {}", e) });

    println!("{} {} {}", Green.paint("Avis de"), Green.paint(name), Green.paint("supprimé."));
    ShouldContinue::Yes
}

fn empty_validator(object: &str) -> MinLengthValidator {
    min_length!(1, format!("{} ne peut pas être vide", object))
}

fn max_length_validator(length: usize, object: &str) -> MaxLengthValidator {
    max_length!(length, format!("{} ne peut pas dépasser {} caractères", object, length))
}

fn prompt_text(object: &str, length: usize) -> InquireResult<String> {
    Text::new(&format!("Entrez {}: ", object))
        .with_validator(empty_validator(object))
        .with_validator(max_length_validator(length, object))
        .prompt()
}