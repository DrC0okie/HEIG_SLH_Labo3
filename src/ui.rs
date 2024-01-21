use ansi_term::Color::{Green};
use crate::models::{Action, Review, Role, User};
use derive_more::Display;
use inquire::{Confirm, CustomType, max_length, min_length, Password, PasswordDisplayMode, Select, Text};
use inquire::validator::{MaxLengthValidator, MinLengthValidator, Validation};
use strum::{EnumIter, IntoEnumIterator};
use crate::utils::{input_validation, hashing, enforcer::ENFORCER};
use ansi_term::Colour::Red;
use casbin::{CoreApi};
use inquire::error::InquireResult;
use crate::db::DATABASE;

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
        use ansi_term::Colour::Red;  // Ensure Red is in scope
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
    let username = match prompt_text("le nom d'utilisateur", MAX_USERNAME_LENGTH){
        Ok(u) => u,
        Err(e) => internal_error!("Login error in username prompt: {}", e)
    };

    // Prompt the user for a password
    let password = match Password::new("Entrez votre mot de passe : ")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_validator(empty_validator("Le mot de passe"))
        .with_validator(max_length_validator(MAX_PASSWORD_LENGTH, "Le mot de passe"))
        .without_confirmation()
        .prompt() {
        Ok(p) => p,
        Err(e) => internal_error!("Login error in password prompt: {}", e)
    };
    let mut ok = false;
    let user = User::get(&username);
    if user.is_some() {
        let hashed_password = user.clone().unwrap().password;
        ok = match hashing::verify_password(&hashed_password, &password) {
            Ok(true) => true,
            Ok(false) => false,
            Err(e) => internal_error!("Password verification error during login: {}", e)
        }
    }// User not found => dummy hash
    else {
        let _ = match hashing::hash_password(&password) {
            Ok(h) => h,
            Err(e) => internal_error!("Dummy hashing error during login: {}", e)
        };
    }

    if ok {
        println!("{} {}", Green.paint("Bienvenue, "), Green.paint(username));
        loop_menu(|| user_menu(&user.clone().unwrap()));
        ShouldContinue::Yes // Loop to the main menu
    } else {
        println!("{}", Red.paint("Nom d'utilisateur ou mot de passe incorrect"));
        ShouldContinue::Yes // Loop to the main menu
    }
}

fn register() -> ShouldContinue {

    // Checks if the username already exists
    let existing_user_validator = move |input: &str| match User::get(input) {
        Some(..) => Ok(Validation::Invalid("Ce nom d'utilisateur existe déjà.".into())),
        None => Ok(Validation::Valid)
    };

    // Prompt the user for a username
    let username = match Text::new("Entrez votre nom d'utilisateur : ")
        .with_validator(empty_validator("Le nom d'utilisateur"))
        .with_validator(max_length_validator(MAX_USERNAME_LENGTH, "Le nom d'utilisateur"))
        .with_validator(existing_user_validator)
        .prompt() {
        Ok(u) => u,
        Err(e) => internal_error!("Error in username prompt: {}", e)
    };

    // Checks if the password is valid
    let name = username.clone();
    let password_validator = move |input: &str|
        match input_validation::validate_password(input, Some(name.as_str())) {
            Ok(()) => Ok(Validation::Valid),
            Err(e) => Ok(Validation::Invalid(e.into()))
        };

    // Prompt the user for a password
    let password1 = match Password::new("Entrez votre mot de passe : ")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_validator(password_validator)
        .without_confirmation()
        .prompt() {
        Ok(p) => p,
        Err(e) => internal_error!("Error in password1 prompt: {}", e)
    };

    // Checks if the passwords match
    let passwords_match_validator = move |p2: &str|
        match input_validation::do_passwords_match(password1.as_str(), p2) {
            Ok(()) => Ok(Validation::Valid),
            Err(e) => Ok(Validation::Invalid(e.into()))
        };

    // Prompt the user for a password confirmation
    let password2 = match Password::new("Confirmez votre mot de passe : ")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_validator(passwords_match_validator)
        .without_confirmation()
        .prompt() {
        Ok(p) => p,
        Err(e) => internal_error!("Error in password confirmation prompt: {}", e)
    };

    // Checks if the user is an owner
    let is_owner = match Confirm::new("Êtes-vous propriétaire d'un établissement ?")
        .with_default(false)
        .prompt() {
        Ok(o) => o,
        Err(e) => internal_error!("Error in owner prompt: {}", e)
    };

    // Prompt the user for an establishment name
    let role = if is_owner {
        let owned_establishment = match Text::new("Entrez le nom de votre établissement : ")
            .with_validator(empty_validator("Le nom de l'établissement"))
            .with_validator(max_length_validator(MAX_ESTA_NAME_LENGTH, "Le nom de l'établissement"))
            .prompt() {
            Ok(i) => i,
            Err(e) => internal_error!("Error in establishment prompt: {}", e)
        };
        Role::Owner {
            owned_establishment,
        }
    } else {
        Role::Reviewer
    };

    // Hash the password
    let hash = match hashing::hash_password(&password2) {
        Ok(h) => h,
        Err(e) => internal_error!("Hashing error during registration: {}", e)
    };

    // Create the user
    let user = User::new(&username, &hash, role);
    let _ = user.save().map_err(|e| { internal_error!("Error saving the user: {}", e)});

    // Save the DB
    match DATABASE.lock().unwrap().save() {
        Ok(_) => {}
        Err(e) => internal_error!("Error saving the database: {}", e)
    }

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
    let e = &*ENFORCER;
    match e.enforce((&user, "", Action::ReadOwnReviews)){
        Ok(true) => (),
        Ok(false) => {
            println!("{}", Red.paint("Vous ne pouvez pas voir vos avis."));
            return ShouldContinue::Yes;
        },
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
    let establishment = match prompt_text("le nom de l'établissement", MAX_ESTA_NAME_LENGTH) {
        Ok(p) => p,
        Err(e) => internal_error!("Add review error in establishment prompt: {}", e)
    };

    // Check if the user has already written a review for this establishment
    match Review::get(&user.name, &establishment) {
        Some(..) => {
            println!("{}", Red.paint("Vous avez déjà écrit un avis pour cet établissement."));
            return ShouldContinue::Yes;
        },
        None => {}
    }

    // Check if the user can write reviews for this establishment
    let e = &*ENFORCER;
    match e.enforce((&user, &establishment, Action::WriteReview)) {
        Ok(true) => (),
        Ok(false) => {
            println!("{}", Red.paint("Impossible d'ajouter un avis sur votre propre établissement."));
            return ShouldContinue::Yes;
        },
        Err(e) => internal_error!("Add review error in policy enforcement: {}", e)
    }

    // Prompt the comment
    let comment = match prompt_text("Votre avis", MAX_COMMENT_LENGTH){
        Ok(p) => p,
        Err(e) => internal_error!("Add review error in comment prompt: {}", e)
    };

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
        .prompt(){
        Ok(p) => p,
        Err(e) => internal_error!("Add review error in note prompt: {}", e)
    };

    // Save the review
    let review = Review::new(&establishment, &user.name, &comment, grade);
    match review.save(){
        Ok(_) => {}
        Err(e) => { // This should never happen
            println!("{}", Red.paint(e.to_string()));
            return ShouldContinue::Yes;
        }
    }

    // Save the DB
    match DATABASE.lock().unwrap().save() {
        Ok(_) => {}
        Err(e) => internal_error!("Error saving the database: {}", e)
    }

    println!("{}",Green.paint("Votre avis a été ajouté avec succès."));
    ShouldContinue::Yes
}

fn list_establishment_reviews(user: &User) -> ShouldContinue {
    let establishment = match prompt_text("le nom de l'établissement", MAX_ESTA_NAME_LENGTH){
        Ok(p) => p,
        Err(e) => internal_error!("List establishment reviews error in establishment prompt: {}", e)
    };

    let e = &*ENFORCER;
    match e.enforce((&user, &establishment, Action::ReadEstablishmentReviews)){
        Ok(true) => (),
        Ok(false) => {
            println!("{}", Red.paint("Vous ne pouvez pas voir les avis de cet établissement."));
            return ShouldContinue::Yes;
        },
        Err(e) => internal_error!("List establishment reviews error in policy enforcement: {}", e)
    };

    for review in Review::of(&establishment) {
        println!("{}", review);
    }

    ShouldContinue::Yes
}

fn delete_review(user: &User) -> ShouldContinue {
    let establishment = match prompt_text("le nom de l'établissement", MAX_ESTA_NAME_LENGTH) {
        Ok(p) => p,
        Err(e) => internal_error!("Delete review error in establishment prompt: {}", e)
    };

    let name = match prompt_text("le nom de l'auteur", MAX_USERNAME_LENGTH){
        Ok(p) => p,
        Err(e) => internal_error!("Delete review error in name prompt: {}", e)
    };

    let e = &*ENFORCER;
    match e.enforce((&user, "", Action::DeleteReview)){
        Ok(true) => (),
        Ok(false) => {
            println!("{}", Red.paint("Vous ne pouvez pas supprimer cet avis."));
            return ShouldContinue::Yes;
        },
        Err(e) => internal_error!("Delete review error in policy enforcement: {}", e)
    };

    let review = match Review::get(&name, &establishment){
        Some(r) => r,
        None => {
            println!("{}", Red.paint("Avis ou établissement introuvable."));
            return ShouldContinue::Yes;
        }
    };

    review.delete();

    // Save the DB
    match DATABASE.lock().unwrap().save() {
        Ok(_) => {}
        Err(e) => internal_error!("Error saving the database: {}", e)
    }

    println!("{} {} {}", Green.paint("Avis de"), Green.paint(name), Green.paint("supprimé."));
    ShouldContinue::Yes
}

fn empty_validator(object: &str) -> MinLengthValidator {
    min_length!(1, format!("{} ne peut pas être vide", object))
}

fn max_length_validator(length: usize,object: &str) -> MaxLengthValidator {
    max_length!(length, format!("{} ne peut pas dépasser {} caractères", object, length))
}

fn prompt_text(object: &str, length: usize)->InquireResult<String>{
    Text::new(&format!("Entrez {}: ", object))
        .with_validator(empty_validator(object))
        .with_validator(max_length_validator(length, object))
        .prompt()
}