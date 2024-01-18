use crate::models::{Review, Role, User};
use anyhow::{anyhow, bail};
use derive_more::Display;
use inquire::{Confirm, CustomType, Password, PasswordDisplayMode, Select, Text};
use inquire::validator::{StringValidator, Validation};
use strum::{EnumIter, IntoEnumIterator};
use crate::utils::input_validation;
use crate::utils::hashing;
use ansi_term::Colour::Red;
use log::debug;
use crate::db::DATABASE;

enum ShouldContinue {
    Yes,
    No,
}

#[macro_export]
macro_rules! internal_error {
    ($($arg:tt)*) => {{
        use ansi_term::Colour::Red;  // Ensure Red is in scope

        let formatted_msg = format!($($arg)*);
        debug!("{}", formatted_msg);
        println!("{}", Red.paint("Erreur interne"));
        return ShouldContinue::No
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
    // Checks the username length
    let length_validator = |input: &str| match input_validation::is_length_valid(input, Some(1..32)){
            Ok(()) => Ok(Validation::Valid),
            Err(e) => Ok(Validation::Invalid(e.into()))
        };

    // Prompt the user for a username
    let username = match Text::new("Entrez votre nom d'utilisateur : ")
        .with_validator(length_validator)
        .prompt(){
        Ok(u) => u,
        Err(e) => {
            println!("Erreur interne");
            debug!("Login error in username prompt: {}", e);
            return ShouldContinue::No;
        }
    };

    let password = Password::new("Entrez votre mot de passe: ")
        .without_confirmation()
        .prompt()
        .unwrap();

    let user = User::get(&username).expect("l'utilisateur n'existe pas");

    if password == user.password {
        loop_menu(|| user_menu(&user));
    } else {
        println!("Le mot de passe est incorrect");
    }

    ShouldContinue::Yes
}

fn register() -> ShouldContinue {

    // Checks the username length
    let length_validator: Box<dyn StringValidator> = Box::new(|input: &str| {
        match input_validation::is_length_valid(input, Some(1..32)){
            Ok(()) => Ok(Validation::Valid),
            Err(e) => Ok(Validation::Invalid(e.into()))
        }
    });

    // Checks if the username already exists
    let existing_user_validator: Box<dyn StringValidator>  =  Box::new(|input: &str|{
        if User::get(input).is_some() {
            Ok(Validation::Invalid("Le nom d'utilisateur existe déjà".into()))
        } else {
            Ok(Validation::Valid)
        }
    });

    // Prompt the user for a username
    let username = match Text::new("Entrez votre nom d'utilisateur : ")
        .with_validators(&[length_validator, existing_user_validator])
        .prompt(){
            Ok(u) => u,
            Err(e) => internal_error!("Error in username prompt: {}", e)
        };

    // Checks if the password is valid
    let name = username.clone();
    let password_validator = move |input: &str|
        match input_validation::validate_password(input, Some(name.as_str())){
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
            Err(e) =>  internal_error!("Error in password1 prompt: {}", e)
        };

    // Checks if the passwords match
    let passwords_match_validator = move |p2: &str|
        match input_validation::do_passwords_match(password1.as_str(), p2){
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

    // Checks the length of the establishment name
    let length_validator = |input: &str| match input_validation::is_length_valid(input, Some(1..64)){
        Ok(()) => Ok(Validation::Valid),
        Err(e) => Ok(Validation::Invalid(e.into()))
    };

    // Prompt the user for an establishment name
    let role = if is_owner {
        let owned_establishment = match Text::new("Entrez le nom de votre établissement : ")
            .with_validator(length_validator)
            .prompt(){
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
    let hash = match hashing::hash_password(password2.as_bytes()){
        Ok(h) => h,
        Err(e) => internal_error!("Hashing error during registration: {}", e)
    };

    // Create the user
    let user = User::new(&username, &hash, role);
    let _ = user.save().map_err(|e| {
        println!("{}", Red.paint(format!("Erreur : {}", e)));
        return ShouldContinue::No;
    });

    // Save the DB
    match DATABASE.lock().unwrap().save(){
        Ok(_) => {},
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
        Choice::ListOwnReviews => list_own_reviews(user),
        Choice::AddReview => add_review(user).unwrap(),
        Choice::ListEstablishmentReviews => list_establishment_reviews(),
        Choice::DeleteReview => delete_review(user).unwrap(),
        Choice::Logout => ShouldContinue::No,
    }
}

fn list_own_reviews(user: &User) -> ShouldContinue {
    for review in Review::by(&user.name) {
        println!("{}", review);
    }

    ShouldContinue::Yes
}

fn add_review(user: &User) -> anyhow::Result<ShouldContinue> {
    let establishment = Text::new("Entrez le nom de l'établissement : ").prompt()?;

    if let Role::Owner {
        ref owned_establishment,
    } = user.role
    {
        if owned_establishment == &establishment {
            bail!("vous ne pouvez pas ajouter d'avis sur votre propre établissement");
        }
    }

    let comment = Text::new("Entrez votre commentaire : ").prompt()?;
    let grade = CustomType::new("Entrez votre note : ").prompt()?;
    let review = Review::new(&establishment, &user.name, &comment, grade);

    review.save()?;

    Ok(ShouldContinue::Yes)
}

fn list_establishment_reviews() -> ShouldContinue {
    let establishment = Text::new("Entrez le nom de l'établissement : ")
        .prompt()
        .unwrap();

    for review in Review::of(&establishment) {
        println!("{}", review);
    }

    ShouldContinue::Yes
}

fn delete_review(_user: &User) -> anyhow::Result<ShouldContinue> {
    let establishment = Text::new("Entrez le nom de l'établissement : ").prompt()?;

    let is_admin = Confirm::new("Êtes-vous administrateur ?")
        .with_default(true)
        .prompt()?;

    if !is_admin {
        bail!("vous n'êtes pas administrateur")
    }

    let name = Text::new("Entrez le nom de l'auteur de l'avis : ").prompt()?;
    let review = Review::get(&name, &establishment).ok_or(anyhow!("avis manquant"))?;

    review.delete();

    Ok(ShouldContinue::Yes)
}
