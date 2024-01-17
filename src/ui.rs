use crate::models::{Review, Role, User};
use anyhow::{anyhow, bail};
use derive_more::Display;
use inquire::{Confirm, CustomType, Password, PasswordDisplayMode, Select, Text};
use inquire::validator::Validation;
use strum::{EnumIter, IntoEnumIterator};
use crate::utils::input_validation;
use crate::utils::hashing;

enum ShouldContinue {
    Yes,
    No,
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
    let username = Text::new("Entrez votre nom d'utilisateur : ")
        .prompt()
        .unwrap();
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

    let length_validator = |input: &str| match input_validation::is_length_valid(input, Some(1..32)){
            Ok(()) => Ok(Validation::Valid),
            Err(e) => Ok(Validation::Invalid(e.into()))
    };

    let username = match Text::new("Entrez votre nom d'utilisateur : ")
        .with_validator(length_validator)
        .prompt(){
            Ok(u) => u,
            Err(_) => {
                println!("Erreur interne");
                return ShouldContinue::No;
            }
        };

    // TODO: check if username already exists
    let usr = username.clone();

    let password1_validator = move |input: &str| match input_validation::validate_password(input, Some(usr.as_str())){
            Ok(()) => Ok(Validation::Valid),
            Err(e) => Ok(Validation::Invalid(e.into()))
    };

    let password1 = match Password::new("Entrez votre mot de passe : ")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_validator(password1_validator)
        .without_confirmation()
        .prompt() {
            Ok(p) => p,
            Err(_) => {
                println!("Erreur interne");
                return ShouldContinue::No;
            }
        };

    let password2_validator = move |p2: &str|
        match input_validation::do_passwords_match(password1.as_str(), p2){
            Ok(()) => Ok(Validation::Valid),
            Err(e) => Ok(Validation::Invalid(e.into()))
    };

    let password2 = match Password::new("Confirmez votre mot de passe : ")
        .with_display_mode(PasswordDisplayMode::Masked)
        .with_validator(password2_validator)
        .without_confirmation()
        .prompt() {
            Ok(p) => p,
            Err(_) => {
                println!("Erreur interne");
                return ShouldContinue::No;
            }
        };

    let is_owner = match Confirm::new("Êtes-vous propriétaire d'un établissement ?")
        .with_default(false)
        .prompt() {
            Ok(o) => o,
            Err(_) => {
                println!("Erreur interne");
                return ShouldContinue::No;
            }
        };

    let length_validator = |input: &str| match input_validation::is_length_valid(input, Some(1..64)){
        Ok(()) => Ok(Validation::Valid),
        Err(e) => Ok(Validation::Invalid(e.into()))
    };

    let role = if is_owner {
        let owned_establishment = match Text::new("Entrez le nom de votre établissement : ")
            .with_validator(length_validator)
            .prompt(){
                Ok(e) => e,
                Err(_) => {
                    println!("Erreur interne");
                    return ShouldContinue::No;
                }
        };
        Role::Owner {
            owned_establishment,
        }
    } else {
        Role::Reviewer
    };

    let hash = match hashing::hash_password(password2.as_bytes()){
        Ok(h) => h,
        Err(_) => {
            println!("Erreur interne");
            return ShouldContinue::No;
        }
    };

    let _ = User::new(&username, &hash, role).save().map_err(|e| {
        println!("Erreur : {}", e);
        return ShouldContinue::No;
    });


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
