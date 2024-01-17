use crate::models::{Review, Role, User};
use anyhow::{anyhow, bail};
use derive_more::Display;
use inquire::{Confirm, CustomType, Password, Select, Text};
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
    let username = Text::new("Entrez votre nom d'utilisateur : ")
        .prompt()
        .unwrap();
    let password = Password::new("Entrez votre mot de passe : ")
        .with_custom_confirmation_message("Confirmez votre mot de passe : ")
        .with_custom_confirmation_error_message("Les mots de passe ne correspondent pas")
        .prompt()
        .unwrap();
    let is_owner = Confirm::new("Êtes-vous propriétaire d'un établissement ?")
        .with_default(false)
        .prompt()
        .unwrap();

    let role = if is_owner {
        let owned_establishment = Text::new("Entrez le nom de votre établissement : ")
            .prompt()
            .unwrap();
        Role::Owner {
            owned_establishment,
        }
    } else {
        Role::Reviewer
    };

    let user = User::new(&username, &password, role);
    let _ = user.save();

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
