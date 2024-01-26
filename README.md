# SLH Labo3 : Access control

**Author : ** Timothée Van Hove

**Date : ** 26.01.2024





![](figures/labo3.png)



## Introduction

The goal of this lab is to detect security vulnerabilities and bad practices in a provided rust console application. In addition, the access control should be managed with an access control tool (ex. casbin), not manually.



## Vulnerabilities found in the given code

### Input validation

Virtually no input validation is performed in the prompts of the code provided. The user can enter empty text in any input, or enter a grade > 5 in a review, or entering arbitrary long text in any user input. In addition, there is no verification if the user already exists, leading to the overwrite of the user. I therefore decided to implement an input length check (min-max) in each user prompt to avoid any risk of DoS. All the input validation is done using `inquire` Validators. In addition of the length check, I set custom validators in user prompts where it was needed.

I chose to implement the password validation process with two instances of `Password::new` because of the the behavior of the `with_validator` function with Inquire. Normally, if a password confirmation step is used, `with_validator` is activated for each password input, including the confirmation. Suppose a user inputs an incorrect password in the confirmation step. The error message generated would come from the validator's response, not the intended `custom_confirmation_error_message`. The user would receive a validator-specific error message instead of the notification that the passwords do not match. In contrast, by using two calls to `Password::new`, it ensures that the user receives the correct error message – “Password do not match” – specifically during the password confirmation phase.

```rust
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
```



### Authentication

No condition were implemented for the password strength or length in the registration process. I decided to use `zxcvbn` to enforce a strong password (also by providing the username) and enforce the length to be between 8 and 64 characters.

#### Plaintext credential storage

Well.., it's hard to do any worse, so passwords are now stored hashed and salted in the database with argon2. The user password verifying process is done in a time-constant way, to protect against timing attacks.



### Error handling

#### Insufficient error handling

In the given code base, almost no error is handled. This leads the program to panic when something goes wrong. For instance, when the credentials are wrong in the login process, or during "Ajouter un avis" and "Supprimer un avis" actions the program just crashes.

In my implementation, I focused on error handling. In the event of an error, the program simply displays "Erreur interne" to the user, logs the origin of the error and displays the main menu.



#### Information leaks

The few prompted errors did leak too much information. For instance, in the login process:

```rust
    let user = User::get(&username).expect("l'utilisateur n'existe pas");

    if password == user.password {
        loop_menu(|| user_menu(&user));
    } else {
        println!("Le mot de passe est incorrect");
    } // here we panic!
```

In this case, we don't want to be too precise about what went wrong in the login process. The error should instead be displayed as :

```rust
"Nom d'utilisateur ou mot de passe incorrect"
```

**Note: ** I want to mention that in my new implementation I do leak the information of an already existing user or an already owned establishment in the `register()` function. This is necessary in our case, otherwise the user couldn't understand why the register process fails.



### Authorization

Because the goal of this lab is to handle access control with casbin, I won't go deep in the access control vulnerabilities in the given program because I have re-implemented it from scratch. The problems I observed were:

* An Owner and a Reviewer can read everyone's reviews.
* An Owner can review his own restaurant
* Anybody can delete any reviews because of this gem in the code:

```rust
    let is_admin = Confirm::new("Êtes-vous administrateur ?")
        .with_default(true)
        .prompt()?;

    if !is_admin {
        bail!("vous n'êtes pas administrateur")
    }
```

In the new implementation, every access is enforced with casbin. Even if in the current lab instructions all roles are permitted to read their own reviews, it could potentially change in the future.



#### Casbin model (ABAC)

This model handles requests containing a subject (User structure), an object (String) and an action (Action enum). I define the policy as a subject rule to be evaluated and the action to be compared.

```rust
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub_rule, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = eval(p.sub_rule) && r.act.name == p.act
```



#### Policies

I decided to declare 1 policy / line. It is easier to read, to maintain and allows to quickly change any access control in the future (e.g we want to deny admins to write reviews).

```
p, r.sub.role.name == "Reviewer", "ReadOwnReviews"
p, r.sub.role.name == "Reviewer", "WriteReview"

p, r.sub.role.name == "Owner", "ReadOwnReviews"
p, r.sub.role.name == "Owner" && r.sub.role.owned_establishment != r.obj, "WriteReview"
p, r.sub.role.name == "Owner" && r.sub.role.owned_establishment == r.obj, 
"ReadEstablishmentReviews"

p, r.sub.role.name == "Admin", "ReadOwnReviews"
p, r.sub.role.name == "Admin", "WriteReview"
p, r.sub.role.name == "Admin", "ReadEstablishmentReviews"
p, r.sub.role.name == "Admin", "DeleteReview"
```



## Miscellaneous bugs

The DB is only saved when the user decides to quit properly the application. This could be a problem if for some reason the user decides to enter `ctrl + c`, the database would not be saved. Instead of saving the DB when the user quits the program, I decided to save it each time an new element is created (registration + review), or deleted.



## UX issues

* The `PasswordDisplayMode` was `Hidden`. This is a problem because `inquire` does not reset the input in case of a validator error, so the user doesn't know that he has to delete the input. I set it to `Masked` to be clearer for the user.

* I didn't want the user to be stuck in a validation loop. For instance, in the login process, in case of an invalid password or username, instead of looping on the prompt, where the user could be stuck if he didn't remember his credentials, I simply display the error and go back in the main menu.
* I display a confirmation for each user action (Register, Login, Add review, delete review). Like that, the user clearly knows what is the result of his action.



## Code best practices

The user, Role and Review are implemented in the main file. I created separate "models" module for a better separation of concerns.

I factored the code to avoid code duplicates as much as possible. For instance, I created a macro that allows to log an error message, display a generic error to the user, and return to the main menu:

```rust
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
```

As another example, I factored the prompt of a simple text, with simple validators that I use many times in the code:

```rust
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
```



## Tests

### Unit tests

Unit tests have been implemented for the input_validation and hashing modules. The access control policies have also been tested in the enforcer module.

### Manual access control tests

I didn't have time to implement integration tests to validate the access control, so instead I did the tests manually:

* Admin
  - [x] Can read his own reviews
  - [x] Can read reviews of any establishment
  - [x] Can write a review for any establishment
  - [x] Can delete any review

* Owners
  - [x] Can read his own reviews
  - [x] Can read reviews of his own establishment
  - [x] Can not read reviews of other establishments
  - [x] Can not write reviews for his own establishment
  - [x] Can write reviews for other establishments
  - [x] can not delete any review
* Reviewers
  - [x] Can read his own reviews
  - [x] Can not read reviews of any establishment
  - [x] Can write a review for any establishment
  - [x] Can not delete any review

 
