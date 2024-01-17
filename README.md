# HEIG_SLH_Labo3


## Introduction



## Critical resources & actions

### Resources

### Actions



### Critical resources authorization



## Access control tests





## Problems

Separation of concerns: The user, Role and Review are implemented in the main file. I created separate "models" crate for them.





I decided to implement the password validation step with 2 calls to the `Password::new` . I did it this way because the `with_validator` function in the `inquire` crate is invoked for each password entry, including the confirmation. This is a problem when the user enters an invalid password as a confirmation, because the displayed error will be the one returned by the validator, and not the `custom_confirmation_error_message`.
