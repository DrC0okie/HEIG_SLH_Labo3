mod db;
mod ui;

use db::{Database, DATABASE};
use derive_more::Display;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Hash)]
struct User {
    name: String,
    password: String,
    role: Role,
}

impl User {
    fn new(name: &str, password: &str, role: Role) -> Self {
        Self {
            name: name.to_string(),
            password: password.to_string(),
            role,
        }
    }

    fn save(&self) -> anyhow::Result<()> {
        let mut db = DATABASE.lock().unwrap();
        db.store_user(self)
    }

    fn get(username: &str) -> Option<Self> {
        let db = DATABASE.lock().unwrap();
        db.get_user(username)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash)]
#[serde(tag = "name")]
enum Role {
    Reviewer,
    Owner { owned_establishment: String },
    Admin,
}

#[derive(Debug, Serialize, Deserialize, Clone, Display)]
#[display(
fmt = r#"Avis sur "{}", par {}: "{}", {}/5"#,
establishment,
reviewer,
comment,
grade
)]
struct Review {
    establishment: String,
    reviewer: String,
    comment: String,
    grade: u8,
}

impl Review {
    fn new(establishment: &str, reviewer: &str, comment: &str, grade: u8) -> Self {
        Self {
            establishment: establishment.to_string(),
            reviewer: reviewer.to_string(),
            comment: comment.to_string(),
            grade,
        }
    }

    fn save(&self) -> anyhow::Result<()> {
        let mut db = DATABASE.lock().unwrap();
        db.store_review(self)
    }

    fn delete(&self) {
        let mut db = DATABASE.lock().unwrap();
        db.delete_review(&self.reviewer, &self.establishment);
    }

    /// Get a review made by a reviewer for an establishment
    fn get(reviewer: &str, establishment: &str) -> Option<Self> {
        let db = DATABASE.lock().unwrap();
        db.get_review(reviewer, establishment)
    }

    /// Get all reviews by a reviewer
    fn by(reviewer: &str) -> Vec<Self> {
        let db = DATABASE.lock().unwrap();
        db.get_reviews_by_reviewer(reviewer)
    }

    /// Get all reviews of an establishment
    fn of(establishment: &str) -> Vec<Self> {
        let db = DATABASE.lock().unwrap();
        db.get_reviews_of_establishment(establishment)
    }
}

// You can change the default content of the database by changing this `init` method
impl Database {
    fn init(&mut self) {
        let users = vec![
            User::new(
                "Sire Debeugg",
                "0n_d17_ch1ffr3r_3t_p4s_crypt3r",
                Role::Reviewer,
            ),
            User::new(
                "Conte Devvisse",
                "c41ss3-à-0ut1l",
                Role::Owner {
                    owned_establishment: "McDonalds".to_string(),
                },
            ),
            User::new(
                "TheStrongestOne",
                "Sur terre comme au ciel, moi seul mérite d'être vénéré",
                Role::Admin,
            ),
        ];

        let reviews = vec![
            Review::new("McDonalds", "Sire Debeugg", "À fuire !", 1),
            Review::new("Bistrot des Lutins", "Sire Debeugg", "Au top !", 4),
            Review::new("Cafétéria du coin", "Sire Debeugg", "Médiocre.", 2),
            Review::new("Triple R", "Conte Devvisse", "Venez chez moi !", 1),
        ];

        for user in users {
            self.store_user(&user).unwrap();
        }

        for review in reviews {
            self.store_review(&review).unwrap();
        }
    }
}

fn main() {
    ui::start();

    DATABASE
        .lock()
        .unwrap()
        .save()
        .expect("impossible de sauvegarder la base de données");
}
