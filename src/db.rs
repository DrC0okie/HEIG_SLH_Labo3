use crate::{Review, Role, User};
use anyhow::{anyhow, bail};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs::File, sync::Mutex};

// DO NOT MODIFY THIS FILE!!!

static DB_FILE: &str = "database.json";
pub static DATABASE: Lazy<Mutex<Database>> =
    Lazy::new(|| Mutex::new(Database::load().unwrap_or_default()));

#[derive(Serialize, Deserialize)]
pub struct Database {
    users: HashMap<String, User>,
    reviews: Vec<Review>,
}

impl Database {
    fn new() -> Self {
        Self {
            users: HashMap::new(),
            reviews: Vec::new(),
        }
    }

    fn load() -> Option<Self> {
        let file = File::open(DB_FILE).ok()?;
        Some(
            serde_json::from_reader(file)
                .expect("le fichier de la base de donnée est corrompu ou invalide"),
        )
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let file = File::create(DB_FILE)?;
        serde_json::to_writer_pretty(file, self)?;
        Ok(())
    }

    pub fn get_user(&self, name: &str) -> Option<User> {
        self.users.get(name).cloned()
    }

    pub fn get_review(&self, reviewer: &str, establishment: &str) -> Option<Review> {
        self.reviews
            .iter()
            .find(|review| review.reviewer == reviewer && review.establishment == establishment)
            .cloned()
    }

    pub fn get_reviews_by_reviewer(&self, reviewer: &str) -> Vec<Review> {
        self.reviews
            .iter()
            .filter(|review| review.reviewer == reviewer)
            .cloned()
            .collect()
    }

    pub fn get_reviews_of_establishment(&self, establishment: &str) -> Vec<Review> {
        self.reviews
            .iter()
            .filter(|review| review.establishment == establishment)
            .cloned()
            .collect()
    }

    pub fn get_owner_of(&self, estab: &str) -> Option<User> {
        self.users
            .values()
            .find(|user| match user.role {
                Role::Owner {
                    ref owned_establishment,
                } if estab == owned_establishment => true,
                _ => false,
            })
            .cloned()
    }

    pub fn store_user(&mut self, user: &User) -> anyhow::Result<()> {
        // Disallow registration of multiple owners for the same establishment
        if let Role::Owner {
            ref owned_establishment,
        } = user.role
        {
            if self.get_owner_of(owned_establishment).is_some() {
                bail!("un propriétaire pour {} existe déjà", owned_establishment)
            }
        }

        match self.users.get(&user.name) {
            Some(..) => Err(anyhow!("un utilisateur nommé {} existe déjà", user.name)),
            None => {
                self.users.insert(user.name.clone(), user.clone());
                Ok(())
            }
        }
    }

    pub fn store_review(&mut self, review: &Review) -> anyhow::Result<()> {
        match self.get_review(&review.reviewer, &review.establishment) {
            Some(..) => Err(anyhow!(
                "un avis de {} sur {} existe déjà",
                review.reviewer,
                review.establishment
            )),
            None => {
                self.reviews.push(review.clone());
                Ok(())
            }
        }
    }

    pub fn delete_review(&mut self, reviewer: &str, establishment: &str) {
        self.reviews.retain(|review| {
            !(review.reviewer == reviewer && review.establishment == establishment)
        });
    }
}

// Initialize the database to t
impl Default for Database {
    fn default() -> Self {
        let mut db = Self::new();
        db.init();
        db
    }
}
