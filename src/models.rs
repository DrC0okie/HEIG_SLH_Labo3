use derive_more::Display;
use serde::{Deserialize, Serialize};
use crate::db::DATABASE;

#[derive(Debug, Serialize, Deserialize, Clone, Hash)]
#[serde(tag = "name")]
pub enum Action {
    Read,
    Write,
    Delete,
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash)]
#[serde(tag = "name")]
pub enum Role {
    Reviewer,
    Owner { owned_establishment: String },
    Admin,
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash)]
pub struct User {
    pub name: String,
    pub password: String,
    pub role: Role,
}

impl User {
    pub fn new(name: &str, password: &str, role: Role) -> Self {
        Self {
            name: name.to_string(),
            password: password.to_string(),
            role,
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let mut db = DATABASE.lock().unwrap();
        db.store_user(self)
    }

    pub fn get(username: &str) -> Option<Self> {
        let db = DATABASE.lock().unwrap();
        db.get_user(username)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Display)]
#[display(fmt = r#"Avis sur "{}", par {}: "{}", {}/5"#,establishment,reviewer,comment,grade)]
pub struct Review {
    pub establishment: String,
    pub reviewer: String,
    pub comment: String,
    pub grade: u8,
}

impl Review {
    pub fn new(establishment: &str, reviewer: &str, comment: &str, grade: u8) -> Self {
        Self {
            establishment: establishment.to_string(),
            reviewer: reviewer.to_string(),
            comment: comment.to_string(),
            grade,
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let mut db = DATABASE.lock().unwrap();
        db.store_review(self)
    }

    pub fn delete(&self) {
        let mut db = DATABASE.lock().unwrap();
        db.delete_review(&self.reviewer, &self.establishment);
    }

    /// Get a review made by a reviewer for an establishment
    pub fn get(reviewer: &str, establishment: &str) -> Option<Self> {
        let db = DATABASE.lock().unwrap();
        db.get_review(reviewer, establishment)
    }

    /// Get all reviews by a reviewer
    pub fn by(reviewer: &str) -> Vec<Self> {
        let db = DATABASE.lock().unwrap();
        db.get_reviews_by_reviewer(reviewer)
    }

    /// Get all reviews of an establishment
    pub fn of(establishment: &str) -> Vec<Self> {
        let db = DATABASE.lock().unwrap();
        db.get_reviews_of_establishment(establishment)
    }
}