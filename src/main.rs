mod db;
mod ui;
mod utils;
mod models;

use db::{Database, DATABASE};
use crate::models::{Review, Role, User};

// You can change the default content of the database by changing this `init` method
impl Database {
    fn init(&mut self) {
        let init_admin = User::new("admin","admin", Role::Admin);
        self.store_user(&init_admin).unwrap();
    }
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Error)// Change this to `Debug` to see debug logs
        .init();

    ui::start();

    DATABASE.lock().unwrap().save().expect("impossible de sauvegarder la base de données");
}
