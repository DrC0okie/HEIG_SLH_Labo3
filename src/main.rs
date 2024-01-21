mod db;
mod ui;
mod utils;
mod models;

use db::Database;
use crate::models::{Review, Role, User};

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

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Error)// Change this to `Debug` to see debug logs
        .init();

    ui::start();
}
