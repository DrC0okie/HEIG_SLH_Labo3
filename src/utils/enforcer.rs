use casbin::{DefaultModel, FileAdapter, Enforcer, CoreApi};
use std::env;
use lazy_static::lazy_static;
use futures::executor::block_on;
use log::{info, warn};
use crate::models::{Action, User};


lazy_static! {
    static ref ENFORCER: Enforcer = {
         initialize_enforcer()
    };
}

pub fn access(user: &User, establishment: Option<&str>, action: Action) -> casbin::Result<bool> {
    let action_text = action.to_string();
    let object = establishment.unwrap_or_else(|| "no object");
    match ENFORCER.enforce((&user, establishment.unwrap_or_else(|| ""), action)){
        Ok(access) => {
            if access {
                info!("{} is allowed to {} on {}.", &action_text, user.name, object);
            } else {
                warn!("Access denied to user {} for {} on {}.", user.name, &action_text, object);
            }
            Ok(access)
        },
        Err(e) => Err(e),
    }
}

fn initialize_enforcer() -> Enforcer {
    let current_dir = match env::current_dir(){
        Ok(path) => path,
        Err(e) => panic!("Fatal error getting the current dir: {}", e),
    };
    let model_path = current_dir.join("src/casbin_config/model.conf");
    let policy_path = current_dir.join("src/casbin_config/policy.csv");

    let model = block_on(DefaultModel::from_file(model_path)).unwrap();
    let adapter = FileAdapter::new(policy_path);

    block_on(Enforcer::new(model, adapter)).unwrap()
}

#[cfg(test)]
mod tests {
    use crate::models::{Action, Role, User};
    use crate::utils::enforcer::{access};

    /******************** Admins ***********************/

    #[test]
    fn admin_can_read_own_reviews() {
        let admin = User::new("admin", "admin", Role::Admin);
        assert!(access(&admin, None, Action::ReadOwnReviews).unwrap());
    }

    #[test]
    fn admin_can_read_establishment_reviews() {
        let admin = User::new("admin", "admin", Role::Admin);
        assert!(access(&admin, None, Action::ReadEstablishmentReviews).unwrap());
    }

    #[test]
    fn admin_can_write_reviews() {
        let admin = User::new("admin", "admin", Role::Admin);
        assert!(access(&admin, None, Action::WriteReview).unwrap());
    }

    #[test]
    fn admin_can_delete_reviews() {
        let admin = User::new("admin", "admin", Role::Admin);
        assert!(access(&admin, None, Action::DeleteReview).unwrap());
    }

    /******************** Owners ***********************/

    #[test]
    fn owner_can_read_own_reviews() {
        let owner = User::new("owner", "owner", Role::Owner { owned_establishment: "e-Sel Hash".to_string() });
        assert!(access(&owner, None, Action::ReadOwnReviews).unwrap());
    }

    #[test]
    fn owner_can_read_reviews_on_owned_establishment() {
        let owner = User::new("owner", "owner", Role::Owner { owned_establishment: "e-Sel Hash".to_string() });
        assert!(access(&owner, Some("e-Sel Hash"), Action::ReadEstablishmentReviews).unwrap());
    }

    #[test]
    fn owner_cannot_read_reviews_of_other_establishments() {
        let owner = User::new("owner", "owner", Role::Owner { owned_establishment: "e-Sel Hash".to_string() });
        assert_eq!(access(&owner, Some("not e-Sel Hash"), Action::ReadEstablishmentReviews).unwrap(), false);
    }

    #[test]
    fn owner_can_write_reviews() {
        let owner = User::new("owner", "owner", Role::Owner { owned_establishment: "e-Sel Hash".to_string() });
        assert!(access(&owner, Some("not e-Sel Hash"), Action::WriteReview).unwrap());
    }

    #[test]
    fn owner_cannot_write_reviews_on_owned_establishment() {
        let owner = User::new("owner", "owner", Role::Owner { owned_establishment: "e-Sel Hash".to_string() });
        assert_eq!(access(&owner, Some("e-Sel Hash"), Action::WriteReview).unwrap(), false);
    }

    #[test]
    fn owner_cannot_delete_reviews() {
        let owner = User::new("owner", "owner", Role::Owner { owned_establishment: "e-Sel Hash".to_string() });
        assert_eq!(access(&owner, Some("e-Sel Hash"), Action::DeleteReview).unwrap(), false);
    }

    /******************** Reviewers ***********************/
    #[test]
    fn reviewer_can_read_own_reviews() {
        let reviewer = User::new("reviewer", "reviewer", Role::Reviewer);
        assert!(access(&reviewer, None, Action::ReadOwnReviews).unwrap());
    }

    #[test]
    fn reviewer_can_write_reviews() {
        let reviewer = User::new("reviewer", "reviewer", Role::Reviewer);
        assert!(access(&reviewer, None, Action::WriteReview).unwrap());
    }

    #[test]
    fn reviewer_cannot_read_establishment_reviews() {
        let reviewer = User::new("reviewer", "reviewer", Role::Reviewer);
        assert_eq!(access(&reviewer, Some("e-Sel Hash"), Action::ReadEstablishmentReviews).unwrap(), false);
    }

    #[test]
    fn reviewer_cannot_delete_reviews() {
        let reviewer = User::new("reviewer", "reviewer", Role::Reviewer);
        assert_eq!(access(&reviewer, Some("e-Sel Hash"), Action::DeleteReview).unwrap(), false);
    }
}