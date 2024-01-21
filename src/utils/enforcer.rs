use casbin::{DefaultModel, FileAdapter, Enforcer, CoreApi};
use std::env;
use lazy_static::lazy_static;
use futures::executor::block_on;

lazy_static! {
    pub static ref ENFORCER: Enforcer = {
         initialize_enforcer()
    };
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