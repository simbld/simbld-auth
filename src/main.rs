mod config;
mod database;
mod types;

use crate::database::Database;
use config::load_config;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    match load_config() {
        Ok(config) => {
            println!("✅ Loaded config !");

            match Database::new(&config.database_url).await {
                Ok(db) => {
                    println!("✅ Database connection established successfully.");

                    if let Err(e) = db.setup_tables().await {
                        println!("❌ Failed to setup tables: {e}");
                    }
                },
                Err(e) => {
                    println!("❌ Failed to connect to the database: {e}");
                },
            }
        },
        Err(e) => {
            println!("❌ Error: {e}");
        },
    }
}
