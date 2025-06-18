mod config;
mod database;
mod types;

use config::load_config;

fn main() {
    match load_config() {
        Ok(config) => {
            println!("✅ Loaded config !");
            println!("URL DB: {}", config.database_url);
            println!("MFA codes: {:?}", config.mfa.recovery_code_count);
            println!("MFA length: {:?}", config.mfa.recovery_code_length);
            println!("MFA separators: {:?}", config.mfa.recovery_code_use_separators);
        },
        Err(e) => {
            println!("❌ Error: {}", e);
        },
    }
}
