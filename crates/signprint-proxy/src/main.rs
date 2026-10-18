// The server itself is unix-only (pingora), so on other platforms most of
// the request handling looks unused to the compiler.
#![cfg_attr(not(unix), allow(dead_code))]

mod app;
mod config;
#[cfg(unix)]
mod server;

use std::path::PathBuf;
use std::process::ExitCode;

use signprint_wire::b64;

const USAGE: &str = "\
usage:
  signprint-proxy run <config.toml>   start the proxy
  signprint-proxy keygen [host_id]    print a new keyring and secrets
  signprint-proxy check <config.toml> validate config and keys, then exit";

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("OS random number generator unavailable");
    b
}

fn keygen(host_id: u16) {
    let keyring = serde_json::json!({
        "host_id": host_id,
        "current": 1,
        "keys": [{ "kid": 1, "secret": b64::encode_url(&random32()) }],
    });
    println!("# keyring.json (keep private)");
    println!("{}", serde_json::to_string_pretty(&keyring).unwrap());
    println!();
    println!("# environment");
    println!("SIGNPRINT_UPSTREAM_SECRET={}", b64::encode_url(&random32()));
    println!("SIGNPRINT_LOG_ROOT={}", b64::encode_url(&random32()));
}

fn load(path: &str) -> Result<(config::Config, app::App), config::ConfigError> {
    let cfg = config::Config::load(&PathBuf::from(path))?;
    let ring = config::load_keyring(&cfg.keys.keyring)?;
    let upstream = config::secret_from_env(&cfg.keys.upstream_secret_env)?;
    let log_root = config::secret_from_env(&cfg.keys.log_root_env)?;
    let rules = config::load_rules(&cfg.rules)?;
    let canvas = if cfg.canvas.enabled {
        let c = signprint_core::canvas::Canvas::open(
            signprint_core::canvas::CanvasConfig {
                min_devices: cfg.canvas.min_devices,
                kb_path: cfg.canvas.kb_path.clone(),
                ..Default::default()
            },
            || u32::from_be_bytes(random32()[..4].try_into().unwrap()),
        )
        .map_err(|e| config::ConfigError::Invalid(e.to_string()))?;
        Some(c)
    } else {
        None
    };
    let calibrate_token = match &cfg.canvas.calibrate_token_env {
        Some(var) => Some(
            std::env::var(var)
                .map_err(|_| config::ConfigError::Invalid(format!("env var {var} not set")))?,
        ),
        None => None,
    };
    let app = app::App::new(
        &cfg,
        ring,
        rules,
        canvas,
        calibrate_token,
        upstream,
        log_root,
    );
    Ok((cfg, app))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["keygen"] => keygen(1),
        ["keygen", id] => match id.parse() {
            Ok(id) => keygen(id),
            Err(_) => {
                eprintln!("host_id must be a number from 0 to 65535");
                return ExitCode::FAILURE;
            }
        },
        ["check", path] => match load(path) {
            Ok(_) => println!("ok"),
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        },
        ["run", path] => {
            let (cfg, app) = match load(path) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            };
            #[cfg(unix)]
            server::run(cfg, app);
            #[cfg(not(unix))]
            {
                let _ = (cfg, app);
                eprintln!(
                    "the proxy server needs Linux or macOS (pingora doesn't support Windows)"
                );
                return ExitCode::FAILURE;
            }
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
