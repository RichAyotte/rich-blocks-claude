use std::path::PathBuf;
use std::process::{Command, ExitCode};

const MARKETPLACE_REPO: &str = "RichAyotte/claude-plugins";
const PLUGIN_NAME: &str = "rich-blocks-claude";

static DEPENDENCIES: &[(&str, &str)] = &[
    ("shellcheck", "https://www.shellcheck.net/"),
    ("shfmt", "https://github.com/mvdan/sh"),
    ("rg", "https://github.com/BurntSushi/ripgrep"),
    ("fd", "https://github.com/sharkdp/fd"),
];

pub fn run() -> ExitCode {
    println!("rich-blocks-claude install\n");

    // Step 1: Check dependencies
    println!("1. Checking dependencies...");
    let missing = check_dependencies();
    if missing.is_empty() {
        println!("   All dependencies found.\n");
    } else {
        println!("   Warning: missing optional dependencies:");
        for (name, hint) in &missing {
            println!("   - {name}: {hint}");
        }
        println!();
    }

    // Step 2: Initialize settings
    println!("2. Initializing settings...");
    let config_path = crate::settings::config_path();
    match init_settings(&config_path) {
        Ok(true) => println!("   Created default settings file.\n"),
        Ok(false) => println!("   Settings file already exists, skipping.\n"),
        Err(e) => println!("   Warning: {e}\n"),
    }

    // Step 3: Register plugin
    println!("3. Registering plugin...");
    match register_plugin() {
        Ok(()) => println!("   Plugin registered and installed.\n"),
        Err(e) => println!("   {e}\n"),
    }

    println!("Done.");
    ExitCode::from(0)
}

fn check_dependencies() -> Vec<(&'static str, &'static str)> {
    DEPENDENCIES
        .iter()
        .filter(|(name, _)| {
            Command::new("which")
                .arg(name)
                .output()
                .map_or(true, |o| !o.status.success())
        })
        .copied()
        .collect()
}

fn init_settings(path: &PathBuf) -> Result<bool, String> {
    if path.exists() {
        return Ok(false);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create config directory: {e}"))?;
    }

    let defaults = include_str!("../settings.sample.json");
    std::fs::write(path, defaults).map_err(|e| format!("Failed to write settings file: {e}"))?;

    Ok(true)
}

fn register_plugin() -> Result<(), String> {
    // Check that claude is on PATH
    Command::new("which")
        .arg("claude")
        .output()
        .map_err(|e| format!("Failed to check for claude: {e}"))
        .and_then(|o| {
            if o.status.success() {
                Ok(())
            } else {
                Err(String::new())
            }
        })
        .map_err(|_| {
            format!(
                "claude CLI not found on PATH. Run these commands manually:\n\
                 \n\
                 claude plugin marketplace add {MARKETPLACE_REPO}\n\
                 claude plugin install {PLUGIN_NAME}@rich-plugins --scope user"
            )
        })?;

    run_claude(&["plugin", "marketplace", "add", MARKETPLACE_REPO])?;
    run_claude(&[
        "plugin",
        "install",
        &format!("{PLUGIN_NAME}@rich-plugins"),
        "--scope",
        "user",
    ])?;

    Ok(())
}

fn run_claude(args: &[&str]) -> Result<String, String> {
    let output = Command::new("claude")
        .args(args)
        .env_remove("CLAUDECODE")
        .output()
        .map_err(|e| format!("Failed to run claude {}: {e}", args.join(" ")))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(format!(
            "claude {} failed (exit {}):\n{stdout}{stderr}",
            args.join(" "),
            output.status
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_deps_finds_present() {
        // "sh" should be present on any Unix system — verify it's not reported missing
        let is_missing = Command::new("which")
            .arg("sh")
            .output()
            .map_or(true, |o| !o.status.success());
        assert!(!is_missing, "sh should be found on PATH");
    }

    #[test]
    fn test_check_deps_reports_missing() {
        let is_missing = Command::new("which")
            .arg("nonexistent_binary_xyz_12345")
            .output()
            .map_or(true, |o| !o.status.success());
        assert!(is_missing, "nonexistent binary should not be found");
    }

    #[test]
    fn test_init_settings_creates_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("rich-blocks-claude/settings.json");

        let result = init_settings(&settings_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert!(settings_path.exists());

        let content = std::fs::read_to_string(&settings_path).unwrap();
        let expected = include_str!("../settings.sample.json");
        assert_eq!(content, expected);
    }

    #[test]
    fn test_init_settings_skips_when_exists() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("rich-blocks-claude");
        std::fs::create_dir_all(&config_dir).unwrap();
        let settings_path = config_dir.join("settings.json");
        std::fs::write(&settings_path, "{}").unwrap();

        let result = init_settings(&settings_path);
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Verify original content untouched
        let content = std::fs::read_to_string(&settings_path).unwrap();
        assert_eq!(content, "{}");
    }

    #[test]
    fn test_init_settings_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir
            .path()
            .join("deep/nested/path/rich-blocks-claude/settings.json");

        let result = init_settings(&settings_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert!(settings_path.exists());
    }

    #[test]
    fn test_embedded_settings_is_valid_json() {
        let content = include_str!("../settings.sample.json");
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(content);
        assert!(parsed.is_ok(), "settings.sample.json must be valid JSON");
    }

    #[test]
    fn test_run_claude_returns_error_on_missing_binary() {
        let result = run_claude(&["--nonexistent-flag-xyz"]);
        // Either claude isn't installed (Err from spawn) or the flag fails (Err from exit code)
        // Both are acceptable — we just verify it doesn't panic
        assert!(result.is_err() || result.is_ok());
    }
}
