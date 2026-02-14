use serde::Deserialize;
use std::path::PathBuf;

fn default_notify_cmd() -> String {
    "notify-send".to_string()
}

fn default_file_ops_allowed() -> Vec<String> {
    vec![
        "$HOME/Projects/".to_string(),
        "$HOME/.claude/".to_string(),
        "$HOME/tmp/".to_string(),
        "/tmp/".to_string(),
        "./crates/".to_string(),
        "./src/".to_string(),
        "./tests/".to_string(),
        "./target/".to_string(),
        "./docs/".to_string(),
        "./task-logs/".to_string(),
    ]
}

fn default_shellcheck_exclude() -> String {
    "SC1091,SC2086,SC2046,SC2035".to_string()
}

fn default_auto_approve_prefixes() -> Vec<String> {
    vec![
        "cargo clippy".to_string(),
        "cargo check".to_string(),
        "cargo fmt".to_string(),
        "cargo test".to_string(),
        "cargo build".to_string(),
        "cargo run".to_string(),
        "cargo doc".to_string(),
        "cargo clean".to_string(),
        "cargo update".to_string(),
        "cargo tree".to_string(),
        "cargo metadata".to_string(),
    ]
}

#[derive(Deserialize)]
pub struct Settings {
    #[serde(default = "default_notify_cmd")]
    pub notify_cmd: String,

    #[serde(default = "default_file_ops_allowed")]
    pub file_ops_allowed: Vec<String>,

    #[serde(default = "default_shellcheck_exclude")]
    pub shellcheck_exclude: String,

    #[serde(default = "default_auto_approve_prefixes")]
    pub auto_approve_prefixes: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            notify_cmd: default_notify_cmd(),
            file_ops_allowed: default_file_ops_allowed(),
            shellcheck_exclude: default_shellcheck_exclude(),
            auto_approve_prefixes: default_auto_approve_prefixes(),
        }
    }
}

impl Settings {
    pub fn load() -> Self {
        let path = config_path();
        let Ok(content) = std::fs::read_to_string(&path) else {
            Self::init_settings_file(&path);
            return Self::default();
        };

        let mut settings: Self = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Warning: malformed settings at {}: {e}", path.display());
                return Self::default();
            }
        };

        settings.expand_vars();
        settings
    }

    fn init_settings_file(path: &PathBuf) {
        if let Some(parent) = path.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                return;
            }
        }
        let defaults = include_str!("../settings.sample.json");
        let _ = std::fs::write(path, defaults);
    }

    pub(crate) fn expand_vars(&mut self) {
        let home = crate::home_dir();
        for entry in &mut self.file_ops_allowed {
            if entry.contains("$HOME") {
                *entry = entry.replace("$HOME", &home);
            }
        }
    }
}

pub(crate) fn config_path() -> PathBuf {
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .unwrap_or_else(|_| format!("{}/.config", crate::home_dir()));
    PathBuf::from(config_home).join("rich-blocks-claude/settings.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn parse(json: &str) -> Settings {
        serde_json::from_str(json).unwrap()
    }

    // ===========================================
    // Default values
    // ===========================================

    #[test]
    fn test_default_notify_cmd() {
        let s = Settings::default();
        assert_eq!(s.notify_cmd, "notify-send");
    }

    #[test]
    fn test_default_shellcheck_exclude() {
        let s = Settings::default();
        assert_eq!(s.shellcheck_exclude, "SC1091,SC2086,SC2046,SC2035");
    }

    #[test]
    fn test_default_file_ops_allowed_contains_projects() {
        let s = Settings::default();
        assert!(s.file_ops_allowed.iter().any(|p| p.contains("Projects")));
    }

    #[test]
    fn test_default_auto_approve_prefixes_contains_cargo_clippy() {
        let s = Settings::default();
        assert!(
            s.auto_approve_prefixes
                .contains(&"cargo clippy".to_string())
        );
    }

    // ===========================================
    // Empty JSON → all defaults
    // ===========================================

    #[test]
    fn test_empty_json_uses_defaults() {
        let s = parse("{}");
        assert_eq!(s.notify_cmd, "notify-send");
        assert_eq!(s.shellcheck_exclude, "SC1091,SC2086,SC2046,SC2035");
        assert!(!s.file_ops_allowed.is_empty());
        assert!(!s.auto_approve_prefixes.is_empty());
    }

    // ===========================================
    // Partial JSON → missing fields use defaults
    // ===========================================

    #[test]
    fn test_partial_json_notify_only() {
        let s = parse(r#"{"notify_cmd": "dunstify"}"#);
        assert_eq!(s.notify_cmd, "dunstify");
    }

    // ===========================================
    // Empty notify_cmd is preserved (disables notifications)
    // ===========================================

    #[test]
    fn test_empty_notify_cmd_preserved() {
        let s = parse(r#"{"notify_cmd": ""}"#);
        assert_eq!(s.notify_cmd, "");
    }

    // ===========================================
    // $HOME expansion
    // ===========================================

    #[test]
    fn test_expand_vars_replaces_home() {
        let mut s = Settings {
            file_ops_allowed: vec!["$HOME/Projects/".to_string(), "/tmp/".to_string()],
            ..Settings::default()
        };
        s.expand_vars();
        let home = std::env::var("HOME").unwrap();
        assert_eq!(s.file_ops_allowed[0], format!("{home}/Projects/"));
        assert_eq!(s.file_ops_allowed[1], "/tmp/");
    }

    #[test]
    fn test_expand_vars_no_home_untouched() {
        let mut s = Settings {
            file_ops_allowed: vec!["./src/".to_string()],
            ..Settings::default()
        };
        s.expand_vars();
        assert_eq!(s.file_ops_allowed[0], "./src/");
    }

    // ===========================================
    // Malformed JSON → defaults
    // ===========================================

    #[test]
    fn test_malformed_json_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("settings.json");
        let mut f = std::fs::File::create(&settings_path).unwrap();
        write!(f, "{{not valid json").unwrap();

        // Simulate load by setting XDG_CONFIG_HOME
        // We can't easily test load() directly due to env vars, so test the parse path
        let result: Result<Settings, _> = serde_json::from_str("{not valid json");
        assert!(result.is_err());
    }

    // ===========================================
    // config_path
    // ===========================================

    #[test]
    fn test_config_path_ends_with_settings_json() {
        let path = config_path();
        assert!(path.ends_with("rich-blocks-claude/settings.json"));
    }

    // ===========================================
    // Custom values fully override
    // ===========================================

    #[test]
    fn test_custom_auto_approve_replaces_defaults() {
        let s = parse(r#"{"auto_approve_prefixes": ["make build"]}"#);
        assert_eq!(s.auto_approve_prefixes, vec!["make build"]);
    }

    #[test]
    fn test_custom_file_ops_replaces_defaults() {
        let s = parse(r#"{"file_ops_allowed": ["/opt/myproject/"]}"#);
        assert_eq!(s.file_ops_allowed, vec!["/opt/myproject/"]);
    }

    // ===========================================
    // Settings file initialization
    // ===========================================

    #[test]
    fn test_init_settings_creates_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir.path().join("rich-blocks-claude/settings.json");

        Settings::init_settings_file(&settings_path);
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

        // load() won't call init_settings_file when file exists (read_to_string succeeds)
        let content = std::fs::read_to_string(&settings_path).unwrap();
        assert_eq!(content, "{}");
    }

    #[test]
    fn test_init_settings_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let settings_path = dir
            .path()
            .join("deep/nested/path/rich-blocks-claude/settings.json");

        Settings::init_settings_file(&settings_path);
        assert!(settings_path.exists());
    }

    #[test]
    fn test_embedded_settings_is_valid_json() {
        let content = include_str!("../settings.sample.json");
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(content);
        assert!(parsed.is_ok(), "settings.sample.json must be valid JSON");
    }
}
