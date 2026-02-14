use serde::Deserialize;
use std::env;
use std::io::{self, Read};
use std::process::ExitCode;

#[must_use]
pub fn home_dir() -> String {
    std::env::var("HOME").unwrap_or_else(|_| String::from("/home/unknown"))
}

macro_rules! block {
    ($($arg:tt)*) => {{
        eprintln!("BLOCK: {}", format!($($arg)*));
        return ExitCode::from(2);
    }};
}

mod install;
mod no_python;
mod notify_unfocused;
mod sensitive_files;
mod settings;
mod validate_bash;

#[derive(Deserialize, Clone)]
pub struct HookInput {
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: ToolInput,
    #[serde(default)]
    pub tool_response: Option<ToolResponse>,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub notification_type: String,
    #[serde(default)]
    pub permission_mode: String,
    #[serde(default)]
    pub message: String,
}

#[derive(Deserialize, Clone, Default)]
pub struct ToolResponse {
    #[serde(default, rename = "type")]
    pub response_type: String,
    #[serde(default)]
    pub file: Option<FileResponse>,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Deserialize, Clone, Default)]
pub struct FileResponse {
    #[serde(default, rename = "filePath")]
    pub file_path: String,
    #[serde(default)]
    pub content: String,
}

#[derive(Deserialize, Clone, Default)]
pub struct ToolInput {
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub pattern: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub glob: String,
    // Read tool parameters
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub limit: Option<u64>,
    // Grep context parameters
    #[serde(default, rename = "-A")]
    pub context_after: Option<u32>,
    #[serde(default, rename = "-B")]
    pub context_before: Option<u32>,
    #[serde(default, rename = "-C")]
    pub context_both: Option<u32>,
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: rich-blocks-claude <command>");
        eprintln!("Commands:");
        eprintln!("  install  Install plugin via Claude Code CLI");
        eprintln!("  bash|write|read|edit|grep|post-sensitive|notify  Hook matchers");
        return ExitCode::from(1);
    }

    // Handle install subcommand before reading stdin (it runs from a terminal, not hooks)
    if args[1] == "install" {
        return install::run();
    }

    // Read stdin once
    let mut input_str = String::new();
    if io::stdin().read_to_string(&mut input_str).is_err() {
        return ExitCode::from(0);
    }

    let input: HookInput = match serde_json::from_str(&input_str) {
        Ok(h) => h,
        Err(_) => return ExitCode::from(0),
    };

    let settings = settings::Settings::load();

    match args[1].as_str() {
        // Bash matcher - run all bash-related hooks (PreToolUse)
        "bash" => {
            let code = validate_bash::run(&input, &settings);
            if code != ExitCode::from(0) {
                return code;
            }

            let code = sensitive_files::run_bash(&input);
            if code != ExitCode::from(0) {
                return code;
            }

            let code = no_python::run_bash(&input);
            if code != ExitCode::from(0) {
                return code;
            }

            ExitCode::from(0)
        }

        // Write matcher - check for sensitive files and python files (PreToolUse)
        "write" => {
            let code = sensitive_files::run_write(&input);
            if code != ExitCode::from(0) {
                return code;
            }
            no_python::run_write(&input)
        }

        // Read matcher - block sensitive file reads (PreToolUse)
        "read" => sensitive_files::run_read(&input),

        // Edit matcher - block sensitive file edits (PreToolUse)
        "edit" => sensitive_files::run_edit(&input),

        // Grep matcher - block grep in sensitive directories (PreToolUse)
        "grep" => sensitive_files::run_grep(&input),

        // PostToolUse safety net - warn if sensitive file was accessed
        "post-sensitive" => sensitive_files::run_post(&input, &settings),

        // Notification hook
        "notify" => notify_unfocused::run(&input, &settings),

        cmd => {
            eprintln!("Unknown matcher: {cmd}");
            ExitCode::from(1)
        }
    }
}
