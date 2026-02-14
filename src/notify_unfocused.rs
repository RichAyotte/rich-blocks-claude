use crate::HookInput;
use crate::settings::Settings;
use serde_json::Value;
use std::process::{Command, ExitCode};

/// Window info: (pid, address, `workspace_id`)
struct WindowInfo {
    pid: String,
    address: String,
    workspace: i64,
}

pub fn run(input: &HookInput, settings: &Settings) -> ExitCode {
    let notify_cmd = &settings.notify_cmd;
    if notify_cmd.is_empty() {
        return ExitCode::from(0);
    }

    let message = if input.message.is_empty() {
        std::env::var("CLAUDE_NOTIFICATION").unwrap_or_default()
    } else {
        input.message.clone()
    };

    let project = get_project_name(&input.cwd);
    let window_info = find_claude_terminal();

    // Check if focused window is the Claude terminal - skip notification if so
    if let Some(ref info) = window_info
        && let Some(focused) = get_focused_pid()
        && focused == info.pid
    {
        return ExitCode::from(0);
    }

    let (urgency, icon) = get_urgency_icon(&input.notification_type);
    let title = build_title(&project);
    let body = build_body(&message, &input.permission_mode);

    // Send notification
    if let Some(info) = window_info {
        send_notification_with_focus(notify_cmd, &title, &body, urgency, icon, &info);
    } else {
        send_simple_notification(notify_cmd, &title, &body, urgency, icon);
    }

    ExitCode::from(0)
}

/// Extract project name from cwd, skipping hidden directories
fn get_project_name(cwd: &str) -> String {
    let mut project = cwd.rsplit('/').next().unwrap_or("").to_string();
    if project.starts_with('.') {
        project = cwd.rsplit('/').nth(1).unwrap_or("").to_string();
    }
    project
}

/// Map notification type to urgency level and icon
fn get_urgency_icon(notification_type: &str) -> (&'static str, &'static str) {
    match notification_type {
        "permission_prompt" => ("critical", "dialog-warning"),
        "idle_prompt" => ("normal", "dialog-question"),
        "auth_success" => ("low", "emblem-ok-symbolic"),
        _ => ("low", "terminal"),
    }
}

/// Build notification title with optional project name
fn build_title(project: &str) -> String {
    if project.is_empty() {
        "Claude Code".to_string()
    } else {
        format!("Claude Code - {project}")
    }
}

/// Build notification body with optional permission mode
fn build_body(message: &str, permission_mode: &str) -> String {
    let mut body = message.to_string();
    if !permission_mode.is_empty() && permission_mode != "default" {
        body = format!("{body}\n(Mode: {permission_mode})");
    }
    body
}

fn find_claude_terminal() -> Option<WindowInfo> {
    let pgrep = Command::new("pgrep").args(["-x", "claude"]).output().ok()?;
    if !pgrep.status.success() {
        return None;
    }

    let claude_pid = String::from_utf8_lossy(&pgrep.stdout)
        .lines()
        .next()?
        .trim()
        .to_string();

    // Get hyprctl clients once and reuse
    let clients = Command::new("hyprctl")
        .args(["clients", "-j"])
        .output()
        .ok()?;
    let clients_json: serde_json::Value = serde_json::from_slice(&clients.stdout).ok()?;
    let clients_arr = clients_json.as_array()?;

    let mut current_pid = claude_pid;
    loop {
        // Search for current_pid in cached clients
        for client in clients_arr {
            if let Some(pid) = client.get("pid").and_then(Value::as_i64)
                && pid.to_string() == current_pid
            {
                let address = client
                    .get("address")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let workspace = client
                    .get("workspace")
                    .and_then(|w| w.get("id"))
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                return Some(WindowInfo {
                    pid: current_pid,
                    address,
                    workspace,
                });
            }
        }

        let ppid = Command::new("ps")
            .args(["-o", "ppid=", "-p", &current_pid])
            .output()
            .ok()?;
        let new_pid = String::from_utf8_lossy(&ppid.stdout).trim().to_string();
        if new_pid.is_empty() || new_pid == "1" {
            break;
        }
        current_pid = new_pid;
    }

    None
}

fn get_focused_pid() -> Option<String> {
    let output = Command::new("hyprctl")
        .args(["activewindow", "-j"])
        .output()
        .ok()?;
    let json: Value = serde_json::from_slice(&output.stdout).ok()?;
    json.get("pid")
        .and_then(Value::as_i64)
        .map(|p| p.to_string())
}

fn send_notification_with_focus(
    notify_cmd: &str,
    title: &str,
    body: &str,
    urgency: &str,
    icon: &str,
    info: &WindowInfo,
) {
    let script = r#"action=$("$NOTIFY_CMD" -a 'Claude Code' -u "$URGENCY" -i "$ICON" -A "focus=Open" "$TITLE" "$BODY")
if [[ "$action" == "focus" && -n "$WINDOW_ADDR" ]]; then
    hyprctl --batch "dispatch workspace $WINDOW_WS ; dispatch focuswindow address:$WINDOW_ADDR"
fi"#;

    let _ = Command::new("bash")
        .args(["-c", script])
        .env("NOTIFY_CMD", notify_cmd)
        .env("TITLE", title)
        .env("BODY", body)
        .env("URGENCY", urgency)
        .env("ICON", icon)
        .env("WINDOW_ADDR", &info.address)
        .env("WINDOW_WS", info.workspace.to_string())
        .spawn();
}

fn send_simple_notification(notify_cmd: &str, title: &str, body: &str, urgency: &str, icon: &str) {
    let _ = Command::new(notify_cmd)
        .args(["-a", "Claude Code", "-u", urgency, "-i", icon, title, body])
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // Project name extraction tests
    // ===========================================

    #[test]
    fn test_project_name_simple() {
        assert_eq!(get_project_name("/home/user/myproject"), "myproject");
        assert_eq!(get_project_name("/home/user/Projects/app"), "app");
    }

    #[test]
    fn test_project_name_root() {
        assert_eq!(get_project_name("/"), "");
    }

    #[test]
    fn test_project_name_skip_hidden_dir() {
        // When cwd is a hidden dir, use parent directory name
        assert_eq!(get_project_name("/home/user/myproject/.git"), "myproject");
        assert_eq!(get_project_name("/home/user/app/.claude"), "app");
        assert_eq!(get_project_name("/home/user/.config"), "user");
    }

    #[test]
    fn test_project_name_subdir_of_hidden() {
        // Subdirectories of hidden dirs are NOT hidden themselves
        assert_eq!(get_project_name("/home/user/.claude/hooks"), "hooks");
        assert_eq!(get_project_name("/home/user/.config/nvim"), "nvim");
    }

    #[test]
    fn test_project_name_hidden_at_root() {
        // Hidden dir with no parent shows empty or parent
        assert_eq!(get_project_name("/.hidden"), "");
    }

    #[test]
    fn test_project_name_nested_path() {
        assert_eq!(
            get_project_name("/home/user/Projects/company/team/app"),
            "app"
        );
    }

    #[test]
    fn test_project_name_with_dots() {
        // Normal dirs with dots (not starting with .)
        assert_eq!(
            get_project_name("/home/user/my.project.name"),
            "my.project.name"
        );
    }

    // ===========================================
    // Urgency and icon mapping tests
    // ===========================================

    #[test]
    fn test_urgency_permission_prompt() {
        let (urgency, icon) = get_urgency_icon("permission_prompt");
        assert_eq!(urgency, "critical");
        assert_eq!(icon, "dialog-warning");
    }

    #[test]
    fn test_urgency_idle_prompt() {
        let (urgency, icon) = get_urgency_icon("idle_prompt");
        assert_eq!(urgency, "normal");
        assert_eq!(icon, "dialog-question");
    }

    #[test]
    fn test_urgency_auth_success() {
        let (urgency, icon) = get_urgency_icon("auth_success");
        assert_eq!(urgency, "low");
        assert_eq!(icon, "emblem-ok-symbolic");
    }

    #[test]
    fn test_urgency_unknown_type() {
        let (urgency, icon) = get_urgency_icon("unknown");
        assert_eq!(urgency, "low");
        assert_eq!(icon, "terminal");
    }

    #[test]
    fn test_urgency_empty_type() {
        let (urgency, icon) = get_urgency_icon("");
        assert_eq!(urgency, "low");
        assert_eq!(icon, "terminal");
    }

    // ===========================================
    // Title building tests
    // ===========================================

    #[test]
    fn test_title_with_project() {
        assert_eq!(build_title("myapp"), "Claude Code - myapp");
        assert_eq!(build_title("my-project"), "Claude Code - my-project");
    }

    #[test]
    fn test_title_empty_project() {
        assert_eq!(build_title(""), "Claude Code");
    }

    // ===========================================
    // Body building tests
    // ===========================================

    #[test]
    fn test_body_message_only() {
        assert_eq!(build_body("Task completed", ""), "Task completed");
        assert_eq!(
            build_body("Waiting for input", "default"),
            "Waiting for input"
        );
    }

    #[test]
    fn test_body_with_permission_mode() {
        assert_eq!(
            build_body("Need permission", "plan"),
            "Need permission\n(Mode: plan)"
        );
        assert_eq!(
            build_body("Review changes", "auto-accept"),
            "Review changes\n(Mode: auto-accept)"
        );
    }

    #[test]
    fn test_body_empty_message() {
        assert_eq!(build_body("", ""), "");
        assert_eq!(build_body("", "plan"), "\n(Mode: plan)");
    }

    #[test]
    fn test_body_default_mode_ignored() {
        // "default" mode should not be shown
        assert_eq!(build_body("Hello", "default"), "Hello");
    }
}
