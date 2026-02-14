use crate::HookInput;
use regex::Regex;
use std::path::Path;
use std::process::ExitCode;
use std::sync::LazyLock;

static RE_PYTHON_INLINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"python3?\s+-(c|m)\s").unwrap());
static RE_PYTHON_HEREDOC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"python3?\s*<<").unwrap());
static RE_PYTHON_PIPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\|\s*python3?\s*$").unwrap());
static RE_PYTHON_PIPE_DASH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\|\s*python3?\s+-").unwrap());

pub fn run_bash(input: &HookInput) -> ExitCode {
    let cmd = &input.tool_input.command;
    if cmd.is_empty() {
        return ExitCode::from(0);
    }

    // Block python -c, python3 -c, python -m, python3 -m
    if RE_PYTHON_INLINE.is_match(cmd) {
        block!("Inline Python is NOT allowed. You MUST use TypeScript with bun instead.");
    }
    // Block python << heredoc
    if RE_PYTHON_HEREDOC.is_match(cmd) {
        block!("Python heredoc is NOT allowed. You MUST use TypeScript with bun instead.");
    }
    // Block piped input to python (| python3, | python -)
    if RE_PYTHON_PIPE.is_match(cmd) || RE_PYTHON_PIPE_DASH.is_match(cmd) {
        block!("Piping to Python is NOT allowed. You MUST use TypeScript with bun instead.");
    }

    ExitCode::from(0)
}

pub fn run_write(input: &HookInput) -> ExitCode {
    let path = &input.tool_input.file_path;
    if Path::new(path).extension().is_some_and(|e| e == "py") {
        block!("Python files are NOT allowed. You MUST use TypeScript with bun instead.");
    }
    ExitCode::from(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HookInput, ToolInput};

    fn make_input(command: &str, file_path: &str) -> HookInput {
        HookInput {
            tool_name: String::new(),
            tool_input: ToolInput {
                command: command.to_string(),
                file_path: file_path.to_string(),
                pattern: String::new(),
                path: String::new(),
                glob: String::new(),
                offset: None,
                limit: None,
                context_after: None,
                context_before: None,
                context_both: None,
            },
            tool_response: None,
            cwd: String::new(),
            notification_type: String::new(),
            permission_mode: String::new(),
            message: String::new(),
        }
    }

    // ==================== Write tool tests ====================

    #[test]
    fn write_blocks_py_files() {
        let input = make_input("", "/path/to/script.py");
        assert_eq!(run_write(&input), ExitCode::from(2));
    }

    #[test]
    fn write_blocks_py_in_subdirs() {
        let input = make_input("", "/home/user/project/src/utils/helper.py");
        assert_eq!(run_write(&input), ExitCode::from(2));
    }

    #[test]
    fn write_allows_ts_files() {
        let input = make_input("", "/path/to/script.ts");
        assert_eq!(run_write(&input), ExitCode::from(0));
    }

    #[test]
    fn write_allows_py_in_name_but_not_extension() {
        let input = make_input("", "/path/to/python_helper.ts");
        assert_eq!(run_write(&input), ExitCode::from(0));
    }

    #[test]
    fn write_allows_pyi_stub_files() {
        // .pyi are type stub files, not actual Python code
        let input = make_input("", "/path/to/types.pyi");
        assert_eq!(run_write(&input), ExitCode::from(0));
    }

    // ==================== Bash tool - python -c tests ====================

    #[test]
    fn bash_blocks_python_c_inline() {
        let input = make_input("python -c 'print(1)'", "");
        assert_eq!(run_bash(&input), ExitCode::from(2));
    }

    #[test]
    fn bash_blocks_python3_c_inline() {
        let input = make_input("python3 -c 'print(1)'", "");
        assert_eq!(run_bash(&input), ExitCode::from(2));
    }

    #[test]
    fn bash_blocks_python_c_double_quotes() {
        let input = make_input(r#"python -c "import sys; print(sys.version)""#, "");
        assert_eq!(run_bash(&input), ExitCode::from(2));
    }

    #[test]
    fn bash_blocks_python_m_module() {
        let input = make_input("python -m http.server 8000", "");
        assert_eq!(run_bash(&input), ExitCode::from(2));
    }

    #[test]
    fn bash_blocks_python3_m_module() {
        let input = make_input("python3 -m json.tool file.json", "");
        assert_eq!(run_bash(&input), ExitCode::from(2));
    }

    // ==================== Bash tool - heredoc tests ====================

    #[test]
    fn bash_blocks_python_heredoc() {
        let input = make_input("python << EOF\nprint('hello')\nEOF", "");
        assert_eq!(run_bash(&input), ExitCode::from(2));
    }

    #[test]
    fn bash_blocks_python3_heredoc() {
        let input = make_input("python3 <<EOF\nimport json\nEOF", "");
        assert_eq!(run_bash(&input), ExitCode::from(2));
    }

    #[test]
    fn bash_blocks_python_heredoc_with_dash() {
        let input = make_input("python3 <<-EOF\n\tprint('indented')\nEOF", "");
        assert_eq!(run_bash(&input), ExitCode::from(2));
    }

    // ==================== Bash tool - allowed commands ====================

    #[test]
    fn bash_allows_running_py_script() {
        let input = make_input("python script.py", "");
        assert_eq!(run_bash(&input), ExitCode::from(0));
    }

    #[test]
    fn bash_allows_python3_script_with_args() {
        let input = make_input("python3 /path/to/script.py --verbose", "");
        assert_eq!(run_bash(&input), ExitCode::from(0));
    }

    #[test]
    fn bash_allows_uv_run() {
        let input = make_input("uv run pytest", "");
        assert_eq!(run_bash(&input), ExitCode::from(0));
    }

    #[test]
    fn bash_allows_pip_install() {
        let input = make_input("pip install requests", "");
        assert_eq!(run_bash(&input), ExitCode::from(0));
    }

    #[test]
    fn bash_allows_pytest() {
        let input = make_input("pytest tests/", "");
        assert_eq!(run_bash(&input), ExitCode::from(0));
    }

    #[test]
    fn bash_allows_empty_command() {
        let input = make_input("", "");
        assert_eq!(run_bash(&input), ExitCode::from(0));
    }

    #[test]
    fn bash_allows_non_python_commands() {
        let input = make_input("ls -la && git status", "");
        assert_eq!(run_bash(&input), ExitCode::from(0));
    }

    // ==================== Bash tool - piped input tests ====================

    #[test]
    fn bash_blocks_pipe_to_python() {
        let input = make_input("cat data.json | python3", "");
        assert_eq!(run_bash(&input), ExitCode::from(2));
    }

    #[test]
    fn bash_blocks_pipe_to_python_with_dash() {
        let input = make_input("echo 'print(1)' | python -", "");
        assert_eq!(run_bash(&input), ExitCode::from(2));
    }

    #[test]
    fn bash_blocks_pipe_to_python3_with_dash() {
        let input = make_input("cat script.py | python3 -", "");
        assert_eq!(run_bash(&input), ExitCode::from(2));
    }

    #[test]
    fn bash_blocks_complex_pipe_to_python() {
        let input = make_input("curl -s https://example.com/data.json | python3", "");
        assert_eq!(run_bash(&input), ExitCode::from(2));
    }

    // ==================== Bash tool - chained commands ====================

    #[test]
    fn bash_blocks_python_c_after_semicolon() {
        let input = make_input("cd /tmp; python -c 'print(1)'", "");
        assert_eq!(run_bash(&input), ExitCode::from(2));
    }

    #[test]
    fn bash_blocks_python_c_after_and() {
        let input = make_input("mkdir -p /tmp/test && python3 -c 'print(1)'", "");
        assert_eq!(run_bash(&input), ExitCode::from(2));
    }
}
