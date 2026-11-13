//! Human-facing terminal output: colour decision, banner, tables.
//! Everything here builds a `String`; only `main.rs` prints.

pub mod banner;
pub mod render;

/// Whether (and how) to colour output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    pub color: bool,
    /// 24-bit colour is available (`COLORTERM=truecolor|24bit`).
    pub truecolor: bool,
}

impl Style {
    /// No colour at all.
    pub fn plain() -> Style {
        Style {
            color: false,
            truecolor: false,
        }
    }

    /// Decide from the real process: the `--no-color` flag, stdout and env.
    pub fn detect(no_color_flag: bool) -> Style {
        use std::io::IsTerminal;
        let is_tty = std::io::stdout().is_terminal();
        Style::detect_with(no_color_flag, is_tty, |k| std::env::var(k).ok())
    }

    /// `detect` with the environment injected, so tests need not touch it.
    pub fn detect_with(
        no_color_flag: bool,
        is_tty: bool,
        env: impl Fn(&str) -> Option<String>,
    ) -> Style {
        let set = |k: &str| env(k).is_some();
        let off = no_color_flag || set("NO_COLOR") || env("TERM").as_deref() == Some("dumb");
        // CI logs have no terminal but GitHub Actions renders ANSI colour.
        let forced = set("CI") || set("GITHUB_ACTIONS") || set("CLICOLOR_FORCE");
        let color = !off && (is_tty || forced);
        let truecolor = color && matches!(env("COLORTERM").as_deref(), Some("truecolor" | "24bit"));
        Style { color, truecolor }
    }
}

/// Wrap `text` in an SGR code (e.g. "1;31") when colour is on.
pub fn paint(style: &Style, code: &str, text: &str) -> String {
    if style.color {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn bold(style: &Style, text: &str) -> String {
    paint(style, "1", text)
}

pub fn dim(style: &Style, text: &str) -> String {
    paint(style, "2", text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn no_color_env_disables_color() {
        let s = Style::detect_with(false, true, env_of(&[("NO_COLOR", "")]));
        assert!(!s.color);
    }

    #[test]
    fn no_color_flag_and_dumb_term_disable_color() {
        assert!(!Style::detect_with(true, true, env_of(&[])).color);
        assert!(!Style::detect_with(false, true, env_of(&[("TERM", "dumb")])).color);
    }

    #[test]
    fn tty_enables_color_and_pipe_does_not() {
        assert!(Style::detect_with(false, true, env_of(&[])).color);
        assert!(!Style::detect_with(false, false, env_of(&[])).color);
    }

    #[test]
    fn github_actions_keeps_color_without_tty() {
        let s = Style::detect_with(false, false, env_of(&[("GITHUB_ACTIONS", "true")]));
        assert!(s.color);
        // ...but --no-color still wins.
        let s = Style::detect_with(true, false, env_of(&[("GITHUB_ACTIONS", "true")]));
        assert!(!s.color);
    }

    #[test]
    fn truecolor_needs_colorterm() {
        let s = Style::detect_with(false, true, env_of(&[("COLORTERM", "truecolor")]));
        assert!(s.truecolor);
        assert!(!Style::detect_with(false, true, env_of(&[])).truecolor);
    }
}
