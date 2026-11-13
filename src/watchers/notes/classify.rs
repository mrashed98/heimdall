//! Classifying release notes by pattern matching. Pure: no I/O.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotesClass {
    CveAffecting,
    Security,
    Bugfix,
    Plain,
    None,
}

impl NotesClass {
    /// The `releases.notes_class` value.
    pub fn as_str(self) -> &'static str {
        match self {
            NotesClass::CveAffecting => "cve_affecting",
            NotesClass::Security => "security",
            NotesClass::Bugfix => "bugfix",
            NotesClass::Plain => "plain",
            NotesClass::None => "none",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    pub class: NotesClass,
    pub mentioned_ids: Vec<String>,
    pub fix_lines: Vec<String>,
    pub breaking_lines: Vec<String>,
}

// ---- classification -------------------------------------------------------

/// `CVE-2026-1234` and `GHSA-xxxx-xxxx-xxxx` (GitHub's alphabet leaves out
/// vowels and look-alikes), either case.
static ID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}").expect("id regex")
});
static SECURITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(security|vulnerabilit(?:y|ies)|exploit\w*)\b").expect("security regex")
});

const MAX_LINES: usize = 5;

/// Which kind of heading the lines below belong to.
#[derive(Clone, Copy, PartialEq)]
enum Section {
    Fixes,
    Breaking,
    Other,
}

/// Classify release notes. `affecting_ids` holds the ids that affect us,
/// uppercased and including advisory aliases. An empty body has no notes.
pub fn classify(body: &str, affecting_ids: &HashSet<String>) -> Classified {
    let mut mentioned_ids: Vec<String> = Vec::new();
    for m in ID_RE.find_iter(body) {
        let id = m.as_str().to_uppercase();
        if !mentioned_ids.contains(&id) {
            mentioned_ids.push(id);
        }
    }

    let mut fix_lines = Vec::new();
    let mut breaking_lines = Vec::new();
    let mut section = Section::Other;
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if is_heading(line) {
            let title = line.trim_matches(['#', '*', ':', ' ']).to_lowercase();
            section = if title.contains("breaking") {
                Section::Breaking
            } else if matches!(
                title.as_str(),
                "fixes" | "fixed" | "bug fixes" | "bug fix" | "bugfixes" | "bugfix"
            ) {
                Section::Fixes
            } else {
                Section::Other
            };
            continue;
        }
        let text = strip_bullet(line);
        let lower = text.to_lowercase();
        if section == Section::Fixes || lower.starts_with("fix") || lower.starts_with("bug") {
            fix_lines.push(text.to_string());
        }
        if section == Section::Breaking || lower.contains("breaking") {
            breaking_lines.push(text.to_string());
        }
    }
    let had_fix_lines = !fix_lines.is_empty();
    fix_lines.truncate(MAX_LINES);
    breaking_lines.truncate(MAX_LINES);

    let class = if body.trim().is_empty() {
        NotesClass::None
    } else if mentioned_ids.iter().any(|id| affecting_ids.contains(id)) {
        NotesClass::CveAffecting
    } else if !mentioned_ids.is_empty() || SECURITY_RE.is_match(body) {
        NotesClass::Security
    } else if had_fix_lines {
        NotesClass::Bugfix
    } else {
        NotesClass::Plain
    };
    Classified {
        class,
        mentioned_ids,
        fix_lines,
        breaking_lines,
    }
}

/// A markdown heading (`## Bug Fixes`) or a bold-only line (`**Bug Fixes**`).
fn is_heading(line: &str) -> bool {
    line.starts_with('#') || (line.len() > 4 && line.starts_with("**") && line.ends_with("**"))
}

/// `- text` and `* text` lose their bullet.
fn strip_bullet(line: &str) -> &str {
    for bullet in ["- ", "* "] {
        if let Some(rest) = line.strip_prefix(bullet) {
            return rest.trim();
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(list: &[&str]) -> HashSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// The `body` of a GitHub release fixture.
    fn body_of(name: &str) -> String {
        let text = std::fs::read_to_string(format!("tests/fixtures/notes/{name}")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["body"].as_str().unwrap().to_string()
    }

    #[test]
    fn classify_cve_affecting() {
        let c = classify("Fixes CVE-2026-1234", &ids(&["CVE-2026-1234"]));
        assert_eq!(c.class, NotesClass::CveAffecting);
        assert_eq!(c.mentioned_ids, vec!["CVE-2026-1234"]);
    }

    #[test]
    fn classify_ghsa_lowercase_normalised() {
        let c = classify(
            "see ghsa-c2c2-f3f3-g4g4 and cve-2026-1234, again GHSA-C2C2-F3F3-G4G4",
            &ids(&["GHSA-C2C2-F3F3-G4G4"]),
        );
        assert_eq!(c.class, NotesClass::CveAffecting);
        // Uppercased, deduplicated, in order of appearance.
        assert_eq!(
            c.mentioned_ids,
            vec!["GHSA-C2C2-F3F3-G4G4", "CVE-2026-1234"]
        );
    }

    #[test]
    fn classify_security_not_affecting() {
        let c = classify("Fixes CVE-2026-9999", &ids(&["CVE-2026-1234"]));
        assert_eq!(c.class, NotesClass::Security);
        assert_eq!(c.mentioned_ids, vec!["CVE-2026-9999"]);
        let words = classify("Hardened the parser against exploit attempts", &ids(&[]));
        assert_eq!(words.class, NotesClass::Security);
    }

    #[test]
    fn classify_bugfix_lines_capped_at_5() {
        let body: String = (1..=8).map(|i| format!("- fix: thing {i}\n")).collect();
        let c = classify(&body, &ids(&[]));
        assert_eq!(c.class, NotesClass::Bugfix);
        assert_eq!(c.fix_lines.len(), 5);
        assert_eq!(c.fix_lines[0], "fix: thing 1");

        let c = classify(&body_of("gh_release_bugfix.json"), &ids(&[]));
        assert_eq!(c.class, NotesClass::Bugfix);
        assert_eq!(
            c.fix_lines,
            vec!["Correct off-by-one in pager", "Handle empty config file"]
        );
    }

    #[test]
    fn breaking_lines_extracted() {
        let c = classify(&body_of("gh_release_breaking.json"), &ids(&[]));
        assert_eq!(
            c.breaking_lines,
            vec![
                "The `--legacy` flag is removed",
                "Config key `port` is now `listen.port`",
                "BREAKING: minimum Go version is 1.22",
            ]
        );
        assert_eq!(c.class, NotesClass::Plain);
    }

    #[test]
    fn classify_plain_and_empty() {
        assert_eq!(
            classify("- New plugin API", &ids(&[])).class,
            NotesClass::Plain
        );
        assert_eq!(classify("  \n", &ids(&[])).class, NotesClass::None);
    }
}
