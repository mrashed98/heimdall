//! Direct dependencies declared in go.mod and package.json files.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Context;
use serde::Deserialize;
use walkdir::WalkDir;

const SKIPPED_DIRS: [&str; 3] = ["node_modules", ".git", "vendor"];

/// Name keys (purl without version) of every direct dependency found under
/// `repo_root`. Sorted and deduplicated.
pub fn direct_name_keys(repo_root: &Path) -> anyhow::Result<Vec<String>> {
    let mut keys = BTreeSet::new();
    let walker = WalkDir::new(repo_root).into_iter().filter_entry(|e| {
        // Never filter the root itself, whatever it is called.
        e.depth() == 0
            || !(e.file_type().is_dir() && SKIPPED_DIRS.iter().any(|d| e.file_name() == *d))
    });
    for entry in walker {
        let entry = entry.context("walking repo")?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        match entry.file_name().to_str() {
            Some("go.mod") => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                keys.extend(go_mod_keys(&text));
            }
            Some("package.json") => {
                let bytes =
                    std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
                keys.extend(
                    package_json_keys(&bytes)
                        .with_context(|| format!("parsing {}", path.display()))?,
                );
            }
            _ => {}
        }
    }
    Ok(keys.into_iter().collect())
}

/// Line-based go.mod reader: handles `require x v` and `require ( ... )`
/// blocks, skipping entries marked `// indirect`.
fn go_mod_keys(text: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut in_block = false;
    for raw in text.lines() {
        let line = raw.trim();
        let spec = if in_block {
            if line.starts_with(')') {
                in_block = false;
                continue;
            }
            line
        } else if let Some(rest) = line.strip_prefix("require") {
            let rest = rest.trim();
            if rest.starts_with('(') {
                in_block = true;
                continue;
            }
            // `require` must be a whole word, not e.g. `requirement`.
            if !line["require".len()..].starts_with(char::is_whitespace) {
                continue;
            }
            rest
        } else {
            continue;
        };
        let (code, comment) = match spec.split_once("//") {
            Some((c, cm)) => (c.trim(), cm.trim()),
            None => (spec, ""),
        };
        if comment.starts_with("indirect") {
            continue;
        }
        if let Some(module) = code.split_whitespace().next() {
            keys.push(format!("pkg:golang/{module}"));
        }
    }
    keys
}

#[derive(Deserialize)]
struct PackageJson {
    #[serde(default)]
    dependencies: std::collections::BTreeMap<String, serde::de::IgnoredAny>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: std::collections::BTreeMap<String, serde::de::IgnoredAny>,
}

fn package_json_keys(bytes: &[u8]) -> anyhow::Result<Vec<String>> {
    let pkg: PackageJson = serde_json::from_slice(bytes)?;
    Ok(pkg
        .dependencies
        .keys()
        .chain(pkg.dev_dependencies.keys())
        // '@' of a scope is %40 in purls.
        .map(|name| format!("pkg:npm/{}", name.replace('@', "%40")))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_mod_direct_only() {
        let keys = direct_name_keys(Path::new("tests/fixtures/manifests")).unwrap();
        assert!(keys.contains(&"pkg:golang/github.com/gin-gonic/gin".to_string()));
        assert!(keys.contains(&"pkg:golang/github.com/lib/pq".to_string()));
        assert!(!keys.iter().any(|k| k.contains("golang.org/x/sys")));
    }

    #[test]
    fn pnpm_workspace_package_jsons_skip_node_modules() {
        let keys = direct_name_keys(Path::new("tests/fixtures/manifests/pnpm-ws")).unwrap();
        assert!(keys.contains(&"pkg:npm/%40vue/core".to_string()));
        assert!(keys.contains(&"pkg:npm/react".to_string()));
        assert!(!keys.contains(&"pkg:npm/should-not-appear".to_string()));
        let mut sorted = keys.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(keys, sorted);
    }
}
