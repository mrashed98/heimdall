//! Version ordering: semver, Go and dpkg (Debian/Ubuntu), plus tag parsing
//! and fix recommendation. Pure functions, no I/O.

use semver::Version;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// A container image tag read as a version plus whatever follows the first `-`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub version: Version,
    pub suffix: String,
}

/// Which version to move to: the smallest safe jump and the newest fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixAdvice {
    pub suggest: String,
    pub latest: String,
}

/// Compare two versions in the given ecosystem. `None` when either side
/// cannot be parsed.
pub fn compare(ecosystem: &str, a: &str, b: &str) -> Option<Ordering> {
    if ecosystem.starts_with("Debian:") || ecosystem.starts_with("Ubuntu:") {
        return Some(dpkg_cmp(a, b));
    }
    // Go and npm are semver by definition: lenient semver (strips `v`, pads
    // `X.Y`), and None when it does not parse.
    // Precedence ignores build metadata (`+incompatible`, `+k3s1`), as SemVer requires.
    let semver = || Some(lenient_semver(a)?.cmp_precedence(&lenient_semver(b)?));
    if matches!(ecosystem, "Go" | "npm") {
        return semver();
    }
    // Everything else (generic, PyPI, ...) also meets versions like `9.6p1`,
    // `1.1.1t` or `11.0.20.1`; semver cannot read those, dpkg ordering can.
    // Missing a CVE because a version did not parse is worse than a rough order.
    Some(semver().unwrap_or_else(|| dpkg_cmp(a, b)))
}

/// Split `s` into its numeric `X[.Y[.Z]]` prefix and the rest.
fn split_numeric(s: &str) -> (&str, &str) {
    let end = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    s.split_at(end)
}

/// Parse a semver, tolerating a leading `v` and a missing minor/patch.
fn lenient_semver(s: &str) -> Option<Version> {
    let s = s.trim();
    let s = s.strip_prefix('v').unwrap_or(s);
    if let Ok(v) = Version::parse(s) {
        return Some(v);
    }
    let (core, rest) = split_numeric(s);
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() > 2 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    let mut padded = parts.clone();
    while padded.len() < 3 {
        padded.push("0");
    }
    Version::parse(&format!("{}{}", padded.join("."), rest)).ok()
}

/// Debian Policy 5.6.12 comparison: epoch, then upstream, then revision.
pub fn dpkg_cmp(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = dpkg_split(a);
    let (eb, ub, rb) = dpkg_split(b);
    ea.cmp(&eb)
        .then_with(|| dpkg_part_cmp(ua, ub))
        .then_with(|| dpkg_part_cmp(ra, rb))
}

/// Returns (epoch, upstream, revision). Missing epoch is 0, missing revision is "".
fn dpkg_split(v: &str) -> (u64, &str, &str) {
    let (epoch, rest) = match v.split_once(':') {
        Some((e, r)) => (e.parse().unwrap_or(0), r),
        None => (0, v),
    };
    match rest.rsplit_once('-') {
        Some((u, r)) => (epoch, u, r),
        None => (epoch, rest, ""),
    }
}

/// Sort weight of one non-digit character: `~` first, then the end of the
/// string, then letters, then everything else.
fn dpkg_order(c: Option<u8>) -> i32 {
    match c {
        Some(b'~') => -1,
        None => 0,
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(c) => c as i32 + 256,
    }
}

fn dpkg_part_cmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        // Non-digit run: compare character by character.
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let ca = a.get(i).copied().filter(|c| !c.is_ascii_digit());
            let cb = b.get(j).copied().filter(|c| !c.is_ascii_digit());
            match dpkg_order(ca).cmp(&dpkg_order(cb)) {
                Ordering::Equal => {}
                other => return other,
            }
            if ca.is_some() {
                i += 1;
            }
            if cb.is_some() {
                j += 1;
            }
        }
        // Digit run: compare numerically, ignoring leading zeros.
        let si = i;
        while i < a.len() && a[i].is_ascii_digit() {
            i += 1;
        }
        let sj = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        let na = trim_zeros(&a[si..i]);
        let nb = trim_zeros(&b[sj..j]);
        match na.len().cmp(&nb.len()).then_with(|| na.cmp(nb)) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

fn trim_zeros(d: &[u8]) -> &[u8] {
    let start = d.iter().position(|&c| c != b'0').unwrap_or(d.len());
    &d[start..]
}

/// Numeric components of a version, ignoring `v`, build metadata and
/// pre-release. Missing or non-numeric components count as 0.
fn components(v: &str, len: usize) -> Vec<u64> {
    let v = v.trim();
    let v = v.strip_prefix('v').unwrap_or(v);
    let v = v.split('+').next().unwrap_or("");
    let v = v.split('-').next().unwrap_or("");
    let mut out: Vec<u64> = v
        .split('.')
        .map(|p| {
            let digits: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().unwrap_or(0)
        })
        .collect();
    while out.len() < len {
        out.push(0);
    }
    out
}

/// True when components `0..=major_component` of `new` are greater than
/// `old`'s. For 0.x versions the window is one component wider, so the
/// second number acts as the major.
pub fn is_major(old: &str, new: &str, major_component: u8) -> bool {
    let mut idx = major_component as usize;
    if components(old, 1)[0] == 0 {
        idx += 1;
    }
    let old = components(old, idx + 1);
    let new = components(new, idx + 1);
    new[..=idx] > old[..=idx]
}

/// Read an image tag such as `16.4-alpine` as a version and suffix.
pub fn parse_tag(tag: &str) -> Option<Tag> {
    let s = tag.strip_prefix('v').unwrap_or(tag);
    if !s.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let (core, rest) = split_numeric(s);
    let suffix = match rest {
        "" => "",
        r => r.strip_prefix('-')?,
    };
    let nums: Vec<u64> = core
        .split('.')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    if nums.len() > 3 {
        return None;
    }
    let get = |i: usize| nums.get(i).copied().unwrap_or(0);
    Some(Tag {
        version: Version::new(get(0), get(1), get(2)),
        suffix: suffix.to_string(),
    })
}

/// True for pre-releases: semver ones (`-rc.1`, `-beta.2`) and the common
/// non-semver forms (`1.0.0rc1`, `1.0a1`, `1.0~rc1`, `1.0.dev0`). Build
/// metadata (`+k3s1`), patch letters (`9.6p1`) and vendor suffixes (`-lts`)
/// are not pre-releases.
pub fn is_prerelease(v: &str) -> bool {
    if let Some(ver) = lenient_semver(v) {
        return !ver.pre.is_empty();
    }
    let v = v.trim();
    let v = v.strip_prefix('v').unwrap_or(v);
    let (_, rest) = split_numeric(v);
    let rest = rest.split('+').next().unwrap_or("").to_ascii_lowercase();
    // Any word of the tail that names a pre-release stage.
    rest.split(|c: char| !c.is_ascii_alphabetic())
        .any(|word| PRERELEASE_WORDS.contains(&word))
}

const PRERELEASE_WORDS: [&str; 8] = ["a", "b", "rc", "alpha", "beta", "pre", "preview", "dev"];

/// The major line a version belongs to: its first `major_component + 1`
/// numbers, one more for a 0.x version (`17.0-alpine` -> `17`,
/// `v1.32.0` with component 1 -> `1.32`, `0.4.0` -> `0.4`). Releases of one
/// line share one MajorRelease finding.
pub fn major_line(v: &str, major_component: u8) -> String {
    let mut len = major_component as usize + 1;
    if components(v, 1)[0] == 0 {
        len += 1;
    }
    let parts: Vec<String> = components(v, len)[..len]
        .iter()
        .map(u64::to_string)
        .collect();
    parts.join(".")
}

/// Pick the smallest fixed version above `current` that keeps its major,
/// falling back to the smallest fixed version above it. `latest` is the
/// highest fixed version. Unparseable or not-newer versions are ignored.
///
/// A linear scan, never a sort: `compare` mixes semver and dpkg ordering, so
/// it is not always a total order, and the standard sort may panic on that.
pub fn recommend_fix(ecosystem: &str, current: &str, fixed: &[&str]) -> Option<FixAdvice> {
    let is = |a: &str, b: &str, want: Ordering| compare(ecosystem, a, b) == Some(want);
    let mut latest: Option<&str> = None;
    let mut smallest: Option<&str> = None;
    let mut smallest_same_major: Option<&str> = None;
    for &f in fixed {
        if !is(f, current, Ordering::Greater) {
            continue;
        }
        if latest.is_none_or(|l| is(f, l, Ordering::Greater)) {
            latest = Some(f);
        }
        if smallest.is_none_or(|s| is(f, s, Ordering::Less)) {
            smallest = Some(f);
        }
        if !is_major(current, f, 0) && smallest_same_major.is_none_or(|s| is(f, s, Ordering::Less))
        {
            smallest_same_major = Some(f);
        }
    }
    Some(FixAdvice {
        suggest: smallest_same_major.or(smallest)?.to_string(),
        latest: latest?.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_epoch_tilde_and_revision() {
        use std::cmp::Ordering::*;
        assert_eq!(dpkg_cmp("1:0.9", "2.0"), Greater);
        assert_eq!(dpkg_cmp("1.0~rc1", "1.0"), Less);
        assert_eq!(dpkg_cmp("1.0-1", "1.0-2"), Less);
        assert_eq!(dpkg_cmp("3.0.11-1~deb12u2", "3.0.11-1~deb12u3"), Less);
        assert_eq!(dpkg_cmp("2.39-0ubuntu8", "2.39-0ubuntu8.1"), Less);
    }

    #[test]
    fn dpkg_empty_revision_and_letters_vs_symbols() {
        use std::cmp::Ordering::*;
        // Missing revision equals revision "0"-less empty; "1.0" < "1.0-1".
        assert_eq!(dpkg_cmp("1.0", "1.0-1"), Less);
        assert_eq!(dpkg_cmp("1.0", "1.0"), Equal);
        // Letters sort before non-letters; "~" before the end of string.
        assert_eq!(dpkg_cmp("1.0a", "1.0+"), Less);
        assert_eq!(dpkg_cmp("1.0~", "1.0"), Less);
        assert_eq!(dpkg_cmp("1.0~~", "1.0~"), Less);
        assert_eq!(dpkg_cmp("1.0", "1.0a"), Less);
        // Leading zeros are ignored in digit runs.
        assert_eq!(dpkg_cmp("1.001", "1.1"), Equal);
        assert_eq!(dpkg_cmp("1.10", "1.9"), Greater);
    }

    #[test]
    fn go_versions_with_v_prefix() {
        assert_eq!(
            compare("Go", "v1.9.0", "v1.10.0"),
            Some(std::cmp::Ordering::Less)
        );
    }

    #[test]
    fn go_incompatible_equal_precedence() {
        assert_eq!(
            compare("Go", "v2.0.0+incompatible", "v2.0.0"),
            Some(std::cmp::Ordering::Equal)
        );
    }

    #[test]
    fn build_metadata_ignored_in_order() {
        assert_eq!(
            compare("npm", "1.0.0+a", "1.0.0+b"),
            Some(std::cmp::Ordering::Equal)
        );
        assert_eq!(
            recommend_fix("Go", "v2.0.0", &["v2.0.0+incompatible"]),
            None
        );
    }

    #[test]
    fn compare_falls_back_to_lenient_and_none() {
        assert_eq!(
            compare("PyPI", "1.2", "1.2.1"),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(compare("Go", "banana", "1.0.0"), None);
    }

    #[test]
    fn major_rules() {
        assert!(is_major("17.2", "18.0", 0));
        assert!(!is_major("17.2", "17.3", 0));
        assert!(is_major("1.31.2", "1.32.0", 1)); // Kubernetes: minor is major
        assert!(!is_major("1.31.2", "1.31.3", 1));
        assert!(is_major("v1.31.2+k3s1", "v1.32.0+k3s1", 1));
        assert!(is_major("0.3.9", "0.4.0", 0)); // 0.x: second number is major
        assert!(!is_major("0.3.9", "0.3.10", 0));
        assert!(is_major("0.9.1", "1.0.0", 0));
    }

    #[test]
    fn smallest_fix_in_same_major() {
        let fixed = ["2.4.1", "2.5.3", "3.0.0"];
        assert_eq!(
            recommend_fix("npm", "2.4.0", &fixed),
            Some(FixAdvice {
                suggest: "2.4.1".into(),
                latest: "3.0.0".into()
            })
        );
        assert_eq!(
            recommend_fix("npm", "2.6.0", &["3.0.0"]),
            Some(FixAdvice {
                suggest: "3.0.0".into(),
                latest: "3.0.0".into()
            })
        );
        assert_eq!(recommend_fix("npm", "2.6.0", &["2.5.0", "junk"]), None);
    }

    #[test]
    fn recommend_fix_survives_non_total_order() {
        // Semver says rc1 < 1.0.0; "1.0.0-a.01" is not semver (leading zero),
        // so it is ordered by dpkg against both: above 1.0.0, below rc1. A cycle.
        let mixed = ["1.0.0-rc1", "1.0.0", "1.0.0-a.01"];
        let advice = recommend_fix("PyPI", "0.9.0", &mixed).unwrap();
        assert!(mixed.contains(&advice.suggest.as_str()));
        assert!(mixed.contains(&advice.latest.as_str()));

        // A longer list makes the standard sort check its comparator.
        let many: Vec<String> = (0..40)
            .flat_map(|i| {
                [
                    format!("1.{i}.0-rc1"),
                    format!("1.{i}.0"),
                    format!("1.{i}.0-a.01"),
                ]
            })
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(recommend_fix("PyPI", "0.9.0", &many).is_some());
    }

    #[test]
    fn tags_keep_suffix_and_skip_non_semver() {
        let t = parse_tag("16.4-alpine").unwrap();
        assert_eq!(
            (t.version.to_string().as_str(), t.suffix.as_str()),
            ("16.4.0", "alpine")
        );
        assert_eq!(parse_tag("16.4").unwrap().suffix, "");
        assert_eq!(parse_tag("16").unwrap().version.to_string(), "16.0.0");
        assert!(parse_tag("latest").is_none());
        assert!(parse_tag("sha-abc123").is_none());
    }

    #[test]
    fn prereleases_detected() {
        assert!(is_prerelease("v1.32.0-rc.1"));
        assert!(is_prerelease("2.0.0-beta.2"));
        assert!(!is_prerelease("v1.32.0+k3s1"));
        assert!(is_prerelease("1.2.3.4-rc1"));
        assert!(!is_prerelease("1.2.3.4"));
    }

    #[test]
    fn non_semver_prereleases_detected() {
        assert!(is_prerelease("1.0.0rc1"));
        assert!(is_prerelease("1.0a1"));
        assert!(is_prerelease("1.0b2"));
        assert!(is_prerelease("1.0~rc1"));
        assert!(is_prerelease("2.0-beta"));
        assert!(is_prerelease("1.0.dev0"));
        assert!(is_prerelease("1.2.3.dev4"));
        assert!(is_prerelease("3.1.0.post1-dev"));
        // Patch letters and vendor suffixes are not pre-releases.
        assert!(!is_prerelease("9.6p1"));
        assert!(!is_prerelease("1.1.1t"));
        assert!(!is_prerelease("24.8.4.13-lts"));
        assert!(!is_prerelease("1.2.3.4"));
    }

    #[test]
    fn major_line_names_the_major() {
        assert_eq!(major_line("17.0-alpine", 0), "17");
        assert_eq!(major_line("v1.32.0+k3s1", 1), "1.32");
        assert_eq!(major_line("0.4.0", 0), "0.4");
        assert_eq!(major_line("1.0.0", 0), "1");
    }

    #[test]
    fn generic_versions_semver_cannot_read_still_order() {
        use std::cmp::Ordering::*;
        assert_eq!(compare("generic", "9.6p1", "9.8"), Some(Less));
        assert_eq!(compare("generic", "1.1.1t", "1.1.1s"), Some(Greater));
        assert_eq!(compare("generic", "11.0.20.1", "11.0.21"), Some(Less));
        // Semver-shaped versions still use semver.
        assert_eq!(compare("generic", "1.10.0", "1.9.0"), Some(Greater));
    }
}
