//! CPE 2.3 formatted-string parsing and version-range matching.

use std::cmp::Ordering;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

use crate::version;

/// One vulnerable `cpeMatch` of an NVD CVE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpeRange {
    pub criteria: String,
    pub start_incl: Option<String>,
    pub start_excl: Option<String>,
    pub end_incl: Option<String>,
    pub end_excl: Option<String>,
}

/// The fields of a CPE we use, unescaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpe {
    pub vendor: String,
    pub product: String,
    /// `*` and `-` mean "no concrete version".
    pub version: String,
}

/// Split on `:` that is not escaped as `\:`. Escapes stay in the fields, which
/// is the form NVD wants back in `virtualMatchString` (`g\+\+`).
fn raw_fields(s: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let cur = out.last_mut().expect("never empty");
                cur.push(c);
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            ':' => out.push(String::new()),
            _ => out.last_mut().expect("never empty").push(c),
        }
    }
    out
}

/// Remove the backslash escapes: for comparing, not for sending to NVD.
fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn fields(s: &str) -> Vec<String> {
    raw_fields(s).iter().map(|f| unescape(f)).collect()
}

/// `cpe:2.3:part:vendor:product:version:...`; None when it is not that shape.
pub fn parse(s: &str) -> Option<Cpe> {
    let f = fields(s);
    if f.len() < 6 || f[0] != "cpe" || f[1] != "2.3" {
        return None;
    }
    Some(Cpe {
        vendor: f[3].clone(),
        product: f[4].clone(),
        version: f[5].clone(),
    })
}

/// `vendor:product`, lowercase, with the CPE escapes kept as written: this is
/// the `virtualMatchString` tail and the `nvd_products` key.
pub fn vendor_product(cpe: &str) -> Option<String> {
    let f = raw_fields(cpe);
    if f.len() < 6 || f[0] != "cpe" || f[1] != "2.3" || f[3] == "*" || f[4] == "*" {
        return None;
    }
    Some(format!("{}:{}", f[3].to_lowercase(), f[4].to_lowercase()))
}

/// The concrete version inside a CPE, if it has one.
pub fn concrete_version(cpe: &str) -> Option<String> {
    let c = parse(cpe)?;
    (!matches!(c.version.as_str(), "*" | "-" | "")).then_some(c.version)
}

/// How many comparisons found no order (version unreadable even by the dpkg
/// fallback). Such a bound counts as no match, so this is the number of
/// possible misses; `nvd::refresh` reports it.
static UNCOMPARABLE: AtomicUsize = AtomicUsize::new(0);

pub fn uncomparable_count() -> usize {
    UNCOMPARABLE.load(AtomicOrdering::Relaxed)
}

fn compare_counted(ecosystem: &str, a: &str, b: &str) -> Option<Ordering> {
    let o = version::compare(ecosystem, a, b);
    if o.is_none() {
        UNCOMPARABLE.fetch_add(1, AtomicOrdering::Relaxed);
        eprintln!("nvd: cannot compare versions {a:?} and {b:?} ({ecosystem})");
    }
    o
}

/// Does `range` cover a component described by `component_cpe` at `version`?
/// Vendor and product must be equal (ignoring case). A concrete version in the
/// range's criteria is an exact match; otherwise the start/end bounds apply
/// (no bounds = every version). A bound that cannot be compared is not a match.
pub fn cpe_matches(range: &CpeRange, component_cpe: &str, version: &str, ecosystem: &str) -> bool {
    let (Some(want), Some(have)) = (parse(&range.criteria), parse(component_cpe)) else {
        return false;
    };
    if !want.vendor.eq_ignore_ascii_case(&have.vendor)
        || !want.product.eq_ignore_ascii_case(&have.product)
    {
        return false;
    }
    if !matches!(want.version.as_str(), "*" | "-" | "") {
        return want.version == version
            || compare_counted(ecosystem, &want.version, version) == Some(Ordering::Equal);
    }
    let ok = |bound: &Option<String>, allowed: &[Ordering]| match bound {
        None => true,
        Some(b) => compare_counted(ecosystem, version, b).is_some_and(|o| allowed.contains(&o)),
    };
    ok(&range.start_incl, &[Ordering::Greater, Ordering::Equal])
        && ok(&range.start_excl, &[Ordering::Greater])
        && ok(&range.end_incl, &[Ordering::Less, Ordering::Equal])
        && ok(&range.end_excl, &[Ordering::Less])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaped_colons_stay_inside_a_field() {
        let c = parse(r"cpe:2.3:a:ven\:dor:Prod:1.0:*:*:*:*:*:*:*").unwrap();
        assert_eq!(c.vendor, "ven:dor");
        assert_eq!(c.product, "Prod");
        assert_eq!(c.version, "1.0");
        assert_eq!(
            vendor_product(r"cpe:2.3:a:ven\:dor:Prod:1.0:*:*:*:*:*:*:*").unwrap(),
            r"ven\:dor:prod"
        );
        assert_eq!(parse("pkg:npm/x"), None);
    }

    #[test]
    fn vendor_product_keeps_escapes_for_nvd() {
        let cpe = r"cpe:2.3:a:GNU:g\+\+:12.1:*:*:*:*:*:*:*";
        assert_eq!(vendor_product(cpe).unwrap(), r"gnu:g\+\+");
        // Comparison still works on the unescaped text.
        assert_eq!(parse(cpe).unwrap().product, "g++");
    }

    #[test]
    fn openssh_9_6p1_is_before_9_8() {
        let r = CpeRange {
            criteria: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*".into(),
            start_incl: Some("8.5".into()),
            start_excl: None,
            end_incl: None,
            end_excl: Some("9.8".into()),
        };
        let c = "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*";
        assert!(cpe_matches(&r, c, "9.6p1", "generic"));
        assert!(!cpe_matches(&r, c, "9.8p1", "generic"));
    }

    #[test]
    fn concrete_version_ignores_wildcards() {
        assert_eq!(
            concrete_version("cpe:2.3:a:v:p:1.2:*:*:*:*:*:*:*").as_deref(),
            Some("1.2")
        );
        assert_eq!(concrete_version("cpe:2.3:a:v:p:*:*:*:*:*:*:*:*"), None);
    }
}
