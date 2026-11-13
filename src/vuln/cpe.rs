//! CPE 2.3 formatted-string parsing and version-range matching.

use std::cmp::Ordering;

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

/// Split on `:` that is not escaped as `\:`, and drop the backslashes.
fn fields(s: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    out.last_mut().expect("never empty").push(next);
                }
            }
            ':' => out.push(String::new()),
            _ => out.last_mut().expect("never empty").push(c),
        }
    }
    out
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

/// `vendor:product` (lowercase, `:` escaped again) as used for backfill and
/// the `nvd_products` table.
pub fn vendor_product(cpe: &str) -> Option<String> {
    let c = parse(cpe)?;
    if c.vendor == "*" || c.product == "*" {
        return None;
    }
    let esc = |s: &str| s.to_lowercase().replace(':', "\\:");
    Some(format!("{}:{}", esc(&c.vendor), esc(&c.product)))
}

/// The concrete version inside a CPE, if it has one.
pub fn concrete_version(cpe: &str) -> Option<String> {
    let c = parse(cpe)?;
    (!matches!(c.version.as_str(), "*" | "-" | "")).then_some(c.version)
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
            || version::compare(ecosystem, &want.version, version) == Some(Ordering::Equal);
    }
    let ok = |bound: &Option<String>, allowed: &[Ordering]| match bound {
        None => true,
        Some(b) => version::compare(ecosystem, version, b).is_some_and(|o| allowed.contains(&o)),
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
    fn concrete_version_ignores_wildcards() {
        assert_eq!(
            concrete_version("cpe:2.3:a:v:p:1.2:*:*:*:*:*:*:*").as_deref(),
            Some("1.2")
        );
        assert_eq!(concrete_version("cpe:2.3:a:v:p:*:*:*:*:*:*:*:*"), None);
    }
}
