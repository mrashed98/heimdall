//! One vulnerability, several OSV records: Go's database, GitHub's, PyPI's,
//! RustSec, Debian and Ubuntu each publish their own record for the same CVE
//! (GO-2024-0001 and GHSA-xxxx-xxxx-xxxx, DSA-1234-1 and DEBIAN-CVE-...).
//! Linked as they come, one CVE would open several findings and send
//! several cards. This module decides which records are the same, and which
//! one of them stands for the group.
//!
//! OSV refresh links a component only to each group's canonical advisory,
//! which takes over the others' aliases, the higher severity and, when it
//! has none of its own, their fixed versions. The gate collapses its hits
//! the same way.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde_json::Value;

use crate::model::Severity;
use crate::vuln::severity;

/// What one advisory is also known as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasInfo {
    pub id: String,
    pub aliases: Vec<String>,
    pub cve_id: Option<String>,
}

/// Two records describe the same vulnerability when they carry the same CVE,
/// or when one lists the other among its aliases.
fn same(a: &AliasInfo, b: &AliasInfo) -> bool {
    (a.cve_id.is_some() && a.cve_id == b.cve_id)
        || a.aliases.contains(&b.id)
        || b.aliases.contains(&a.id)
}

/// Group `items` (by index) into sets of records for one vulnerability. The
/// relation is followed transitively: if A is B and B is C, all three are one
/// group even when A and C share nothing. Groups come in the order of their
/// first item, each sorted.
pub fn groups(items: &[AliasInfo]) -> Vec<Vec<usize>> {
    let mut group_of: Vec<Option<usize>> = vec![None; items.len()];
    let mut out: Vec<Vec<usize>> = Vec::new();
    for start in 0..items.len() {
        if group_of[start].is_some() {
            continue;
        }
        // Walk everything reachable from `start`.
        let g = out.len();
        let mut members = vec![start];
        group_of[start] = Some(g);
        let mut next = 0;
        while next < members.len() {
            let current = members[next];
            next += 1;
            for other in 0..items.len() {
                if group_of[other].is_none() && same(&items[current], &items[other]) {
                    group_of[other] = Some(g);
                    members.push(other);
                }
            }
        }
        members.sort();
        out.push(members);
    }
    out
}

/// The index in `group` of the record that stands for it: a GHSA- id, then
/// the lexicographically smallest id. Whether a record carries a CVE is
/// judged for the whole group (it does if any member does), so it does not
/// pick between members: per record it changes as databases add aliases,
/// and the choice would flip. The choice depends only on the ids.
pub fn canonical(items: &[AliasInfo], group: &[usize]) -> usize {
    *group
        .iter()
        .min_by_key(|&&i| (!items[i].id.starts_with("GHSA-"), items[i].id.as_str()))
        .expect("a group is never empty")
}

/// Like `canonical`, but sticky: when members of the group are already
/// linked to any component (`linked`), one of those keeps standing for it
/// (by the same rule among them).
/// A new record joining the group, or a record gaining an alias, then never
/// re-keys the finding (a second card, and oaths left behind).
pub fn sticky_canonical(items: &[AliasInfo], group: &[usize], linked: &HashSet<String>) -> usize {
    let already: Vec<usize> = group
        .iter()
        .copied()
        .filter(|&i| linked.contains(&items[i].id))
        .collect();
    if already.is_empty() {
        canonical(items, group)
    } else {
        canonical(items, &already)
    }
}

/// What OSV refresh knows of one advisory, from its fresh record or its
/// stored row.
pub struct Known {
    pub info: AliasInfo,
    pub severity: Severity,
    /// `{name_key: [fixed versions]}`
    pub fixed: Value,
}

/// What a canonical advisory takes over from the rest of its group.
#[derive(Debug, PartialEq)]
pub struct Merged {
    /// The other records' ids and aliases.
    pub aliases: BTreeSet<String>,
    /// The highest severity in the group.
    pub severity: Severity,
    /// Fixed versions, per component, that only another record knew.
    pub fixed: BTreeMap<String, Vec<String>>,
    /// The group's CVE, when any member carries one.
    pub cve_id: Option<String>,
}

/// One component's OSV hits, collapsed: the advisory ids to link (one per
/// vulnerability). `linked` holds the advisories linked to any component
/// now, which keep standing for their group (`sticky_canonical`). What each
/// canonical takes over is added to `merged`.
pub fn collapse_hits(
    hit_ids: &[String],
    name_key: &str,
    known: &HashMap<String, Known>,
    linked: &HashSet<String>,
    merged: &mut BTreeMap<String, Merged>,
) -> Vec<String> {
    let items: Vec<AliasInfo> = hit_ids
        .iter()
        .map(|id| match known.get(id) {
            Some(k) => k.info.clone(),
            None => AliasInfo {
                id: id.clone(),
                aliases: Vec::new(),
                cve_id: None,
            },
        })
        .collect();
    let fixed_of = |id: &str| -> Vec<String> {
        known
            .get(id)
            .and_then(|k| serde_json::from_value(k.fixed.get(name_key)?.clone()).ok())
            .unwrap_or_default()
    };
    let severity_of = |id: &str| known.get(id).map_or(Severity::Unknown, |k| k.severity);

    let mut link = Vec::new();
    for group in groups(&items) {
        let canon = &items[sticky_canonical(&items, &group, linked)].id;
        link.push(canon.clone());
        if group.len() == 1 {
            continue;
        }
        let m = merged.entry(canon.clone()).or_insert_with(|| Merged {
            aliases: BTreeSet::new(),
            severity: severity_of(canon),
            fixed: BTreeMap::new(),
            cve_id: None,
        });
        for &i in &group {
            let it = &items[i];
            m.severity = severity::merge(m.severity, severity_of(&it.id));
            if m.cve_id.is_none() {
                m.cve_id = it.cve_id.clone();
            }
            if it.id != *canon {
                m.aliases.insert(it.id.clone());
                m.aliases.extend(it.aliases.iter().cloned());
            }
        }
        if fixed_of(canon).is_empty() {
            let theirs = group
                .iter()
                .map(|&i| fixed_of(&items[i].id))
                .find(|f| !f.is_empty());
            if let Some(f) = theirs {
                m.fixed.insert(name_key.to_string(), f);
            }
        }
    }
    link
}

/// Write what each canonical advisory took over from its group.
pub async fn store_merged(
    tx: &mut sqlx::PgConnection,
    merged: &BTreeMap<String, Merged>,
) -> anyhow::Result<()> {
    for (id, m) in merged {
        let aliases: Vec<&String> = m.aliases.iter().collect();
        sqlx::query(
            "update advisories set \
               aliases = array(select distinct a from unnest(aliases || $2::text[]) as a \
                               where a <> $1 order by a), \
               severity = $3, \
               fixed = fixed || $4, \
               cve_id = coalesce(cve_id, $5) \
             where id = $1",
        )
        .bind(id)
        .bind(&aliases)
        .bind(m.severity)
        .bind(serde_json::to_value(&m.fixed)?)
        .bind(&m.cve_id)
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(id: &str, aliases: &[&str], cve: Option<&str>) -> AliasInfo {
        AliasInfo {
            id: id.to_string(),
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            cve_id: cve.map(str::to_string),
        }
    }

    #[test]
    fn same_cve_is_one_group_and_ghsa_stands_for_it() {
        let items = [
            info(
                "GO-2026-0001",
                &["CVE-2026-1", "GHSA-zzzz"],
                Some("CVE-2026-1"),
            ),
            info("GHSA-zzzz", &["CVE-2026-1"], Some("CVE-2026-1")),
            info("GHSA-other", &[], None),
        ];
        let g = groups(&items);
        assert_eq!(g, vec![vec![0, 1], vec![2]]);
        assert_eq!(canonical(&items, &g[0]), 1);
        assert_eq!(canonical(&items, &g[1]), 2);
    }

    #[test]
    fn aliases_are_followed_transitively() {
        // A names B, B names C; A and C share nothing directly.
        let items = [
            info("RUSTSEC-2026-0001", &["GHSA-bbbb"], None),
            info("GHSA-bbbb", &["PYSEC-2026-1"], None),
            info("PYSEC-2026-1", &[], None),
        ];
        assert_eq!(groups(&items), vec![vec![0, 1, 2]]);
        // No CVE anywhere: the GHSA id stands for the group.
        assert_eq!(canonical(&items, &[0, 1, 2]), 1);
    }

    #[test]
    fn ghsa_wins_whether_or_not_it_carries_the_cve_then_smallest_id() {
        let items = [
            info("GHSA-aaaa", &["USN-1"], None),
            info("USN-1", &["UBUNTU-CVE-2026-2"], Some("CVE-2026-2")),
            info("UBUNTU-CVE-2026-2", &[], Some("CVE-2026-2")),
        ];
        assert_eq!(groups(&items), vec![vec![0, 1, 2]]);
        assert_eq!(canonical(&items, &[0, 1, 2]), 0);
        assert_eq!(canonical(&items, &[1, 2]), 2, "UBUNTU-... < USN-...");
    }

    #[test]
    fn an_already_linked_member_keeps_standing_for_the_group() {
        let items = [
            info("PYSEC-1", &["GHSA-bbbb"], Some("CVE-2026-9")),
            info("GHSA-bbbb", &[], Some("CVE-2026-9")),
        ];
        let linked: HashSet<String> = ["PYSEC-1".to_string()].into();
        assert_eq!(sticky_canonical(&items, &[0, 1], &linked), 0);
        assert_eq!(sticky_canonical(&items, &[0, 1], &HashSet::new()), 1);
    }

    #[test]
    fn records_without_a_link_stay_apart() {
        let items = [
            info("DSA-1-1", &[], Some("CVE-2026-3")),
            info("DLA-2-1", &[], Some("CVE-2026-4")),
        ];
        assert_eq!(groups(&items), vec![vec![0], vec![1]]);
    }
}
