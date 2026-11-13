//! Grouping pending findings into cards: one per advisory or release, with
//! the merges that keep one advisory to one card.

use std::collections::{BTreeMap, BTreeSet};

use super::{AlertGroup, AlertItem};
use crate::model::FindingKind;

/// The `(kind, ref_id)` grouping key of a finding.
pub(super) fn group_key(item: Option<&AlertItem>, kind: FindingKind, ref_id: &str) -> String {
    let detail = |name: &str| {
        item.and_then(|i| i.details[name].as_str())
            .unwrap_or_default()
            .to_string()
    };
    let k = kind_name(kind);
    match kind {
        FindingKind::MajorRelease | FindingKind::Eol => {
            format!("{k}|{}|{ref_id}", detail("target"))
        }
        FindingKind::ReleaseNoteCve => {
            format!("{k}|{}|{}|{ref_id}", detail("target"), detail("version"))
        }
        _ => format!("{k}|{ref_id}"),
    }
}

/// The lowercase name stored in the database.
fn kind_name(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::Vuln => "vuln",
        FindingKind::FixAvailable => "fixavailable",
        FindingKind::MajorRelease => "majorrelease",
        FindingKind::OathExpired => "oathexpired",
        FindingKind::Eol => "eol",
        FindingKind::K8sCve => "k8scve",
        FindingKind::ReleaseNoteCve => "releasenotecve",
    }
}

/// Group findings into cards, worst first:
/// - one group per `(kind, ref_id)` (plus target for releases);
/// - a FixAvailable whose service already has a Vuln card for the same
///   advisory is absorbed into that card, which shows the fix advice;
/// - a Vuln card for an advisory whose oath just expired merges into the
///   "Oath expired" card, so the advisory gives one card, not two.
pub(super) fn group(items: Vec<(String, AlertItem)>) -> Vec<AlertGroup> {
    let mut groups: BTreeMap<String, AlertGroup> = BTreeMap::new();
    for (ref_id, item) in items {
        let k = group_key(Some(&item), item.kind, &ref_id);
        groups
            .entry(k)
            .or_insert_with(|| AlertGroup {
                kind: item.kind,
                ref_id,
                items: Vec::new(),
                absorbed: Vec::new(),
                advisory: None,
                release: None,
            })
            .items
            .push(item);
    }

    let advisories: Vec<String> = groups
        .values()
        .filter(|g| g.kind == FindingKind::FixAvailable)
        .map(|g| g.ref_id.clone())
        .collect();
    for adv in advisories {
        let fix_key = format!("fixavailable|{adv}");
        let Some(vuln) = groups.get(&format!("vuln|{adv}")) else {
            continue;
        };
        let covered: BTreeSet<(String, Option<String>)> = vuln
            .items
            .iter()
            .map(|i| (i.realm.clone(), i.service.clone()))
            .collect();
        let fix = groups.get_mut(&fix_key).expect("collected above");
        let (folded, kept): (Vec<AlertItem>, Vec<AlertItem>) = fix
            .items
            .drain(..)
            .partition(|i| covered.contains(&(i.realm.clone(), i.service.clone())));
        fix.items = kept;
        let folded_ids: Vec<i64> = folded.iter().map(|i| i.finding_id).collect();
        if fix.items.is_empty() {
            groups.remove(&fix_key);
        }
        if let Some(vuln) = groups.get_mut(&format!("vuln|{adv}")) {
            vuln.absorbed.extend(folded_ids);
        }
    }

    let expired: Vec<String> = groups
        .values()
        .filter(|g| g.kind == FindingKind::OathExpired)
        .map(|g| g.ref_id.clone())
        .collect();
    for adv in expired {
        if let Some(vuln) = groups.remove(&format!("vuln|{adv}")) {
            let oath = groups
                .get_mut(&format!("oathexpired|{adv}"))
                .expect("collected above");
            oath.items.extend(vuln.items);
            oath.absorbed.extend(vuln.absorbed);
        }
    }

    let mut out: Vec<AlertGroup> = groups.into_values().collect();
    out.sort_by_key(|g| {
        let first = g.items.iter().map(|i| i.finding_id).min().unwrap_or(0);
        (std::cmp::Reverse(g.routing_severity()), first)
    });
    out
}
