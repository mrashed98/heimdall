//! Matcher: joins a realm's inventory with linked advisories and oaths into
//! findings. A finding has a stable text key, so it is opened once, kept up to
//! date while it applies, and resolved when it no longer does.

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{FromRow, PgConnection, PgPool};

use crate::inventory::store::{effective_components, EffectiveComponent};
use crate::model::{FindingKind, MatchSource, Severity};
use crate::oath::{self, Oath};
use crate::purl::osv_package;
use crate::version::recommend_fix;

/// A Vuln or FixAvailable resolved less recently than this, and wanted again,
/// is an inventory flap (a new image not scanned yet, a scale to zero, a Job
/// pod gone): it re-opens without a second announcement.
const FLAP_WINDOW_DAYS: i64 = 30;

/// What one matcher run changed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MatchReport {
    /// Findings that are new occurrences: inserted, or re-opened after being
    /// resolved. Gjallarhorn alerts on these.
    pub opened: Vec<i64>,
    pub resolved: usize,
}

/// The finding key: a kind prefix and `parts`, joined with `|`. Every finding
/// key is built here so the formats cannot drift apart.
pub fn key(kind: FindingKind, parts: &[&str]) -> String {
    let prefix = match kind {
        FindingKind::Vuln => "vuln",
        FindingKind::FixAvailable => "fix",
        FindingKind::OathExpired => "oath_expired",
        FindingKind::MajorRelease => "major_release",
        FindingKind::Eol => "eol",
        FindingKind::K8sCve => "k8s_cve",
        FindingKind::ReleaseNoteCve => "relnote",
    };
    let mut all = vec![prefix];
    all.extend_from_slice(parts);
    all.join("|")
}

/// One advisory linked to one component, with what the findings need from both.
#[derive(Debug, FromRow)]
struct Link {
    component_id: i64,
    version: String,
    advisory_id: String,
    match_source: MatchSource,
    severity: Severity,
    /// `{name_key: [fixed versions]}`
    fixed: Value,
    scores: Value,
}

/// A finding this run says should be open.
#[derive(Debug)]
struct Wanted {
    key: String,
    kind: FindingKind,
    realm: String,
    service_id: Option<i64>,
    component_id: Option<i64>,
    ref_id: String,
    severity: Severity,
    details: Value,
}

/// Bring the realm's findings up to date at `now`:
/// 1. Vuln and FixAvailable findings from effective components and their
///    linked advisories (an active oath is recorded in `details.oath`).
/// 2. An OathExpired finding for every lapsed oath whose advisory still
///    applies to the oath's component and service.
/// 3. Upsert all of them by key, and resolve open Vuln/FixAvailable findings
///    of this realm that were not produced.
///
/// Everything happens in one transaction, so a failed run also rolls back the
/// oath expiries and the next run expires them again. OathExpired findings are
/// one-shot and never resolved here. MajorRelease, Eol, K8sCve and
/// ReleaseNoteCve belong to the watchers and are left alone.
pub async fn run(pool: &PgPool, realm: &str, now: DateTime<Utc>) -> anyhow::Result<MatchReport> {
    let mut tx = pool.begin().await?;
    // Several loops call the matcher. Runs for one realm wait for each other
    // here, so each reads the state the previous one committed and they never
    // race to insert the same key. The lock is released at commit or rollback.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('matcher:' || $1))")
        .bind(realm)
        .execute(&mut *tx)
        .await?;

    let mut wanted: BTreeMap<String, Wanted> = BTreeMap::new();
    for w in component_findings(&mut tx, realm, now).await? {
        // Two versions of one package in one service share a key; the first
        // (lowest purl) wins so the finding does not flip between runs.
        wanted.entry(w.key.clone()).or_insert(w);
    }
    let expired = oath::process_expiries(&mut tx, now).await?;
    for w in expiry_findings(&mut tx, realm, &expired).await? {
        wanted.insert(w.key.clone(), w);
    }

    let opened = upsert(&mut tx, &wanted, now).await?;
    let keys: Vec<&String> = wanted.keys().collect();
    let resolved = sqlx::query(
        "UPDATE findings SET status = 'resolved', resolved_at = $2 \
         WHERE realm = $1 AND status = 'open' AND kind IN ('vuln', 'fixavailable') \
           AND key <> ALL($3)",
    )
    .bind(realm)
    .bind(now)
    .bind(&keys)
    .execute(&mut *tx)
    .await?
    .rows_affected() as usize;
    tx.commit().await?;

    Ok(MatchReport { opened, resolved })
}

/// Vuln and FixAvailable findings for every effective component of the realm.
async fn component_findings(
    tx: &mut PgConnection,
    realm: &str,
    now: DateTime<Utc>,
) -> anyhow::Result<Vec<Wanted>> {
    let components = effective_components(&mut *tx, realm).await?;
    let ids: Vec<i64> = components.iter().map(|c| c.component_id).collect();
    let links: Vec<Link> = sqlx::query_as(
        "SELECT ca.component_id, c.version, ca.advisory_id, ca.match_source, \
                a.severity, a.fixed, a.scores \
         FROM component_advisories ca \
         JOIN components c ON c.id = ca.component_id \
         JOIN advisories a ON a.id = ca.advisory_id \
         WHERE ca.component_id = ANY($1) \
         ORDER BY ca.component_id, ca.advisory_id",
    )
    .bind(&ids)
    .fetch_all(&mut *tx)
    .await?;
    let mut by_component: HashMap<i64, Vec<Link>> = HashMap::new();
    for l in links {
        by_component.entry(l.component_id).or_default().push(l);
    }

    let mut out = Vec::new();
    for c in &components {
        for link in by_component.get(&c.component_id).into_iter().flatten() {
            let oath = oath::active_for(
                &mut *tx,
                &link.advisory_id,
                &c.name_key,
                &c.service,
                realm,
                now,
            )
            .await?;
            out.extend(findings_for(realm, c, link, oath.map(|o| o.id)));
        }
    }
    Ok(out)
}

/// The Vuln finding for one (component, advisory) pair, plus a FixAvailable
/// when a fixed version newer than the current one exists. An oath does not
/// stop either: the Vuln carries the oath id so Gjallarhorn stays quiet.
fn findings_for(
    realm: &str,
    c: &EffectiveComponent,
    link: &Link,
    oath: Option<i64>,
) -> Vec<Wanted> {
    let fixed: Vec<String> = link.fixed[&c.name_key]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    // Purls OSV has no ecosystem for (generic, oci, ...) are compared as
    // "generic", which tolerates non-semver versions.
    let ecosystem = osv_package(&c.purl)
        .map(|p| p.ecosystem)
        .unwrap_or_else(|| "generic".to_string());
    let fixed_refs: Vec<&str> = fixed.iter().map(String::as_str).collect();
    let advice = recommend_fix(&ecosystem, &link.version, &fixed_refs);

    let parts = [
        realm,
        c.service.as_str(),
        c.name_key.as_str(),
        link.advisory_id.as_str(),
    ];
    let base = |kind: FindingKind, details: Value| Wanted {
        key: key(kind, &parts),
        kind,
        realm: realm.to_string(),
        service_id: Some(c.service_id),
        component_id: Some(c.component_id),
        ref_id: link.advisory_id.clone(),
        severity: link.severity,
        details,
    };

    let mut out = vec![base(
        FindingKind::Vuln,
        json!({
            "purl": c.purl,
            "version": link.version,
            "fixed": fixed,
            "advice": advice,
            "oath": oath,
            "direct": c.direct,
            "match_source": link.match_source,
            "scores": link.scores,
        }),
    )];
    if let Some(advice) = advice {
        out.push(base(
            FindingKind::FixAvailable,
            json!({
                "purl": c.purl,
                "version": link.version,
                "advice": advice,
                "direct": c.direct,
                "advisory": link.advisory_id,
            }),
        ));
    }
    out
}

/// One OathExpired finding per expired oath that still matters, with the
/// advisory's severity. An oath whose advisory no longer links its component
/// in its service (the CVE was fixed, the component left) gets no finding;
/// the expiry stays visible in `oath_events`.
async fn expiry_findings(
    tx: &mut PgConnection,
    realm: &str,
    expired: &[Oath],
) -> anyhow::Result<Vec<Wanted>> {
    let advisory_ids: Vec<&str> = expired.iter().map(|o| o.advisory_id.as_str()).collect();
    let severities: HashMap<String, Severity> = sqlx::query_as::<_, (String, Severity)>(
        "SELECT id, severity FROM advisories WHERE id = ANY($1)",
    )
    .bind(&advisory_ids)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .collect();

    let mut out = Vec::new();
    for o in expired {
        let Some(filed_in) = realm_where_oath_applies(tx, o, realm).await? else {
            continue;
        };
        out.push(Wanted {
            key: key(FindingKind::OathExpired, &[&o.id.to_string()]),
            kind: FindingKind::OathExpired,
            realm: filed_in,
            service_id: None,
            component_id: None,
            ref_id: o.advisory_id.clone(),
            severity: severities
                .get(&o.advisory_id)
                .copied()
                .unwrap_or(Severity::Unknown),
            details: json!({
                "oath": o.id,
                "advisory": o.advisory_id,
                "name_key": o.name_key,
                "service": o.service_name,
                "realm": o.realm,
                "kind": o.kind,
                "reason": o.reason,
                "version_at_creation": o.version_at_creation,
            }),
        });
    }
    Ok(out)
}

/// The realm in which the oath's advisory still links a component with the
/// oath's name in the oath's service, or None. A realm oath checks its own
/// realm. An all-realms oath checks every realm with a service of that name,
/// preferring the realm being matched, then the first by name.
async fn realm_where_oath_applies(
    tx: &mut PgConnection,
    o: &Oath,
    current: &str,
) -> anyhow::Result<Option<String>> {
    let mut candidates: Vec<String> = match &o.realm {
        Some(r) => vec![r.clone()],
        None => {
            sqlx::query_scalar("SELECT DISTINCT realm FROM services WHERE name = $1 ORDER BY realm")
                .bind(&o.service_name)
                .fetch_all(&mut *tx)
                .await?
        }
    };
    if let Some(pos) = candidates.iter().position(|r| r == current) {
        let r = candidates.remove(pos);
        candidates.insert(0, r);
    }
    for r in candidates {
        let ids: Vec<i64> = effective_components(&mut *tx, &r)
            .await?
            .into_iter()
            .filter(|c| c.service == o.service_name && c.name_key == o.name_key)
            .map(|c| c.component_id)
            .collect();
        let linked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM component_advisories \
             WHERE advisory_id = $1 AND component_id = ANY($2))",
        )
        .bind(&o.advisory_id)
        .bind(&ids)
        .fetch_one(&mut *tx)
        .await?;
        if linked {
            return Ok(Some(r));
        }
    }
    Ok(None)
}

/// Write `wanted` by key and return the ids of new occurrences. A new key is
/// inserted; a resolved finding (or any OathExpired, which is produced only
/// when an oath lapses) is re-opened with `notified_at` cleared; an open one
/// only gets its severity and details refreshed, so it is not announced again.
/// A Vuln or FixAvailable resolved within `FLAP_WINDOW_DAYS` re-opens but
/// keeps its `notified_at`: it was announced, and only flapped.
async fn upsert(
    tx: &mut PgConnection,
    wanted: &BTreeMap<String, Wanted>,
    now: DateTime<Utc>,
) -> anyhow::Result<Vec<i64>> {
    let keys: Vec<&String> = wanted.keys().collect();
    // Runs of one realm are already serialized by the advisory lock in `run`.
    // FOR UPDATE also holds these rows against other writers (Gjallarhorn
    // setting notified_at, a run of another realm) between this read and
    // our write, so the open/resolved decision below stays true.
    let existing: HashMap<String, Existing> = sqlx::query_as::<_, Existing>(
        "SELECT key, id, status, resolved_at FROM findings WHERE key = ANY($1) FOR UPDATE",
    )
    .bind(&keys)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .map(|e| (e.key.clone(), e))
    .collect();
    let flap_since = now - chrono::Duration::days(FLAP_WINDOW_DAYS);

    let mut opened = Vec::new();
    for w in wanted.values() {
        match existing.get(&w.key) {
            None => {
                let id: i64 = sqlx::query_scalar(
                    "INSERT INTO findings (key, kind, realm, service_id, component_id, ref_id, \
                         severity, details, opened_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
                )
                .bind(&w.key)
                .bind(w.kind)
                .bind(&w.realm)
                .bind(w.service_id)
                .bind(w.component_id)
                .bind(&w.ref_id)
                .bind(w.severity)
                .bind(&w.details)
                .bind(now)
                .fetch_one(&mut *tx)
                .await?;
                opened.push(id);
            }
            Some(e) if e.status == "resolved" || w.kind == FindingKind::OathExpired => {
                let flapped = matches!(w.kind, FindingKind::Vuln | FindingKind::FixAvailable)
                    && e.resolved_at.is_some_and(|at| at > flap_since);
                // On the right of SET, `notified_at` is still the old value.
                sqlx::query(
                    "UPDATE findings SET status = 'open', opened_at = $2, resolved_at = NULL, \
                         notified_at = CASE WHEN $5 THEN notified_at ELSE NULL END, \
                         severity = $3, details = $4 \
                     WHERE id = $1",
                )
                .bind(e.id)
                .bind(now)
                .bind(w.severity)
                .bind(&w.details)
                .bind(flapped)
                .execute(&mut *tx)
                .await?;
                if !flapped {
                    opened.push(e.id);
                }
            }
            Some(Existing { id, .. }) => {
                // A Vuln re-scored from below High to High or worse alerts
                // again: it may have been announced only in the digest. On
                // the right of SET, `severity` is still the old value.
                sqlx::query(
                    "UPDATE findings SET severity = $2, details = $3, \
                         notified_at = CASE \
                             WHEN kind = 'vuln' \
                                  AND severity NOT IN ('critical', 'high') \
                                  AND $2 IN ('critical', 'high') THEN NULL \
                             ELSE notified_at END \
                     WHERE id = $1",
                )
                .bind(id)
                .bind(w.severity)
                .bind(&w.details)
                .execute(&mut *tx)
                .await?;
            }
        }
    }
    Ok(opened)
}

/// A finding row `upsert` may update.
#[derive(FromRow)]
struct Existing {
    key: String,
    id: i64,
    status: String,
    resolved_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use serde_json::{json, Value};

    use super::*;
    use crate::inventory::store::{replace_components, upsert_service, InventoryItem};
    use crate::model::Source;

    const REALM: &str = "prod";
    const SERVICE: &str = "api";
    const GIN_KEY: &str = "pkg:golang/github.com/gin-gonic/gin";
    const ADV: &str = "GHSA-gin-0001";

    fn gin(version: &str) -> String {
        format!("{GIN_KEY}@{version}")
    }

    fn item(purl: &str, direct: bool) -> InventoryItem {
        InventoryItem {
            purl: purl.to_string(),
            cpes: vec![],
            direct,
            via_image_digest: None,
        }
    }

    /// Put `items` in the service's inventory for `source`; returns the service id.
    async fn inventory(pool: &PgPool, source: Source, items: &[InventoryItem]) -> i64 {
        let sid = upsert_service(pool, REALM, SERVICE).await.unwrap();
        replace_components(pool, sid, source, items).await.unwrap();
        sid
    }

    async fn advisory(pool: &PgPool, id: &str, severity: &str, fixed: Value, scores: Value) {
        sqlx::query(
            "INSERT INTO advisories (id, severity, summary, fixed, source, scores) \
             VALUES ($1, $2, 'test advisory', $3, 'osv', $4)",
        )
        .bind(id)
        .bind(severity)
        .bind(fixed)
        .bind(scores)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn link(pool: &PgPool, purl: &str, advisory_id: &str, match_source: &str) {
        sqlx::query(
            "INSERT INTO component_advisories (component_id, advisory_id, match_source) \
             SELECT id, $2, $3 FROM components WHERE purl = $1",
        )
        .bind(purl)
        .bind(advisory_id)
        .bind(match_source)
        .execute(pool)
        .await
        .unwrap();
    }

    /// The usual case: gin 1.9.0, direct, linked by OSV to an advisory fixed in 1.9.1.
    async fn seed_gin(pool: &PgPool, version: &str) {
        inventory(pool, Source::Git, &[item(&gin(version), true)]).await;
        advisory(
            pool,
            ADV,
            "high",
            json!({ GIN_KEY: ["1.9.1"] }),
            json!({"osv": 7.5}),
        )
        .await;
        link(pool, &gin(version), ADV, "osv").await;
    }

    async fn snooze(pool: &PgPool, expires_at: DateTime<Utc>) -> i64 {
        sqlx::query_scalar(
            "INSERT INTO oaths (advisory_id, name_key, service_name, realm, kind, reason, \
             version_at_creation, expires_at, created_by) \
             VALUES ($1, $2, $3, $4, 'snooze', 'not reachable', '1.9.0', $5, 'alice') \
             RETURNING id",
        )
        .bind(ADV)
        .bind(GIN_KEY)
        .bind(SERVICE)
        .bind(REALM)
        .bind(expires_at)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[derive(Debug, sqlx::FromRow)]
    struct Row {
        id: i64,
        key: String,
        kind: FindingKind,
        severity: String,
        status: String,
        notified_at: Option<DateTime<Utc>>,
        details: Value,
    }

    async fn findings(pool: &PgPool) -> Vec<Row> {
        sqlx::query_as(
            "SELECT id, key, kind, severity, status, notified_at, details FROM findings ORDER BY id",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    async fn of_kind(pool: &PgPool, kind: FindingKind) -> Vec<Row> {
        findings(pool)
            .await
            .into_iter()
            .filter(|f| f.kind == kind)
            .collect()
    }

    fn vuln_key() -> String {
        key(FindingKind::Vuln, &[REALM, SERVICE, GIN_KEY, ADV])
    }

    #[test]
    fn keys_join_parts_with_kind_prefix() {
        assert_eq!(
            key(FindingKind::Vuln, &["prod", "api", "n", "A"]),
            "vuln|prod|api|n|A"
        );
        assert_eq!(key(FindingKind::FixAvailable, &["prod", "x"]), "fix|prod|x");
        assert_eq!(key(FindingKind::OathExpired, &["7"]), "oath_expired|7");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn vuln_opened_once_and_stable(pool: PgPool) {
        seed_gin(&pool, "v1.9.0").await;
        let now = Utc::now();

        let first = run(&pool, REALM, now).await.unwrap();
        let vulns = of_kind(&pool, FindingKind::Vuln).await;
        assert_eq!(vulns.len(), 1);
        let v = &vulns[0];
        assert_eq!(v.key, vuln_key());
        assert_eq!(v.severity, "high");
        assert_eq!(v.status, "open");
        assert!(v.notified_at.is_none());
        assert!(first.opened.contains(&v.id));
        assert_eq!(v.details["purl"], json!(gin("v1.9.0")));
        assert_eq!(v.details["version"], json!("v1.9.0"));
        assert_eq!(v.details["fixed"], json!(["1.9.1"]));
        assert_eq!(v.details["direct"], json!(true));
        assert_eq!(v.details["match_source"], json!("osv"));
        assert_eq!(v.details["scores"], json!({"osv": 7.5}));
        assert_eq!(v.details["oath"], Value::Null);

        let second = run(&pool, REALM, now).await.unwrap();
        assert!(second.opened.is_empty(), "{second:?}");
        assert_eq!(second.resolved, 0);
        assert_eq!(of_kind(&pool, FindingKind::Vuln).await.len(), 1);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn open_finding_updates_severity_but_keeps_notified_at(pool: PgPool) {
        seed_gin(&pool, "v1.9.0").await;
        let now = Utc::now();
        run(&pool, REALM, now).await.unwrap();
        sqlx::query("UPDATE findings SET notified_at = $1")
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE advisories SET severity = 'critical'")
            .execute(&pool)
            .await
            .unwrap();

        // High -> critical: already alerted as high, so no second alert.
        let report = run(&pool, REALM, now).await.unwrap();
        assert!(report.opened.is_empty());
        let v = &of_kind(&pool, FindingKind::Vuln).await[0];
        assert_eq!(v.severity, "critical");
        assert!(v.notified_at.is_some());

        // Medium -> low stays below High: notified_at is kept too.
        for sev in ["medium", "low"] {
            sqlx::query("UPDATE advisories SET severity = $1")
                .bind(sev)
                .execute(&pool)
                .await
                .unwrap();
            run(&pool, REALM, now).await.unwrap();
            let v = &of_kind(&pool, FindingKind::Vuln).await[0];
            assert_eq!(v.severity, sev);
            assert!(v.notified_at.is_some(), "{sev}");
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn severity_crossing_high_rearms_alert(pool: PgPool) {
        seed_gin(&pool, "v1.9.0").await;
        sqlx::query("UPDATE advisories SET severity = 'medium'")
            .execute(&pool)
            .await
            .unwrap();
        let now = Utc::now();
        run(&pool, REALM, now).await.unwrap();
        // The digest announced the medium Vuln (and its fix alerted).
        sqlx::query("UPDATE findings SET notified_at = $1")
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE advisories SET severity = 'high'")
            .execute(&pool)
            .await
            .unwrap();

        run(&pool, REALM, now).await.unwrap();
        let v = &of_kind(&pool, FindingKind::Vuln).await[0];
        assert_eq!(v.severity, "high");
        assert!(v.notified_at.is_none());
        let f = &of_kind(&pool, FindingKind::FixAvailable).await[0];
        assert!(f.notified_at.is_some());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn vuln_resolves_when_component_removed(pool: PgPool) {
        seed_gin(&pool, "v1.9.0").await;
        let now = Utc::now();
        run(&pool, REALM, now).await.unwrap();

        let sid = upsert_service(&pool, REALM, SERVICE).await.unwrap();
        replace_components(&pool, sid, Source::Git, &[])
            .await
            .unwrap();
        let report = run(&pool, REALM, now).await.unwrap();

        // The vuln and its fix finding both go.
        assert_eq!(report.resolved, 2);
        let all = findings(&pool).await;
        assert_eq!(all.len(), 2);
        assert!(all.iter().all(|f| f.status == "resolved"), "{all:?}");
    }

    /// Open the gin findings, mark them announced, take gin away at
    /// `resolved_at` and run the matcher there, then put gin back.
    async fn announce_resolve_and_return(pool: &PgPool, resolved_at: DateTime<Utc>) {
        seed_gin(pool, "v1.9.0").await;
        run(pool, REALM, resolved_at - Duration::hours(1))
            .await
            .unwrap();
        sqlx::query("UPDATE findings SET notified_at = $1")
            .bind(resolved_at)
            .execute(pool)
            .await
            .unwrap();
        let sid = upsert_service(pool, REALM, SERVICE).await.unwrap();
        replace_components(pool, sid, Source::Git, &[])
            .await
            .unwrap();
        run(pool, REALM, resolved_at).await.unwrap();
        inventory(pool, Source::Git, &[item(&gin("v1.9.0"), true)]).await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn reopen_within_30_days_keeps_notified_at(pool: PgPool) {
        // An inventory flap (a scale-to-zero, an image not scanned yet):
        // the findings come back, already announced, so no second card.
        let resolved_at = Utc::now() - Duration::days(29);
        announce_resolve_and_return(&pool, resolved_at).await;
        let report = run(&pool, REALM, Utc::now()).await.unwrap();
        let all = findings(&pool).await;
        assert_eq!(all.len(), 2, "same keys, same rows");
        assert!(all
            .iter()
            .all(|f| f.status == "open" && f.notified_at.is_some()));
        assert!(report.opened.is_empty(), "{report:?}");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn reopen_after_30_days_rearms(pool: PgPool) {
        // Gone for over 30 days: coming back is a new occurrence.
        let resolved_at = Utc::now() - Duration::days(31);
        announce_resolve_and_return(&pool, resolved_at).await;
        let report = run(&pool, REALM, Utc::now()).await.unwrap();
        let all = findings(&pool).await;
        assert_eq!(all.len(), 2, "same keys, same rows");
        assert!(all
            .iter()
            .all(|f| f.status == "open" && f.notified_at.is_none()));
        let mut ids: Vec<i64> = all.iter().map(|f| f.id).collect();
        let mut opened = report.opened.clone();
        ids.sort();
        opened.sort();
        assert_eq!(opened, ids);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn resolve_is_scoped_to_realm(pool: PgPool) {
        seed_gin(&pool, "v1.9.0").await;
        let now = Utc::now();
        run(&pool, REALM, now).await.unwrap();
        let report = run(&pool, "staging", now).await.unwrap();
        assert_eq!(report.resolved, 0);
        assert!(findings(&pool).await.iter().all(|f| f.status == "open"));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn fix_available_when_fixed_version_greater(pool: PgPool) {
        seed_gin(&pool, "v1.9.0").await;
        run(&pool, REALM, Utc::now()).await.unwrap();
        let fixes = of_kind(&pool, FindingKind::FixAvailable).await;
        assert_eq!(fixes.len(), 1);
        let f = &fixes[0];
        assert_eq!(
            f.key,
            key(FindingKind::FixAvailable, &[REALM, SERVICE, GIN_KEY, ADV])
        );
        assert_eq!(f.severity, "high");
        assert_eq!(f.details["purl"], json!(gin("v1.9.0")));
        assert_eq!(f.details["version"], json!("v1.9.0"));
        assert_eq!(f.details["advisory"], json!(ADV));
        assert_eq!(f.details["direct"], json!(true));
        assert_eq!(
            f.details["advice"],
            json!({"suggest": "1.9.1", "latest": "1.9.1"})
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn no_fix_available_when_current_is_past_the_fix(pool: PgPool) {
        // OSV would not link v1.9.2, so there is nothing to find.
        inventory(&pool, Source::Git, &[item(&gin("v1.9.2"), true)]).await;
        advisory(&pool, ADV, "high", json!({ GIN_KEY: ["1.9.1"] }), json!({})).await;
        let report = run(&pool, REALM, Utc::now()).await.unwrap();
        assert!(report.opened.is_empty());
        assert!(findings(&pool).await.is_empty());

        // Even if a link exists (say an NVD range), a fix that is not newer
        // than the current version is no FixAvailable.
        link(&pool, &gin("v1.9.2"), ADV, "nvd").await;
        run(&pool, REALM, Utc::now()).await.unwrap();
        assert_eq!(of_kind(&pool, FindingKind::Vuln).await.len(), 1);
        assert!(of_kind(&pool, FindingKind::FixAvailable).await.is_empty());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn fix_available_even_under_oath(pool: PgPool) {
        seed_gin(&pool, "v1.9.0").await;
        let now = Utc::now();
        let oath_id = snooze(&pool, now + Duration::days(7)).await;
        run(&pool, REALM, now).await.unwrap();

        let vulns = of_kind(&pool, FindingKind::Vuln).await;
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].details["oath"], json!(oath_id));
        assert_eq!(of_kind(&pool, FindingKind::FixAvailable).await.len(), 1);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn oath_filed_under_cve_suppresses_vuln(pool: PgPool) {
        seed_gin(&pool, "v1.9.0").await;
        sqlx::query("UPDATE advisories SET cve_id = 'CVE-2026-0042', aliases = '{CVE-2026-0042}'")
            .execute(&pool)
            .await
            .unwrap();
        // Someone files the oath under the CVE they read about.
        let created = oath::create(
            &pool,
            oath::NewOath {
                advisory_id: "CVE-2026-0042".to_string(),
                purl: gin("v1.9.0"),
                service: SERVICE.to_string(),
                realm: REALM.to_string(),
                all_realms: false,
                kind: crate::model::OathKind::Ignore,
                reason: "not reachable".to_string(),
                until: None,
                by: "alice".to_string(),
            },
        )
        .await
        .unwrap();
        run(&pool, REALM, Utc::now()).await.unwrap();
        let v = &of_kind(&pool, FindingKind::Vuln).await[0];
        assert_eq!(v.details["oath"], json!(created.id));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn oath_expired_finding_from_expiry(pool: PgPool) {
        seed_gin(&pool, "v1.9.0").await;
        let now = Utc::now();
        let oath_id = snooze(&pool, now - Duration::hours(1)).await;

        let report = run(&pool, REALM, now).await.unwrap();
        let expired = of_kind(&pool, FindingKind::OathExpired).await;
        assert_eq!(expired.len(), 1);
        let e = &expired[0];
        assert_eq!(
            e.key,
            key(FindingKind::OathExpired, &[&oath_id.to_string()])
        );
        assert_eq!(e.status, "open");
        assert!(e.notified_at.is_none());
        assert_eq!(e.severity, "high");
        assert_eq!(e.details["oath"], json!(oath_id));
        assert_eq!(e.details["advisory"], json!(ADV));
        assert!(report.opened.contains(&e.id));
        // The lapsed oath no longer covers the vuln.
        let v = &of_kind(&pool, FindingKind::Vuln).await[0];
        assert_eq!(v.details["oath"], Value::Null);

        // One-shot: a later run neither re-opens nor resolves it.
        let again = run(&pool, REALM, now).await.unwrap();
        assert!(!again.opened.contains(&e.id));
        let expired = of_kind(&pool, FindingKind::OathExpired).await;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].status, "open");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn ci_inventory_produces_no_findings(pool: PgPool) {
        inventory(&pool, Source::Ci, &[item(&gin("v1.9.0"), true)]).await;
        advisory(&pool, ADV, "high", json!({ GIN_KEY: ["1.9.1"] }), json!({})).await;
        link(&pool, &gin("v1.9.0"), ADV, "osv").await;
        let report = run(&pool, REALM, Utc::now()).await.unwrap();
        assert!(report.opened.is_empty());
        assert!(findings(&pool).await.is_empty());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn fix_available_for_indirect_has_direct_false(pool: PgPool) {
        inventory(&pool, Source::Git, &[item(&gin("v1.9.0"), false)]).await;
        advisory(
            &pool,
            ADV,
            "medium",
            json!({ GIN_KEY: ["1.9.1"] }),
            json!({}),
        )
        .await;
        link(&pool, &gin("v1.9.0"), ADV, "osv").await;
        run(&pool, REALM, Utc::now()).await.unwrap();
        let fixes = of_kind(&pool, FindingKind::FixAvailable).await;
        assert_eq!(fixes.len(), 1);
        assert_eq!(fixes[0].details["direct"], json!(false));
        assert_eq!(fixes[0].severity, "medium");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn advice_uses_recommend_fix(pool: PgPool) {
        const LIB: &str = "pkg:npm/lib";
        let purl = format!("{LIB}@2.4.0");
        inventory(&pool, Source::Git, &[item(&purl, true)]).await;
        advisory(
            &pool,
            ADV,
            "high",
            json!({ LIB: ["2.4.1", "2.5.3", "3.0.0"] }),
            json!({}),
        )
        .await;
        link(&pool, &purl, ADV, "osv").await;
        run(&pool, REALM, Utc::now()).await.unwrap();

        let want = json!({"suggest": "2.4.1", "latest": "3.0.0"});
        let v = &of_kind(&pool, FindingKind::Vuln).await[0];
        assert_eq!(v.details["advice"], want);
        let f = &of_kind(&pool, FindingKind::FixAvailable).await[0];
        assert_eq!(f.details["advice"], want);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn nvd_link_produces_vuln_with_match_source_nvd(pool: PgPool) {
        const OPENSSL: &str = "pkg:generic/openssl";
        let purl = format!("{OPENSSL}@3.0.11");
        inventory(&pool, Source::Git, &[item(&purl, false)]).await;
        advisory(
            &pool,
            "CVE-2024-0001",
            "critical",
            json!({}),
            json!({"nvd": 9.8}),
        )
        .await;
        link(&pool, &purl, "CVE-2024-0001", "nvd").await;
        run(&pool, REALM, Utc::now()).await.unwrap();

        let vulns = of_kind(&pool, FindingKind::Vuln).await;
        assert_eq!(vulns.len(), 1);
        let v = &vulns[0];
        assert_eq!(v.severity, "critical");
        assert_eq!(v.details["match_source"], json!("nvd"));
        assert_eq!(v.details["scores"], json!({"nvd": 9.8}));
        assert_eq!(v.details["fixed"], json!([]));
        assert_eq!(v.details["advice"], Value::Null);
        // No fixed version known, so no FixAvailable.
        assert!(of_kind(&pool, FindingKind::FixAvailable).await.is_empty());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn expiry_rolls_back_with_failed_matcher_tx(pool: PgPool) {
        seed_gin(&pool, "v1.9.0").await;
        let now = Utc::now();
        let oath_id = snooze(&pool, now - Duration::hours(1)).await;
        // Make the findings write fail after process_expiries has run.
        sqlx::query(
            "CREATE FUNCTION fail_findings() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'boom'; END $$",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER fail_findings BEFORE INSERT ON findings \
             FOR EACH ROW EXECUTE FUNCTION fail_findings()",
        )
        .execute(&pool)
        .await
        .unwrap();

        assert!(run(&pool, REALM, now).await.is_err());
        let status: String = sqlx::query_scalar("SELECT status FROM oaths WHERE id = $1")
            .bind(oath_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "active", "the expiry rolled back with the run");

        sqlx::query("DROP TRIGGER fail_findings ON findings")
            .execute(&pool)
            .await
            .unwrap();
        run(&pool, REALM, now).await.unwrap();
        let expired = of_kind(&pool, FindingKind::OathExpired).await;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].details["oath"], json!(oath_id));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn concurrent_runs_same_realm_no_error(pool: PgPool) {
        seed_gin(&pool, "v1.9.0").await;
        let now = Utc::now();
        // Several runs at once, as Task 17's loops will do. Without the realm
        // lock they race to insert the same keys (unique violation).
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let pool = pool.clone();
            set.spawn(async move { run(&pool, REALM, now).await });
        }
        let mut opened = 0;
        while let Some(res) = set.join_next().await {
            opened += res.unwrap().unwrap().opened.len();
        }
        // One run inserted both findings; the others saw them committed.
        assert_eq!(opened, 2);
        let all = findings(&pool).await;
        assert_eq!(all.len(), 2);
        let mut keys: Vec<&str> = all.iter().map(|f| f.key.as_str()).collect();
        keys.dedup();
        assert_eq!(keys.len(), 2);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn expired_oath_for_fixed_cve_is_silent(pool: PgPool) {
        seed_gin(&pool, "v1.9.0").await;
        let now = Utc::now();
        let oath_id = snooze(&pool, now - Duration::hours(1)).await;
        // Upgraded past the fix: OSV no longer links the component.
        inventory(&pool, Source::Git, &[item(&gin("v1.9.1"), true)]).await;

        run(&pool, REALM, now).await.unwrap();
        assert!(of_kind(&pool, FindingKind::OathExpired).await.is_empty());
        let (status, events): (String, i64) = sqlx::query_as(
            "SELECT o.status, (SELECT count(*) FROM oath_events e \
                 WHERE e.oath_id = o.id AND e.event = 'expired') \
             FROM oaths o WHERE o.id = $1",
        )
        .bind(oath_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((status.as_str(), events), ("expired", 1));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn all_realms_expiry_filed_where_it_applies(pool: PgPool) {
        // The service runs in prod (linked) and staging (not linked).
        seed_gin(&pool, "v1.9.0").await;
        let staging = upsert_service(&pool, "staging", SERVICE).await.unwrap();
        replace_components(&pool, staging, Source::Git, &[item(&gin("v1.9.1"), true)])
            .await
            .unwrap();
        let now = Utc::now();
        let oath_id: i64 = sqlx::query_scalar(
            "INSERT INTO oaths (advisory_id, name_key, service_name, realm, kind, reason, \
             version_at_creation, expires_at, created_by) \
             VALUES ($1, $2, $3, NULL, 'snooze', 'not reachable', '1.9.0', $4, 'alice') \
             RETURNING id",
        )
        .bind(ADV)
        .bind(GIN_KEY)
        .bind(SERVICE)
        .bind(now - Duration::hours(1))
        .fetch_one(&pool)
        .await
        .unwrap();

        // The staging run processes the expiry, but files it under prod.
        run(&pool, "staging", now).await.unwrap();
        let expired = of_kind(&pool, FindingKind::OathExpired).await;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].details["oath"], json!(oath_id));
        let realm: String = sqlx::query_scalar("SELECT realm FROM findings WHERE id = $1")
            .bind(expired[0].id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(realm, REALM);
    }
}
