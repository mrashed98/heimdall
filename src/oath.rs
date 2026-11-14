//! Oaths: recorded human decisions to accept an advisory for one component
//! in one service. A snooze lapses on a date; an ignore comes up for review.
//! The matcher, the gate and the digest all read oaths from here.

use std::fmt;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::auth::{require, Authed, Scope};
use crate::error::ApiError;
use crate::model::OathKind;
use crate::vuln::collapse::{canonical, AliasInfo};
use crate::AppState;

/// A request that breaks a rule (blank reason, date in the past, ...).
/// Wrapped in `anyhow::Error` so callers can tell it from a database failure
/// with `downcast`; the HTTP layer turns it into a 400.
#[derive(Debug)]
pub struct Invalid(pub String);

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Invalid {}

/// What a caller asks for. `by` is filled in by the server from the API key.
#[derive(Debug, Clone)]
pub struct NewOath {
    pub advisory_id: String,
    /// The component's current purl; its name and version are taken from it.
    pub purl: String,
    pub service: String,
    /// Ignored when `all_realms` is true.
    pub realm: String,
    pub all_realms: bool,
    pub kind: OathKind,
    pub reason: String,
    pub until: Option<NaiveDate>,
    pub by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Oath {
    pub id: i64,
    pub advisory_id: String,
    pub name_key: String,
    pub service_name: String,
    /// None means all realms.
    pub realm: Option<String>,
    pub kind: OathKind,
    pub reason: String,
    pub version_at_creation: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub review_at: Option<DateTime<Utc>>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub status: String,
}

/// Every column of `oaths` that `Oath` carries, in one place so each query
/// returns the same shape.
const COLUMNS: &str = "id, advisory_id, name_key, service_name, realm, kind, reason, \
     version_at_creation, expires_at, review_at, created_by, created_at, status";

fn invalid(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Invalid(msg.into()))
}

/// A date means 00:00 UTC on that day.
fn midnight_utc(d: NaiveDate) -> DateTime<Utc> {
    d.and_hms_opt(0, 0, 0).expect("midnight exists").and_utc()
}

/// Dates for snooze/ignore/extend must be strictly after today (UTC).
fn check_future(until: NaiveDate) -> anyhow::Result<()> {
    if until <= Utc::now().date_naive() {
        return Err(invalid(format!(
            "until must be after today (UTC), got {until}"
        )));
    }
    Ok(())
}

/// The version part of a purl, or "" when it has none.
fn purl_version(purl: &str) -> String {
    use std::str::FromStr;
    packageurl::PackageUrl::from_str(purl)
        .ok()
        .and_then(|p| p.version().map(str::to_string))
        .unwrap_or_default()
}

/// What `create` made, and anything the caller should be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Created {
    pub id: i64,
    /// Set when the advisory id matches no known advisory: the oath is
    /// stored as given, but it suppresses nothing until an advisory with
    /// that id appears.
    pub warning: Option<String>,
}

/// Record an oath. The advisory may be given under any of its names (its
/// id, a CVE, an alias such as a GO- id); the oath is stored under the
/// advisory's own id, the one findings carry, and the name given is kept in
/// the `created` event's note.
pub async fn create(pool: &PgPool, req: NewOath) -> anyhow::Result<Created> {
    if req.reason.trim().is_empty() {
        return Err(invalid("reason must not be blank"));
    }
    if req.advisory_id.trim().is_empty() || req.service.trim().is_empty() {
        return Err(invalid("advisory and service must not be blank"));
    }
    if req.all_realms == !req.realm.is_empty() {
        return Err(invalid("give either a realm or all-realms, not both"));
    }
    let name_key = crate::purl::name_key(&req.purl).map_err(|e| invalid(format!("{e:#}")))?;
    let version = purl_version(&req.purl);
    if let Some(until) = req.until {
        check_future(until)?;
    }
    // A snooze lapses on its date; an ignore is reviewed on its date, or in
    // 90 days when none is given.
    let (expires_at, review_at) = match (req.kind, req.until) {
        (OathKind::Snooze, None) => return Err(invalid("a snooze needs an until date")),
        (OathKind::Snooze, Some(d)) => (Some(midnight_utc(d)), None),
        (OathKind::Ignore, Some(d)) => (None, Some(midnight_utc(d))),
        (OathKind::Ignore, None) => (None, Some(Utc::now() + Duration::days(90))),
    };
    let realm = if req.all_realms {
        None
    } else {
        Some(req.realm)
    };

    let given = req.advisory_id.trim();
    let mut tx = pool.begin().await?;
    let (advisory_id, warning) = match resolve_advisory(&mut tx, given).await? {
        Some(id) => (id, None),
        None => (
            given.to_string(),
            Some(format!(
                "no known advisory is called {given}; the oath is stored as given \
                 and applies once an advisory with that id is linked"
            )),
        ),
    };
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO oaths (advisory_id, name_key, service_name, realm, kind, reason, \
         version_at_creation, expires_at, review_at, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
    )
    .bind(&advisory_id)
    .bind(&name_key)
    .bind(&req.service)
    .bind(&realm)
    .bind(req.kind)
    .bind(req.reason.trim())
    .bind(&version)
    .bind(expires_at)
    .bind(review_at)
    .bind(&req.by)
    .fetch_one(&mut *tx)
    .await?;
    let note = (advisory_id != given).then(|| format!("filed as {given}"));
    add_event(&mut tx, id, "created", &req.by, note.as_deref()).await?;
    tx.commit().await?;
    Ok(Created { id, warning })
}

/// The id of the advisory known as `name` (its id, an alias or its CVE).
/// When several match (records from different databases not yet collapsed),
/// the canonical one; None when none does.
async fn resolve_advisory(
    tx: &mut sqlx::PgConnection,
    name: &str,
) -> anyhow::Result<Option<String>> {
    let rows: Vec<(String, Vec<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, aliases, cve_id FROM advisories \
         WHERE id = $1 OR $1 = ANY(aliases) OR cve_id = $1",
    )
    .bind(name)
    .fetch_all(&mut *tx)
    .await?;
    let items: Vec<AliasInfo> = rows
        .into_iter()
        .map(|(id, aliases, cve_id)| AliasInfo {
            id,
            aliases,
            cve_id,
        })
        .collect();
    if items.is_empty() {
        return Ok(None);
    }
    let all: Vec<usize> = (0..items.len()).collect();
    Ok(Some(items[canonical(&items, &all)].id.clone()))
}

async fn add_event(
    tx: &mut sqlx::PgConnection,
    oath_id: i64,
    event: &str,
    by: &str,
    note: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO oath_events (oath_id, event, by, note) VALUES ($1, $2, $3, $4)")
        .bind(oath_id)
        .bind(event)
        .bind(by)
        .bind(note)
        .execute(tx)
        .await?;
    Ok(())
}

/// SQL condition: the oath's `advisory_id` names the advisory `$1`, under
/// its id or as an alias either way (the advisory lists the oath's id, or the
/// oath's advisory row lists `$1`). So an oath keeps applying when OSV
/// collapse links the vulnerability under another of its ids.
pub(crate) const SAME_ADVISORY: &str = "(advisory_id = $1 \
     OR advisory_id IN (SELECT unnest(aliases) FROM advisories WHERE id = $1) \
     OR $1 IN (SELECT unnest(a.aliases) FROM advisories a WHERE a.id = oaths.advisory_id))";

/// The oath that suppresses `advisory_id` for this component in this service
/// and realm, if any. Matching is by component name (not version), so an oath
/// carries across versions; an all-realms oath (realm NULL) matches any realm.
/// The advisory may be named by any of its ids (`SAME_ADVISORY`).
/// Only `active` oaths whose date is still ahead of `now` count, so a lapsed
/// oath stops suppressing even if the scheduler is late. `process_expiries`
/// stays the one place that changes status, so each expiry is announced once.
/// Takes any executor (pool or open transaction) so the matcher can read it
/// inside its transaction.
pub async fn active_for(
    db: impl sqlx::PgExecutor<'_>,
    advisory_id: &str,
    name_key: &str,
    service_name: &str,
    realm: &str,
    now: DateTime<Utc>,
) -> anyhow::Result<Option<Oath>> {
    let sql = format!(
        "SELECT {COLUMNS} FROM oaths \
         WHERE status = 'active' AND {SAME_ADVISORY} AND name_key = $2 \
           AND service_name = $3 AND (realm = $4 OR realm IS NULL) \
           AND COALESCE(expires_at, review_at) > $5 \
         ORDER BY id LIMIT 1"
    );
    let found = sqlx::query_as::<_, Oath>(&sql)
        .bind(advisory_id)
        .bind(name_key)
        .bind(service_name)
        .bind(realm)
        .bind(now)
        .fetch_optional(db)
        .await?;
    Ok(found)
}

/// Retire every active oath that is due at `now` and return those oaths.
/// One UPDATE ... RETURNING does the selecting and the marking, so two
/// processes running at once cannot both get the same oath. It runs on the
/// caller's connection so the matcher can roll the expiry back together with
/// its findings: an expiry is never lost to a failed run.
pub async fn process_expiries(
    conn: &mut sqlx::PgConnection,
    now: DateTime<Utc>,
) -> anyhow::Result<Vec<Oath>> {
    let sql = format!(
        "WITH due AS ( \
             UPDATE oaths SET status = 'expired' \
             WHERE status = 'active' \
               AND ((kind = 'snooze' AND expires_at <= $1) \
                 OR (kind = 'ignore' AND review_at <= $1)) \
             RETURNING {COLUMNS} \
         ), logged AS ( \
             INSERT INTO oath_events (oath_id, event, by) \
             SELECT id, 'expired', 'heimdall' FROM due \
         ) \
         SELECT {COLUMNS} FROM due ORDER BY id"
    );
    let due = sqlx::query_as::<_, Oath>(&sql)
        .bind(now)
        .fetch_all(conn)
        .await?;
    Ok(due)
}

/// Revoke an oath. None means no such id. Revoking a revoked oath changes
/// nothing and records nothing.
pub async fn revoke(pool: &PgPool, id: i64, by: &str) -> anyhow::Result<Option<Oath>> {
    let mut tx = pool.begin().await?;
    let sql = format!(
        "UPDATE oaths SET status = 'revoked' WHERE id = $1 AND status <> 'revoked' \
         RETURNING {COLUMNS}"
    );
    let updated = sqlx::query_as::<_, Oath>(&sql)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    let result = match updated {
        Some(o) => {
            add_event(&mut tx, id, "revoked", by, None).await?;
            Some(o)
        }
        None => fetch(&mut tx, id).await?,
    };
    tx.commit().await?;
    Ok(result)
}

async fn fetch(tx: &mut sqlx::PgConnection, id: i64) -> anyhow::Result<Option<Oath>> {
    let sql = format!("SELECT {COLUMNS} FROM oaths WHERE id = $1");
    Ok(sqlx::query_as::<_, Oath>(&sql)
        .bind(id)
        .fetch_optional(tx)
        .await?)
}

/// Move an oath's date (snooze `expires_at` or ignore `review_at`) to
/// `until`. Works on active and expired oaths; an expired one becomes active
/// again. None means no such id.
pub async fn extend(
    pool: &PgPool,
    id: i64,
    until: NaiveDate,
    by: &str,
) -> anyhow::Result<Option<Oath>> {
    check_future(until)?;
    let at = midnight_utc(until);
    let mut tx = pool.begin().await?;
    // Lock the row so a concurrent revoke cannot be overwritten.
    let current: Option<(String,)> =
        sqlx::query_as("SELECT status FROM oaths WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((status,)) = current else {
        return Ok(None);
    };
    if status == "revoked" {
        return Err(invalid("a revoked oath cannot be extended"));
    }
    let sql = format!(
        "UPDATE oaths SET status = 'active', \
             expires_at = CASE WHEN kind = 'snooze' THEN $2 ELSE expires_at END, \
             review_at = CASE WHEN kind = 'ignore' THEN $2 ELSE review_at END \
         WHERE id = $1 RETURNING {COLUMNS}"
    );
    let oath = sqlx::query_as::<_, Oath>(&sql)
        .bind(id)
        .bind(at)
        .fetch_one(&mut *tx)
        .await?;
    let note = if status == "expired" {
        format!("reactivated until {until}")
    } else {
        format!("until {until}")
    };
    add_event(&mut tx, id, "extended", by, Some(&note)).await?;
    tx.commit().await?;
    Ok(Some(oath))
}

/// All oaths, newest first, optionally only those with one status.
pub async fn list(pool: &PgPool, status: Option<&str>) -> anyhow::Result<Vec<Oath>> {
    if let Some(s) = status {
        if !["active", "expired", "revoked"].contains(&s) {
            return Err(invalid(format!(
                "unknown status {s:?} (use active, expired or revoked)"
            )));
        }
    }
    let sql = format!(
        "SELECT {COLUMNS} FROM oaths WHERE ($1::text IS NULL OR status = $1) ORDER BY id DESC"
    );
    Ok(sqlx::query_as::<_, Oath>(&sql)
        .bind(status)
        .fetch_all(pool)
        .await?)
}

/// Body of `POST /api/v1/oaths`. The `by` field is never taken from the
/// client: it is the name of the API key that made the call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOathBody {
    pub advisory_id: String,
    pub purl: String,
    pub service: String,
    #[serde(default)]
    pub realm: String,
    #[serde(default)]
    pub all_realms: bool,
    pub kind: OathKind,
    pub reason: String,
    #[serde(default)]
    pub until: Option<NaiveDate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendBody {
    pub until: NaiveDate,
}

#[derive(Deserialize)]
struct ListQuery {
    status: Option<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/oaths", get(list_handler).post(create_handler))
        .route("/api/v1/oaths/{id}/revoke", post(revoke_handler))
        .route("/api/v1/oaths/{id}/extend", post(extend_handler))
}

/// Rule violations are the caller's fault (400); anything else is ours (500).
fn api_error(e: anyhow::Error) -> ApiError {
    match e.downcast::<Invalid>() {
        Ok(Invalid(msg)) => ApiError::BadRequest(msg),
        Err(other) => ApiError::Internal(other),
    }
}

async fn create_handler(
    State(state): State<AppState>,
    authed: Authed,
    Json(body): Json<NewOathBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require(&authed, Scope::Admin)?;
    // An empty realm is left for `create` to judge together with all_realms.
    if !body.all_realms && !body.realm.is_empty() && !state.cfg.realms.contains(&body.realm) {
        return Err(ApiError::BadRequest(format!(
            "unknown realm {:?}",
            body.realm
        )));
    }
    let req = NewOath {
        advisory_id: body.advisory_id,
        purl: body.purl,
        service: body.service,
        realm: body.realm,
        all_realms: body.all_realms,
        kind: body.kind,
        reason: body.reason,
        until: body.until,
        by: authed.name,
    };
    let created = create(&state.pool, req).await.map_err(api_error)?;
    Ok(Json(
        serde_json::json!({ "id": created.id, "warning": created.warning }),
    ))
}

async fn list_handler(
    State(state): State<AppState>,
    authed: Authed,
    Query(q): Query<ListQuery>,
) -> Result<Json<Vec<Oath>>, ApiError> {
    require(&authed, Scope::Read)?;
    let oaths = list(&state.pool, q.status.as_deref())
        .await
        .map_err(api_error)?;
    Ok(Json(oaths))
}

async fn revoke_handler(
    State(state): State<AppState>,
    authed: Authed,
    Path(id): Path<i64>,
) -> Result<Json<Oath>, ApiError> {
    require(&authed, Scope::Admin)?;
    let oath = revoke(&state.pool, id, &authed.name)
        .await
        .map_err(api_error)?;
    oath.map(Json).ok_or(ApiError::NotFound)
}

async fn extend_handler(
    State(state): State<AppState>,
    authed: Authed,
    Path(id): Path<i64>,
    Json(body): Json<ExtendBody>,
) -> Result<Json<Oath>, ApiError> {
    require(&authed, Scope::Admin)?;
    let oath = extend(&state.pool, id, body.until, &authed.name)
        .await
        .map_err(api_error)?;
    oath.map(Json).ok_or(ApiError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIN: &str = "pkg:golang/github.com/gin-gonic/gin@v1.9.0";
    const GIN_KEY: &str = "pkg:golang/github.com/gin-gonic/gin";

    fn today() -> NaiveDate {
        Utc::now().date_naive()
    }

    fn req(kind: OathKind) -> NewOath {
        NewOath {
            advisory_id: "GHSA-aaaa-bbbb-cccc".to_string(),
            purl: GIN.to_string(),
            service: "api".to_string(),
            realm: "prod".to_string(),
            all_realms: false,
            kind,
            reason: "not reachable from our handlers".to_string(),
            until: None,
            by: "alice".to_string(),
        }
    }

    fn snooze(days: i64) -> NewOath {
        NewOath {
            until: Some(today() + Duration::days(days)),
            ..req(OathKind::Snooze)
        }
    }

    fn is_invalid(e: &anyhow::Error) -> bool {
        e.downcast_ref::<Invalid>().is_some()
    }

    async fn get(pool: &PgPool, id: i64) -> Oath {
        list(pool, None)
            .await
            .unwrap()
            .into_iter()
            .find(|o| o.id == id)
            .unwrap()
    }

    async fn events(pool: &PgPool, id: i64) -> Vec<(String, String)> {
        sqlx::query_as("SELECT event, by FROM oath_events WHERE oath_id = $1 ORDER BY id")
            .bind(id)
            .fetch_all(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn oath_under_an_alias_is_stored_under_the_advisory(pool: PgPool) {
        sqlx::query(
            "INSERT INTO advisories (id, aliases, severity, source, cve_id) \
             VALUES ('GHSA-aaaa-bbbb-cccc', '{CVE-2026-0042,GO-2026-0042}', 'high', 'osv', \
                     'CVE-2026-0042')",
        )
        .execute(&pool)
        .await
        .unwrap();
        for given in ["CVE-2026-0042", "GO-2026-0042", "GHSA-aaaa-bbbb-cccc"] {
            let r = NewOath {
                advisory_id: given.to_string(),
                ..snooze(7)
            };
            let created = create(&pool, r).await.unwrap();
            assert_eq!(created.warning, None);
            let o = get(&pool, created.id).await;
            assert_eq!(o.advisory_id, "GHSA-aaaa-bbbb-cccc", "filed as {given}");
        }
        let note: Option<String> = sqlx::query_scalar(
            "SELECT note FROM oath_events WHERE event = 'created' ORDER BY id LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(note.unwrap().contains("CVE-2026-0042"));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn oath_for_an_unknown_advisory_warns(pool: PgPool) {
        let r = NewOath {
            advisory_id: "CVE-2099-0001".to_string(),
            ..snooze(7)
        };
        let created = create(&pool, r).await.unwrap();
        assert!(created.warning.unwrap().contains("CVE-2099-0001"));
        assert_eq!(get(&pool, created.id).await.advisory_id, "CVE-2099-0001");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn blank_reason_rejected(pool: PgPool) {
        let r = NewOath {
            reason: "   ".to_string(),
            ..snooze(7)
        };
        let e = create(&pool, r).await.unwrap_err();
        assert!(is_invalid(&e), "{e:#}");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn snooze_requires_future_until(pool: PgPool) {
        for until in [None, Some(today()), Some(today() - Duration::days(1))] {
            let r = NewOath {
                until,
                ..req(OathKind::Snooze)
            };
            let e = create(&pool, r).await.unwrap_err();
            assert!(is_invalid(&e), "until {until:?}: {e:#}");
        }
        let id = create(&pool, snooze(1)).await.unwrap().id;
        let o = get(&pool, id).await;
        assert_eq!(o.status, "active");
        assert_eq!(
            o.expires_at.unwrap(),
            (today() + Duration::days(1))
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn ignore_defaults_review_90_days(pool: PgPool) {
        let before = Utc::now();
        let id = create(&pool, req(OathKind::Ignore)).await.unwrap().id;
        let o = get(&pool, id).await;
        let review = o.review_at.unwrap();
        assert!(review >= before + Duration::days(90));
        assert!(review <= Utc::now() + Duration::days(90));
        assert!(o.expires_at.is_none());

        let r = NewOath {
            until: Some(today() + Duration::days(30)),
            ..req(OathKind::Ignore)
        };
        let id = create(&pool, r).await.unwrap().id;
        let o = get(&pool, id).await;
        assert_eq!(
            o.review_at.unwrap(),
            (today() + Duration::days(30))
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn active_matches_any_version_of_same_name(pool: PgPool) {
        let id = create(&pool, snooze(7)).await.unwrap().id;
        let o = get(&pool, id).await;
        assert_eq!(o.name_key, GIN_KEY);
        assert_eq!(o.version_at_creation, "v1.9.0");
        assert_eq!(
            events(&pool, id).await,
            vec![("created".into(), "alice".into())]
        );

        let hit = active_for(
            &pool,
            "GHSA-aaaa-bbbb-cccc",
            GIN_KEY,
            "api",
            "prod",
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(hit.unwrap().id, id);
        // Other advisory, other component, other service: no match.
        for (adv, key, svc) in [
            ("GHSA-other", GIN_KEY, "api"),
            ("GHSA-aaaa-bbbb-cccc", "pkg:golang/example.com/x", "api"),
            ("GHSA-aaaa-bbbb-cccc", GIN_KEY, "web"),
        ] {
            assert!(active_for(&pool, adv, key, svc, "prod", Utc::now())
                .await
                .unwrap()
                .is_none());
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn expiry_processed_once_after_downtime(pool: PgPool) {
        let snooze_id = create(&pool, snooze(1)).await.unwrap().id;
        let ignore_id = create(&pool, req(OathKind::Ignore)).await.unwrap().id;
        // Not yet due.
        assert!(
            process_expiries(&mut pool.acquire().await.unwrap(), Utc::now())
                .await
                .unwrap()
                .is_empty()
        );

        // Heimdall was down for a while: only the snooze is due 10 days on.
        let later = Utc::now() + Duration::days(10);
        let due = process_expiries(&mut pool.acquire().await.unwrap(), later)
            .await
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, snooze_id);
        assert_eq!(due[0].status, "expired");
        assert!(process_expiries(&mut pool.acquire().await.unwrap(), later)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            events(&pool, snooze_id).await.last().unwrap(),
            &("expired".to_string(), "heimdall".to_string())
        );

        // Ignore comes up for review at 90 days.
        let due = process_expiries(
            &mut pool.acquire().await.unwrap(),
            Utc::now() + Duration::days(91),
        )
        .await
        .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, ignore_id);
        // Expired oaths no longer suppress.
        assert!(active_for(
            &pool,
            "GHSA-aaaa-bbbb-cccc",
            GIN_KEY,
            "api",
            "prod",
            Utc::now()
        )
        .await
        .unwrap()
        .is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn all_realms_oath_applies_everywhere(pool: PgPool) {
        let all = NewOath {
            all_realms: true,
            realm: String::new(),
            ..snooze(7)
        };
        let id = create(&pool, all).await.unwrap().id;
        assert!(get(&pool, id).await.realm.is_none());
        for realm in ["prod", "dev-k3s"] {
            let hit = active_for(
                &pool,
                "GHSA-aaaa-bbbb-cccc",
                GIN_KEY,
                "api",
                realm,
                Utc::now(),
            )
            .await
            .unwrap();
            assert_eq!(hit.unwrap().id, id);
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn per_realm_oath_does_not_leak_to_other_realms(pool: PgPool) {
        let dev = NewOath {
            realm: "dev-k3s".to_string(),
            ..snooze(7)
        };
        create(&pool, dev).await.unwrap();
        assert!(active_for(
            &pool,
            "GHSA-aaaa-bbbb-cccc",
            GIN_KEY,
            "api",
            "prod",
            Utc::now()
        )
        .await
        .unwrap()
        .is_none());
        assert!(active_for(
            &pool,
            "GHSA-aaaa-bbbb-cccc",
            GIN_KEY,
            "api",
            "dev-k3s",
            Utc::now()
        )
        .await
        .unwrap()
        .is_some());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn realm_and_all_realms_are_exclusive(pool: PgPool) {
        let both = NewOath {
            all_realms: true,
            ..snooze(7)
        };
        assert!(is_invalid(&create(&pool, both).await.unwrap_err()));
        let neither = NewOath {
            realm: String::new(),
            ..snooze(7)
        };
        assert!(is_invalid(&create(&pool, neither).await.unwrap_err()));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn revoke_stops_matching_and_records_event(pool: PgPool) {
        let id = create(&pool, snooze(7)).await.unwrap().id;
        let o = revoke(&pool, id, "bob").await.unwrap().unwrap();
        assert_eq!(o.status, "revoked");
        assert!(active_for(
            &pool,
            "GHSA-aaaa-bbbb-cccc",
            GIN_KEY,
            "api",
            "prod",
            Utc::now()
        )
        .await
        .unwrap()
        .is_none());
        assert_eq!(
            events(&pool, id).await.last().unwrap(),
            &("revoked".to_string(), "bob".to_string())
        );
        // Revoking twice is harmless and adds no event.
        revoke(&pool, id, "bob").await.unwrap().unwrap();
        assert_eq!(events(&pool, id).await.len(), 2);
        assert!(revoke(&pool, id + 1000, "bob").await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn extend_reactivates_expired_and_rejects_bad_input(pool: PgPool) {
        let id = create(&pool, snooze(1)).await.unwrap().id;
        process_expiries(
            &mut pool.acquire().await.unwrap(),
            Utc::now() + Duration::days(5),
        )
        .await
        .unwrap();
        assert_eq!(get(&pool, id).await.status, "expired");

        let past = extend(&pool, id, today(), "bob").await.unwrap_err();
        assert!(is_invalid(&past));

        let new_until = today() + Duration::days(30);
        let o = extend(&pool, id, new_until, "bob").await.unwrap().unwrap();
        assert_eq!(o.status, "active");
        assert_eq!(
            o.expires_at.unwrap(),
            new_until.and_hms_opt(0, 0, 0).unwrap().and_utc()
        );
        assert_eq!(
            events(&pool, id).await.last().unwrap(),
            &("extended".to_string(), "bob".to_string())
        );

        revoke(&pool, id, "bob").await.unwrap();
        let e = extend(&pool, id, new_until, "bob").await.unwrap_err();
        assert!(is_invalid(&e));
        assert!(extend(&pool, id + 1000, new_until, "bob")
            .await
            .unwrap()
            .is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn list_filters_by_status(pool: PgPool) {
        let a = create(&pool, snooze(7)).await.unwrap().id;
        let b = create(&pool, req(OathKind::Ignore)).await.unwrap().id;
        revoke(&pool, b, "bob").await.unwrap();
        let active = list(&pool, Some("active")).await.unwrap();
        assert_eq!(active.iter().map(|o| o.id).collect::<Vec<_>>(), vec![a]);
        assert_eq!(list(&pool, None).await.unwrap().len(), 2);
        assert!(is_invalid(&list(&pool, Some("bogus")).await.unwrap_err()));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn lapsed_but_unprocessed_oath_not_active(pool: PgPool) {
        create(&pool, snooze(1)).await.unwrap();
        create(
            &pool,
            NewOath {
                advisory_id: "GHSA-ign".to_string(),
                ..req(OathKind::Ignore)
            },
        )
        .await
        .unwrap();
        let later = Utc::now() + Duration::days(100);
        // process_expiries has not run, yet neither oath suppresses at `later`.
        for adv in ["GHSA-aaaa-bbbb-cccc", "GHSA-ign"] {
            assert!(active_for(&pool, adv, GIN_KEY, "api", "prod", Utc::now())
                .await
                .unwrap()
                .is_some());
            assert!(active_for(&pool, adv, GIN_KEY, "api", "prod", later)
                .await
                .unwrap()
                .is_none());
        }
    }

    mod http {
        use std::sync::Arc;

        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        use super::*;
        use crate::auth::create_key;

        async fn call(
            app: &Router,
            method: &str,
            path: &str,
            key: &str,
            body: serde_json::Value,
        ) -> (StatusCode, serde_json::Value) {
            let req = Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice(&bytes).unwrap_or_default())
        }

        #[sqlx::test(migrations = "./migrations")]
        async fn writes_need_admin_and_record_key_name(pool: PgPool) {
            let mut cfg: crate::config::HeimdallConfig =
                serde_saphyr::from_str("realms: [prod]").unwrap();
            cfg.admins = vec!["alice".to_string()];
            let admins = cfg.admins.clone();
            let state = AppState::new(pool.clone(), Arc::new(cfg), reqwest::Client::new());
            let admin = create_key(&pool, &admins, "alice", Scope::Admin)
                .await
                .unwrap();
            let reader = create_key(&pool, &admins, "viewer", Scope::Read)
                .await
                .unwrap();
            let app = routes().with_state(state);

            let until = (today() + Duration::days(7)).to_string();
            let body = serde_json::json!({
                "advisory_id": "GHSA-aaaa-bbbb-cccc", "purl": GIN, "service": "api",
                "realm": "prod", "kind": "snooze", "reason": "later", "until": until,
            });
            let (s, _) = call(&app, "POST", "/api/v1/oaths", &reader, body.clone()).await;
            assert_eq!(s, StatusCode::FORBIDDEN);
            let (s, v) = call(&app, "POST", "/api/v1/oaths", &admin, body.clone()).await;
            assert_eq!(s, StatusCode::OK);
            let id = v["id"].as_i64().unwrap();
            assert_eq!(get(&pool, id).await.created_by, "alice");

            let mut bad = body.clone();
            bad["reason"] = "".into();
            let (s, _) = call(&app, "POST", "/api/v1/oaths", &admin, bad).await;
            assert_eq!(s, StatusCode::BAD_REQUEST);
            let mut bad = body;
            bad["realm"] = "nowhere".into();
            let (s, _) = call(&app, "POST", "/api/v1/oaths", &admin, bad).await;
            assert_eq!(s, StatusCode::BAD_REQUEST);

            let (s, v) = call(
                &app,
                "GET",
                "/api/v1/oaths?status=active",
                &reader,
                serde_json::json!({}),
            )
            .await;
            assert_eq!(s, StatusCode::OK);
            assert_eq!(v.as_array().unwrap().len(), 1);

            let (s, _) = call(
                &app,
                "POST",
                &format!("/api/v1/oaths/{id}/revoke"),
                &reader,
                serde_json::json!({}),
            )
            .await;
            assert_eq!(s, StatusCode::FORBIDDEN);
            let (s, v) = call(
                &app,
                "POST",
                &format!("/api/v1/oaths/{id}/revoke"),
                &admin,
                serde_json::json!({}),
            )
            .await;
            assert_eq!((s, v["status"].as_str()), (StatusCode::OK, Some("revoked")));
            let (s, _) = call(
                &app,
                "POST",
                "/api/v1/oaths/999999/revoke",
                &admin,
                serde_json::json!({}),
            )
            .await;
            assert_eq!(s, StatusCode::NOT_FOUND);
            let ext = serde_json::json!({ "until": (today() + Duration::days(9)).to_string() });
            let (s, _) = call(
                &app,
                "POST",
                "/api/v1/oaths/999999/extend",
                &admin,
                ext.clone(),
            )
            .await;
            assert_eq!(s, StatusCode::NOT_FOUND);
            // A revoked oath cannot be extended: 400, not 500.
            let (s, _) = call(
                &app,
                "POST",
                &format!("/api/v1/oaths/{id}/extend"),
                &admin,
                ext,
            )
            .await;
            assert_eq!(s, StatusCode::BAD_REQUEST);
        }
    }
}
