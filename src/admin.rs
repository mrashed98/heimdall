//! User administration and the audit log.
use crate::{
    error::ApiError,
    local_auth::{Grant, Principal},
    AppState,
};
use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/users", get(users))
        .route("/api/v1/users/{id}", axum::routing::patch(update_user))
        .route("/api/v1/users/{id}/grants", get(grants).put(replace_grants))
        .route("/api/v1/audit", get(audit))
}
fn require_admin(p: &Principal) -> Result<(), ApiError> {
    if p.can("admin", "*") {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}
pub(crate) async fn record(
    conn: &mut PgConnection,
    actor: &str,
    action: &str,
    detail: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO audit_log (username, action, detail) VALUES ($1,$2,$3)")
        .bind(actor)
        .bind(action)
        .bind(detail)
        .execute(conn)
        .await?;
    Ok(())
}
async fn db_grants(pool: &PgPool, id: i64) -> Result<Vec<Grant>, sqlx::Error> {
    sqlx::query_as("SELECT role, realm FROM user_grants WHERE user_id=$1 ORDER BY role, realm")
        .bind(id)
        .fetch_all(pool)
        .await
}
#[derive(Serialize, sqlx::FromRow)]
struct User {
    id: i64,
    kind: String,
    name: String,
    email: Option<String>,
    disabled: bool,
    last_login_at: Option<DateTime<Utc>>,
    #[sqlx(skip)]
    grants: Vec<Grant>,
}
async fn users(State(s): State<AppState>, p: Principal) -> Result<Json<Vec<User>>, ApiError> {
    require_admin(&p)?;
    let mut users: Vec<User> = sqlx::query_as(
        "SELECT id, kind, username AS name, email, disabled, last_login_at FROM users ORDER BY id",
    )
    .fetch_all(&s.pool)
    .await?;
    for u in &mut users {
        u.grants = db_grants(&s.pool, u.id).await?;
    }
    Ok(Json(users))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserUpdate {
    disabled: bool,
}
async fn update_user(
    State(s): State<AppState>,
    p: Principal,
    Path(id): Path<i64>,
    Json(body): Json<UserUpdate>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&p)?;
    let mut tx = s.pool.begin().await?;
    let name: Option<String> =
        sqlx::query_scalar("UPDATE users SET disabled=$2 WHERE id=$1 RETURNING username")
            .bind(id)
            .bind(body.disabled)
            .fetch_optional(&mut *tx)
            .await?;
    let name = name.ok_or(ApiError::NotFound)?;
    if body.disabled {
        sqlx::query("DELETE FROM sessions WHERE user_id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    record(
        &mut tx,
        &p.name,
        if body.disabled {
            "user_disabled"
        } else {
            "user_enabled"
        },
        serde_json::json!({"user_id":id,"name":name}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({"id":id,"disabled":body.disabled})))
}
async fn grants(
    State(s): State<AppState>,
    p: Principal,
    Path(id): Path<i64>,
) -> Result<Json<Vec<Grant>>, ApiError> {
    require_admin(&p)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)")
        .bind(id)
        .fetch_one(&s.pool)
        .await?;
    if !exists {
        return Err(ApiError::NotFound);
    }
    Ok(Json(db_grants(&s.pool, id).await?))
}
async fn replace_grants(
    State(s): State<AppState>,
    p: Principal,
    Path(id): Path<i64>,
    Json(mut new): Json<Vec<Grant>>,
) -> Result<Json<Vec<Grant>>, ApiError> {
    require_admin(&p)?;
    let mut tx = s.pool.begin().await?;
    let identity: Option<(String, Option<String>, String, Option<String>)> = sqlx::query_as(
        "SELECT username, email, kind, preferred_username FROM users WHERE id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let (name, email, kind, preferred) = identity.ok_or(ApiError::NotFound)?;
    let admin_allowed = if kind == "oidc" {
        preferred.as_ref().is_some_and(|n| s.cfg.admins.contains(n))
            || email.as_ref().is_some_and(|e| s.cfg.admins.contains(e))
    } else {
        s.cfg.admins.contains(&name)
    };
    for g in &new {
        if !["viewer", "editor", "admin"].contains(&g.role.as_str()) {
            return Err(ApiError::BadRequest("invalid_role".into()));
        }
        if g.realm != "*" && !s.cfg.realms.contains(&g.realm) {
            return Err(ApiError::BadRequest("invalid_realm".into()));
        }
        if g.role == "admin" && !admin_allowed {
            return Err(ApiError::BadRequest("admin_not_allowed".into()));
        }
    }
    new.sort_by(|a, b| (&a.role, &a.realm).cmp(&(&b.role, &b.realm)));
    new.dedup();
    let old: Vec<Grant> =
        sqlx::query_as("SELECT role,realm FROM user_grants WHERE user_id=$1 ORDER BY role,realm")
            .bind(id)
            .fetch_all(&mut *tx)
            .await?;
    sqlx::query("DELETE FROM user_grants WHERE user_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    for g in &new {
        sqlx::query("INSERT INTO user_grants(user_id,role,realm) VALUES ($1,$2,$3)")
            .bind(id)
            .bind(&g.role)
            .bind(&g.realm)
            .execute(&mut *tx)
            .await?;
    }
    record(
        &mut tx,
        &p.name,
        "grants_replaced",
        serde_json::json!({"user_id":id,"name":name,"old":old,"new":new}),
    )
    .await?;
    tx.commit().await?;
    s.grants_cache.invalidate(id);
    Ok(Json(new))
}
#[derive(Deserialize)]
struct AuditQuery {
    actor: Option<String>,
    action: Option<String>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    limit: Option<i64>,
    offset: Option<i64>,
}
#[derive(Serialize, sqlx::FromRow)]
struct AuditRow {
    id: i64,
    occurred_at: DateTime<Utc>,
    action: String,
    actor: Option<String>,
    method: Option<String>,
    ip: Option<String>,
    detail: Option<serde_json::Value>,
}
async fn audit(
    State(s): State<AppState>,
    p: Principal,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Vec<AuditRow>>, ApiError> {
    require_admin(&p)?;
    let limit = q.limit.unwrap_or(100).clamp(0, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let rows = sqlx::query_as("SELECT id,occurred_at,action,username AS actor,method,ip,detail FROM audit_log WHERE ($1::text IS NULL OR username=$1) AND ($2::text IS NULL OR action=$2) AND ($3::timestamptz IS NULL OR occurred_at >= $3) AND ($4::timestamptz IS NULL OR occurred_at <= $4) ORDER BY occurred_at DESC,id DESC LIMIT $5 OFFSET $6")
        .bind(q.actor).bind(q.action).bind(q.since).bind(q.until).bind(limit).bind(offset).fetch_all(&s.pool).await?;
    Ok(Json(rows))
}
