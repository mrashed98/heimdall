//! Bifröst: the HTTP routes through which SBOMs, cluster inventory and image
//! SBOMs enter Heimdall.

use std::collections::HashSet;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::{require, Authed, Scope};
pub use crate::error::ApiError;
use crate::ingest::sbom;
use crate::inventory::store::{
    replace_components, store_image_components, upsert_service, InventoryItem,
};
use crate::model::Source;
use crate::purl::name_key;
use crate::AppState;

/// Ingest bodies (SBOMs can be big) are capped at 50 MB.
pub const BODY_LIMIT: usize = 50 * 1024 * 1024;

/// What Sight (the cluster scanner) posts: every service it saw in a realm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterInventory {
    pub realm: String,
    pub services: Vec<ClusterService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterService {
    pub name: String,
    pub items: Vec<ClusterItem>,
}

/// Wire form of `InventoryItem` (which is a plain store type, not serde).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterItem {
    pub purl: String,
    #[serde(default)]
    pub cpes: Vec<String>,
    #[serde(default)]
    pub direct: bool,
    #[serde(default)]
    pub via_image_digest: Option<String>,
}

/// Where an SBOM upload belongs. Shared with the gate (Hofund).
#[derive(Debug, Clone, Deserialize)]
pub struct SbomQuery {
    pub service: String,
    pub realm: String,
    pub branch: String,
    pub default_branch: String,
}

/// What one SBOM upload did to the inventory.
#[derive(Debug, Clone)]
pub struct IngestOutcome {
    pub source: Source,
    pub added: usize,
    pub removed: usize,
    pub skipped_without_purl: usize,
    /// Every component purl in the SBOM, in SBOM order.
    pub purls: Vec<String>,
}

#[derive(Deserialize)]
struct SbomUpload {
    sbom: serde_json::Value,
    #[serde(default)]
    direct: Vec<String>,
}

#[derive(Deserialize)]
struct ImageQuery {
    image_ref: String,
}

#[derive(Serialize)]
struct PendingImage {
    digest: String,
    image_ref: String,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/ingest/sbom", post(ingest_sbom))
        .route("/api/v1/ingest/cluster", post(ingest_cluster))
        .route("/api/v1/ingest/image/{digest}", post(ingest_image))
        .route("/api/v1/images/pending", get(pending_images))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
}

fn check_realm(state: &AppState, realm: &str) -> Result<(), ApiError> {
    if state.cfg.realms.iter().any(|r| r == realm) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!("unknown realm {realm:?}")))
    }
}

/// The body is taken as raw bytes and parsed by hand so every malformed
/// body is a 400 with our own message.
async fn ingest_sbom(
    State(state): State<AppState>,
    authed: Authed,
    Query(q): Query<SbomQuery>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    require(&authed, Scope::Ingest)?;
    let out = ingest_sbom_inner(&state, &q, &body).await?;
    Ok(Json(serde_json::json!({
        "source": out.source,
        "added": out.added,
        "removed": out.removed,
        "skipped_without_purl": out.skipped_without_purl,
    })))
}

/// The SBOM upload itself, shared by `/ingest/sbom` and the gate: check the
/// realm, parse `{"sbom": ..., "direct": [...]}` and replace the service's
/// git (default branch) or ci component set. The caller checks the scope.
pub async fn ingest_sbom_inner(
    state: &AppState,
    q: &SbomQuery,
    body: &[u8],
) -> Result<IngestOutcome, ApiError> {
    check_realm(state, &q.realm)?;
    let upload: SbomUpload = serde_json::from_slice(body)
        .map_err(|e| ApiError::BadRequest(format!("invalid body: {e}")))?;
    // Re-serialize the embedded object so the one SBOM parser is used everywhere.
    let sbom_bytes = serde_json::to_vec(&upload.sbom).map_err(anyhow::Error::from)?;
    let parsed = sbom::parse(&sbom_bytes).map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;

    let direct: HashSet<&str> = upload.direct.iter().map(|s| s.as_str()).collect();
    let purls: Vec<String> = parsed.components.iter().map(|c| c.purl.clone()).collect();
    let items: Vec<InventoryItem> = parsed
        .components
        .into_iter()
        .map(|c| InventoryItem {
            direct: name_key(&c.purl).is_ok_and(|k| direct.contains(k.as_str())),
            purl: c.purl,
            cpes: c.cpes,
            via_image_digest: None,
        })
        .collect();

    let source = if q.branch == q.default_branch {
        Source::Git
    } else {
        Source::Ci
    };
    let service_id = upsert_service(&state.pool, &q.realm, &q.service).await?;
    let report = replace_components(&state.pool, service_id, source, &items).await?;
    Ok(IngestOutcome {
        source,
        added: report.added,
        removed: report.removed,
        skipped_without_purl: parsed.skipped_without_purl,
        purls,
    })
}

async fn ingest_cluster(
    State(state): State<AppState>,
    authed: Authed,
    Json(inv): Json<ClusterInventory>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require(&authed, Scope::Ingest)?;
    let out = ingest_cluster_inner(&state, &inv).await?;
    Ok(Json(serde_json::json!({
        "services": out.services,
        "added": out.added,
        "removed": out.removed,
    })))
}

/// What one cluster inventory did to the inventory.
#[derive(Debug, Clone)]
pub struct ClusterOutcome {
    pub services: usize,
    pub added: usize,
    pub removed: usize,
}

/// The cluster ingest itself, shared by `/ingest/cluster` and Sight's
/// in-process mode: check the realm, replace each reported service's cluster
/// component set and empty the ones that vanished. The caller checks the scope.
pub async fn ingest_cluster_inner(
    state: &AppState,
    inv: &ClusterInventory,
) -> Result<ClusterOutcome, ApiError> {
    check_realm(state, &inv.realm)?;

    let mut added = 0;
    let mut removed = 0;
    let mut listed: HashSet<String> = HashSet::new();
    for svc in &inv.services {
        listed.insert(svc.name.clone());
        let items: Vec<InventoryItem> = svc
            .items
            .iter()
            .map(|i| InventoryItem {
                purl: i.purl.clone(),
                cpes: i.cpes.clone(),
                direct: i.direct,
                via_image_digest: i.via_image_digest.clone(),
            })
            .collect();
        let id = upsert_service(&state.pool, &inv.realm, &svc.name).await?;
        let r = replace_components(&state.pool, id, Source::Cluster, &items).await?;
        added += r.added;
        removed += r.removed;
    }

    // Services that still have cluster rows but were not reported have left
    // the cluster: replace their cluster set with nothing.
    let known: Vec<(i64, String)> = sqlx::query_as(
        "SELECT DISTINCT s.id, s.name FROM services s \
         JOIN service_components sc ON sc.service_id = s.id \
         WHERE s.realm = $1 AND sc.source = 'cluster'",
    )
    .bind(&inv.realm)
    .fetch_all(&state.pool)
    .await?;
    for (id, name) in known {
        if !listed.contains(&name) {
            let r = replace_components(&state.pool, id, Source::Cluster, &[]).await?;
            removed += r.removed;
        }
    }

    Ok(ClusterOutcome {
        services: inv.services.len(),
        added,
        removed,
    })
}

/// `sha256:` followed by 64 hex characters.
fn is_valid_digest(d: &str) -> bool {
    d.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

async fn ingest_image(
    State(state): State<AppState>,
    authed: Authed,
    Path(digest): Path<String>,
    Query(q): Query<ImageQuery>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    require(&authed, Scope::Ingest)?;
    if !is_valid_digest(&digest) {
        return Err(ApiError::BadRequest(
            "digest must be sha256:<64 hex characters>".into(),
        ));
    }
    let parsed = sbom::parse(&body).map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    let components: Vec<(String, Vec<String>)> = parsed
        .components
        .into_iter()
        .map(|c| (c.purl, c.cpes))
        .collect();
    store_image_components(&state.pool, &digest, &q.image_ref, &components).await?;
    Ok(Json(serde_json::json!({
        "digest": digest,
        "components": components.len(),
        "skipped_without_purl": parsed.skipped_without_purl,
    })))
}

async fn pending_images(
    State(state): State<AppState>,
    authed: Authed,
) -> Result<Json<Vec<PendingImage>>, ApiError> {
    require(&authed, Scope::Ingest)?;
    let rows = crate::inventory::store::pending_image_digests(&state.pool).await?;
    Ok(Json(
        rows.into_iter()
            .map(|(digest, image_ref)| PendingImage { digest, image_ref })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use http_body_util::BodyExt;
    use sqlx::PgPool;
    use tower::ServiceExt;

    use crate::auth::{create_key, Scope};
    use crate::config::HeimdallConfig;
    use crate::inventory::store::effective_components;
    use crate::{server, AppState};

    const GOOD: &str = include_str!("../../tests/fixtures/sbom/go-service.cdx.json");

    async fn setup(pool: PgPool) -> (Router, String, PgPool) {
        let key = create_key(&pool, &[], "ci", Scope::Ingest).await.unwrap();
        let cfg = HeimdallConfig::load(std::path::Path::new("heimdall.example.yaml")).unwrap();
        let state = AppState {
            pool: pool.clone(),
            cfg: Arc::new(cfg),
            http: reqwest::Client::new(),
        };
        (server::router(state), key, pool)
    }

    async fn call(
        app: &Router,
        key: &str,
        method: &str,
        uri: &str,
        body: Vec<u8>,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {key}"))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    fn sbom_body(direct: &[&str]) -> Vec<u8> {
        let sbom: serde_json::Value = serde_json::from_str(GOOD).unwrap();
        serde_json::to_vec(&serde_json::json!({ "sbom": sbom, "direct": direct })).unwrap()
    }

    fn sbom_uri(branch: &str) -> String {
        format!("/api/v1/ingest/sbom?service=api&realm=dev-k3s&branch={branch}&default_branch=main")
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn default_branch_upload_is_git(pool: PgPool) {
        let (app, key, _) = setup(pool).await;
        let (st, body) = call(&app, &key, "POST", &sbom_uri("main"), sbom_body(&[])).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["source"], "git");
        assert!(body["added"].as_u64().unwrap() > 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn feature_branch_upload_is_ci(pool: PgPool) {
        let (app, key, pool) = setup(pool).await;
        let (st, body) = call(&app, &key, "POST", &sbom_uri("feat-x"), sbom_body(&[])).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["source"], "ci");
        // CI uploads never count as effective inventory.
        assert!(effective_components(&pool, "dev-k3s")
            .await
            .unwrap()
            .is_empty());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn malformed_sbom_400_and_inventory_untouched(pool: PgPool) {
        let (app, key, pool) = setup(pool).await;
        let (st, _) = call(&app, &key, "POST", &sbom_uri("main"), sbom_body(&[])).await;
        assert_eq!(st, StatusCode::OK);
        let before = effective_components(&pool, "dev-k3s").await.unwrap().len();
        assert!(before > 0);
        let (st, _) = call(&app, &key, "POST", &sbom_uri("main"), b"{not json".to_vec()).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // Valid envelope, but the sbom inside is not CycloneDX.
        let bad = br#"{"sbom":{"hello":1},"direct":[]}"#.to_vec();
        let (st, _) = call(&app, &key, "POST", &sbom_uri("main"), bad).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let after = effective_components(&pool, "dev-k3s").await.unwrap().len();
        assert_eq!(before, after);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn unknown_realm_and_missing_params_400(pool: PgPool) {
        let (app, key, _) = setup(pool).await;
        let uri = "/api/v1/ingest/sbom?service=api&realm=nope&branch=main&default_branch=main";
        let (st, _) = call(&app, &key, "POST", uri, sbom_body(&[])).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, _) = call(
            &app,
            &key,
            "POST",
            "/api/v1/ingest/sbom?service=api",
            sbom_body(&[]),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn direct_flag_follows_direct_list(pool: PgPool) {
        let (app, key, pool) = setup(pool).await;
        let parsed = crate::ingest::sbom::parse(GOOD.as_bytes()).unwrap();
        let first = crate::purl::name_key(&parsed.components[0].purl).unwrap();
        call(
            &app,
            &key,
            "POST",
            &sbom_uri("main"),
            sbom_body(&[first.as_str()]),
        )
        .await;
        let eff = effective_components(&pool, "dev-k3s").await.unwrap();
        let direct: Vec<_> = eff.iter().filter(|e| e.direct).collect();
        assert!(!direct.is_empty());
        assert!(direct.iter().all(|e| e.name_key == first));
        assert!(eff.iter().any(|e| !e.direct));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn oversized_body_413(pool: PgPool) {
        let (app, key, _) = setup(pool).await;
        let big = vec![b' '; 51 * 1024 * 1024];
        let (st, _) = call(&app, &key, "POST", &sbom_uri("main"), big).await;
        assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn ingest_requires_ingest_scope(pool: PgPool) {
        let (app, _, pool) = setup(pool).await;
        let read = create_key(&pool, &[], "viewer", Scope::Read).await.unwrap();
        let (st, _) = call(&app, &read, "POST", &sbom_uri("main"), sbom_body(&[])).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        let (st, _) = call(&app, &read, "GET", "/api/v1/images/pending", vec![]).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    fn cluster_body(services: &[&str]) -> Vec<u8> {
        let services: Vec<_> = services
            .iter()
            .map(|n| {
                serde_json::json!({ "name": n, "items": [
                    { "purl": "pkg:npm/left-pad@1.0.0", "cpes": [],
                      "direct": true, "via_image_digest": null }
                ]})
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({ "realm": "dev-k3s", "services": services }))
            .unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn cluster_ingest_empties_vanished_services(pool: PgPool) {
        let (app, key, pool) = setup(pool).await;
        let uri = "/api/v1/ingest/cluster";
        let (st, _) = call(&app, &key, "POST", uri, cluster_body(&["web", "worker"])).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(
            effective_components(&pool, "dev-k3s").await.unwrap().len(),
            2
        );
        // `worker` vanished from the cluster.
        let (st, body) = call(&app, &key, "POST", uri, cluster_body(&["web"])).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["removed"], 1);
        let eff = effective_components(&pool, "dev-k3s").await.unwrap();
        assert_eq!(eff.len(), 1);
        assert_eq!(eff[0].service, "web");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn image_sbom_stored_and_pending_listed(pool: PgPool) {
        let (app, key, pool) = setup(pool).await;
        let digest = format!("sha256:{}", "a".repeat(64));
        // A cluster item references the image, so it is pending.
        let purl = "pkg:oci/app@sha256%3Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?repository_url=reg.example/app";
        let cluster = serde_json::to_vec(&serde_json::json!({
            "realm": "dev-k3s",
            "services": [{ "name": "web", "items": [
                { "purl": purl, "cpes": [], "direct": true, "via_image_digest": digest }
            ]}]
        }))
        .unwrap();
        call(&app, &key, "POST", "/api/v1/ingest/cluster", cluster).await;
        let (st, pending) = call(&app, &key, "GET", "/api/v1/images/pending", vec![]).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(pending[0]["digest"], digest.as_str());
        assert!(pending[0]["image_ref"].as_str().unwrap().ends_with(&digest));

        let uri = format!("/api/v1/ingest/image/{digest}?image_ref=reg.example/app");
        let (st, _) = call(&app, &key, "POST", &uri, GOOD.as_bytes().to_vec()).await;
        assert_eq!(st, StatusCode::OK);
        let n: i64 = sqlx::query_scalar("select count(*) from image_components where digest = $1")
            .bind(&digest)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(n > 0);
        let (_, pending) = call(&app, &key, "GET", "/api/v1/images/pending", vec![]).await;
        assert_eq!(pending.as_array().unwrap().len(), 0);

        let (st, _) = call(
            &app,
            &key,
            "POST",
            "/api/v1/ingest/image/not-a-digest?image_ref=x",
            GOOD.as_bytes().to_vec(),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }
}
