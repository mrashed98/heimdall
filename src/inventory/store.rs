//! Inventory store: which components each service uses, per source.

use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;

use anyhow::Context;
use packageurl::PackageUrl;
use sqlx::{FromRow, PgConnection, PgPool};

use crate::config::DeclaredComponent;
use crate::model::Source;
use crate::purl::name_key;

#[derive(Debug, Clone)]
pub struct InventoryItem {
    pub purl: String,
    pub cpes: Vec<String>,
    pub direct: bool,
    pub via_image_digest: Option<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReplaceReport {
    pub added: usize,
    pub removed: usize,
}

#[derive(Debug, Clone, FromRow)]
pub struct EffectiveComponent {
    pub service_id: i64,
    pub service: String,
    pub component_id: i64,
    pub purl: String,
    pub name_key: String,
    pub direct: bool,
}

/// Find or create a service; returns its id.
pub async fn upsert_service(pool: &PgPool, realm: &str, name: &str) -> anyhow::Result<i64> {
    // DO UPDATE (a no-op write) so RETURNING yields the id on conflict too.
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO services (realm, name) VALUES ($1, $2) \
         ON CONFLICT (realm, name) DO UPDATE SET name = EXCLUDED.name \
         RETURNING id",
    )
    .bind(realm)
    .bind(name)
    .fetch_one(pool)
    .await
    .context("upsert service")?;
    Ok(id)
}

/// Insert a component by purl, unioning any new CPEs into the stored ones.
async fn upsert_component(
    conn: &mut PgConnection,
    purl: &str,
    cpes: &[String],
) -> anyhow::Result<i64> {
    let key = name_key(purl)?;
    let parsed = PackageUrl::from_str(purl).with_context(|| format!("invalid purl {purl}"))?;
    let ecosystem = parsed.ty().to_string();
    let version = parsed.version().unwrap_or("").to_string();
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO components (purl, name_key, ecosystem, version, cpes) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (purl) DO UPDATE SET cpes = ARRAY( \
             SELECT DISTINCT c FROM unnest(components.cpes || EXCLUDED.cpes) AS c ORDER BY c) \
         RETURNING id",
    )
    .bind(purl)
    .bind(key)
    .bind(ecosystem)
    .bind(version)
    .bind(cpes)
    .fetch_one(&mut *conn)
    .await
    .with_context(|| format!("upsert component {purl}"))?;
    Ok(id)
}

/// Make `items` the full set for (service, source), in one transaction.
/// Existing rows are updated in place (not deleted and reinserted) so
/// `declared_since` survives; rows not in `items` are deleted.
pub async fn replace_components(
    pool: &PgPool,
    service_id: i64,
    source: Source,
    items: &[InventoryItem],
) -> anyhow::Result<ReplaceReport> {
    let mut tx = pool.begin().await?;

    let existing: Vec<(i64,)> = sqlx::query_as(
        "SELECT component_id FROM service_components WHERE service_id = $1 AND source = $2",
    )
    .bind(service_id)
    .bind(source)
    .fetch_all(&mut *tx)
    .await?;
    let existing: HashSet<i64> = existing.into_iter().map(|(id,)| id).collect();

    let mut kept: HashSet<i64> = HashSet::new();
    let mut added = 0;
    for item in items {
        let component_id = upsert_component(&mut tx, &item.purl, &item.cpes).await?;
        // Two items can share a purl; the later one wins, but it counts once.
        if kept.insert(component_id) && !existing.contains(&component_id) {
            added += 1;
        }
        sqlx::query(
            "INSERT INTO service_components \
                 (service_id, component_id, source, direct, via_image_digest) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (service_id, component_id, source) DO UPDATE SET \
                 direct = EXCLUDED.direct, \
                 via_image_digest = EXCLUDED.via_image_digest, \
                 uploaded_at = now()",
        )
        .bind(service_id)
        .bind(component_id)
        .bind(source)
        .bind(item.direct)
        .bind(&item.via_image_digest)
        .execute(&mut *tx)
        .await?;
    }

    let kept: Vec<i64> = kept.into_iter().collect();
    let removed = sqlx::query(
        "DELETE FROM service_components \
         WHERE service_id = $1 AND source = $2 AND component_id <> ALL($3)",
    )
    .bind(service_id)
    .bind(source)
    .bind(&kept)
    .execute(&mut *tx)
    .await?
    .rows_affected() as usize;

    tx.commit().await?;
    Ok(ReplaceReport { added, removed })
}

/// Record an image's SBOM: the image row plus its components.
pub async fn store_image_sbom(
    pool: &PgPool,
    digest: &str,
    image_ref: &str,
    purls: &[String],
) -> anyhow::Result<()> {
    let components: Vec<(String, Vec<String>)> =
        purls.iter().map(|p| (p.clone(), Vec::new())).collect();
    store_image_components(pool, digest, image_ref, &components).await
}

/// Same as `store_image_sbom`, but each component is a (purl, cpes) pair so
/// the SBOM's CPEs are unioned onto the stored components.
pub async fn store_image_components(
    pool: &PgPool,
    digest: &str,
    image_ref: &str,
    components: &[(String, Vec<String>)],
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO image_sboms (digest, image_ref) VALUES ($1, $2) \
         ON CONFLICT (digest) DO UPDATE SET image_ref = EXCLUDED.image_ref, scanned_at = now()",
    )
    .bind(digest)
    .bind(image_ref)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM image_components WHERE digest = $1")
        .bind(digest)
        .execute(&mut *tx)
        .await?;
    for (purl, cpes) in components {
        let component_id = upsert_component(&mut tx, purl, cpes).await?;
        sqlx::query(
            "INSERT INTO image_components (digest, component_id) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(digest)
        .bind(component_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Image digests that services reference but that have no SBOM yet, each with
/// a pullable reference `{repository_url}@{digest}`. The repository comes from
/// the `repository_url` qualifier of a referencing `pkg:oci` purl; digests
/// with no such purl are skipped with a warning.
pub async fn pending_image_digests(pool: &PgPool) -> anyhow::Result<Vec<(String, String)>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT sc.via_image_digest, c.purl \
         FROM service_components sc \
         JOIN components c ON c.id = sc.component_id \
         WHERE sc.via_image_digest IS NOT NULL \
           AND NOT EXISTS (SELECT 1 FROM image_sboms i WHERE i.digest = sc.via_image_digest) \
         ORDER BY sc.via_image_digest, c.purl",
    )
    .fetch_all(pool)
    .await?;

    // Rows are sorted by purl within a digest, so the first usable one is
    // deterministic.
    let mut by_digest: BTreeMap<String, Option<String>> = BTreeMap::new();
    for (digest, purl) in rows {
        let entry = by_digest.entry(digest.clone()).or_insert(None);
        if entry.is_none() {
            *entry = oci_repository(&purl).map(|repo| format!("{repo}@{digest}"));
        }
    }

    let mut out = Vec::new();
    for (digest, image_ref) in by_digest {
        match image_ref {
            Some(r) => out.push((digest, r)),
            None => eprintln!(
                "warning: no pkg:oci purl with repository_url references {digest}; skipping"
            ),
        }
    }
    Ok(out)
}

/// The `repository_url` qualifier of a `pkg:oci` purl, if present.
fn oci_repository(purl: &str) -> Option<String> {
    let parsed = PackageUrl::from_str(purl).ok()?;
    if parsed.ty() != "oci" {
        return None;
    }
    // The parser percent-decodes qualifier values.
    parsed
        .qualifiers()
        .get("repository_url")
        .map(|v| v.to_string())
}

/// Apply declared components: one replace (source declared) per service.
pub async fn sync_declared(pool: &PgPool, declared: &[DeclaredComponent]) -> anyhow::Result<()> {
    let mut by_service: BTreeMap<(String, String), Vec<InventoryItem>> = BTreeMap::new();
    for d in declared {
        by_service
            .entry((d.realm.clone(), d.service.clone()))
            .or_default()
            .push(InventoryItem {
                purl: d.purl.clone(),
                cpes: vec![],
                direct: true,
                via_image_digest: None,
            });
    }
    let mut kept_services: Vec<i64> = Vec::new();
    for ((realm, service), items) in by_service {
        let service_id = upsert_service(pool, &realm, &service).await?;
        replace_components(pool, service_id, Source::Declared, &items).await?;
        kept_services.push(service_id);
    }
    // Services dropped from the declared list lose their declared rows
    // (an empty list clears them all).
    sqlx::query(
        "DELETE FROM service_components WHERE source = 'declared' AND service_id <> ALL($1)",
    )
    .bind(&kept_services)
    .execute(pool)
    .await?;
    Ok(())
}

/// What a realm actually runs: direct rows from git/cluster/declared (CI is
/// excluded) plus the components of images those rows reference. A component
/// reached by several routes appears once, direct if any route is direct.
/// Takes any executor (pool or open transaction) so the matcher can read it
/// inside its transaction.
pub async fn effective_components(
    db: impl sqlx::PgExecutor<'_>,
    realm: &str,
) -> anyhow::Result<Vec<EffectiveComponent>> {
    let rows = sqlx::query_as(
        "SELECT service_id, service, component_id, purl, name_key, bool_or(direct) AS direct \
         FROM ( \
             SELECT s.id AS service_id, s.name AS service, c.id AS component_id, \
                    c.purl, c.name_key, sc.direct \
             FROM service_components sc \
             JOIN services s ON s.id = sc.service_id \
             JOIN components c ON c.id = sc.component_id \
             WHERE s.realm = $1 AND sc.source IN ('git', 'cluster', 'declared') \
           UNION ALL \
             SELECT s.id, s.name, c.id, c.purl, c.name_key, false \
             FROM service_components sc \
             JOIN services s ON s.id = sc.service_id \
             JOIN image_components ic ON ic.digest = sc.via_image_digest \
             JOIN components c ON c.id = ic.component_id \
             WHERE s.realm = $1 AND sc.source IN ('git', 'cluster', 'declared') \
         ) routes \
         GROUP BY service_id, service, component_id, purl, name_key \
         ORDER BY service, purl",
    )
    .bind(realm)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sqlx::PgPool;

    use super::*;

    fn item(purl: &str) -> InventoryItem {
        InventoryItem {
            purl: purl.to_string(),
            cpes: vec![],
            direct: true,
            via_image_digest: None,
        }
    }

    async fn effective_purls(pool: &PgPool, realm: &str) -> BTreeSet<String> {
        effective_components(pool, realm)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.purl)
            .collect()
    }

    fn set(purls: &[&str]) -> BTreeSet<String> {
        purls.iter().map(|p| p.to_string()).collect()
    }

    const A: &str = "pkg:npm/a@1.0.0";
    const B: &str = "pkg:npm/b@1.0.0";
    const C: &str = "pkg:npm/c@1.0.0";

    #[sqlx::test(migrations = "./migrations")]
    async fn replace_removes_missing_and_keeps_other_sources(pool: PgPool) {
        let svc = upsert_service(&pool, "prod", "api").await.unwrap();
        replace_components(&pool, svc, Source::Git, &[item(A), item(B)])
            .await
            .unwrap();
        replace_components(&pool, svc, Source::Cluster, &[item(C)])
            .await
            .unwrap();
        let report = replace_components(&pool, svc, Source::Git, &[item(A)])
            .await
            .unwrap();
        assert_eq!(report.removed, 1);
        assert_eq!(report.added, 0);
        assert_eq!(effective_purls(&pool, "prod").await, set(&[A, C]));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn ci_source_not_effective(pool: PgPool) {
        let svc = upsert_service(&pool, "prod", "api").await.unwrap();
        replace_components(&pool, svc, Source::Ci, &[item("pkg:npm/x@1.0.0")])
            .await
            .unwrap();
        assert!(effective_purls(&pool, "prod").await.is_empty());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn image_components_reach_service(pool: PgPool) {
        let svc = upsert_service(&pool, "prod", "api").await.unwrap();
        let image = InventoryItem {
            purl: "pkg:oci/app@sha256%3Ad1?repository_url=ghcr.io/o/app".to_string(),
            cpes: vec![],
            direct: true,
            via_image_digest: Some("sha256:d1".to_string()),
        };
        replace_components(&pool, svc, Source::Cluster, &[image])
            .await
            .unwrap();
        let pending = pending_image_digests(&pool).await.unwrap();
        assert_eq!(
            pending,
            vec![(
                "sha256:d1".to_string(),
                "ghcr.io/o/app@sha256:d1".to_string()
            )]
        );

        let openssl = "pkg:deb/debian/openssl@3.0.11?distro=debian-12".to_string();
        store_image_sbom(
            &pool,
            "sha256:d1",
            "ghcr.io/o/app:1",
            std::slice::from_ref(&openssl),
        )
        .await
        .unwrap();
        assert!(pending_image_digests(&pool).await.unwrap().is_empty());

        let eff = effective_components(&pool, "prod").await.unwrap();
        let hit = eff.iter().find(|e| e.purl == openssl).unwrap();
        assert_eq!(hit.service_id, svc);
        assert_eq!(hit.service, "api");
        assert!(!hit.direct);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn declared_since_kept_on_replace(pool: PgPool) {
        let svc = upsert_service(&pool, "prod", "api").await.unwrap();
        replace_components(&pool, svc, Source::Git, &[item(A), item(B)])
            .await
            .unwrap();
        sqlx::query(
            "UPDATE service_components SET declared_since = '2020-01-01T00:00:00Z', \
             uploaded_at = '2020-01-01T00:00:00Z'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let report = replace_components(&pool, svc, Source::Git, &[item(A)])
            .await
            .unwrap();
        assert_eq!((report.added, report.removed), (0, 1));
        let (kept, refreshed): (bool, bool) = sqlx::query_as(
            "SELECT declared_since = '2020-01-01T00:00:00Z', uploaded_at > '2020-01-01T00:00:00Z' \
             FROM service_components",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(kept, "declared_since must survive a replace");
        assert!(refreshed, "uploaded_at should be refreshed");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn cpes_are_unioned(pool: PgPool) {
        let s1 = upsert_service(&pool, "prod", "api").await.unwrap();
        let s2 = upsert_service(&pool, "prod", "web").await.unwrap();
        let mut one = item(A);
        one.cpes = vec!["cpe:2.3:a:x:a:*".into(), "cpe:2.3:a:y:a:*".into()];
        let mut two = item(A);
        two.cpes = vec!["cpe:2.3:a:y:a:*".into(), "cpe:2.3:a:z:a:*".into()];
        replace_components(&pool, s1, Source::Git, &[one])
            .await
            .unwrap();
        replace_components(&pool, s2, Source::Git, &[two])
            .await
            .unwrap();
        let (cpes,): (Vec<String>,) = sqlx::query_as("SELECT cpes FROM components WHERE purl = $1")
            .bind(A)
            .fetch_one(&pool)
            .await
            .unwrap();
        let got: BTreeSet<String> = cpes.into_iter().collect();
        assert_eq!(
            got,
            set(&["cpe:2.3:a:x:a:*", "cpe:2.3:a:y:a:*", "cpe:2.3:a:z:a:*"])
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn component_via_two_routes_returned_once_direct_wins(pool: PgPool) {
        let svc = upsert_service(&pool, "prod", "api").await.unwrap();
        let openssl = "pkg:deb/debian/openssl@3.0.11?distro=debian-12";
        let image = InventoryItem {
            purl: "pkg:oci/app@sha256%3Ad1".to_string(),
            cpes: vec![],
            direct: true,
            via_image_digest: Some("sha256:d1".to_string()),
        };
        replace_components(&pool, svc, Source::Cluster, &[image])
            .await
            .unwrap();
        store_image_sbom(&pool, "sha256:d1", "app:1", &[openssl.to_string()])
            .await
            .unwrap();
        replace_components(&pool, svc, Source::Git, &[item(openssl)])
            .await
            .unwrap();
        let eff = effective_components(&pool, "prod").await.unwrap();
        let hits: Vec<_> = eff.iter().filter(|e| e.purl == openssl).collect();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].direct);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn sync_declared_replaces_per_service(pool: PgPool) {
        let decl = |purl: &str| DeclaredComponent {
            realm: "prod".into(),
            service: "api".into(),
            purl: purl.into(),
        };
        sync_declared(&pool, &[decl(A), decl(B)]).await.unwrap();
        assert_eq!(effective_purls(&pool, "prod").await, set(&[A, B]));
        sync_declared(&pool, &[decl(A)]).await.unwrap();
        assert_eq!(effective_purls(&pool, "prod").await, set(&[A]));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn pending_skips_digest_without_repository_url(pool: PgPool) {
        let svc = upsert_service(&pool, "prod", "api").await.unwrap();
        let image = InventoryItem {
            purl: "pkg:oci/app@sha256%3Ad2".to_string(),
            cpes: vec![],
            direct: true,
            via_image_digest: Some("sha256:d2".to_string()),
        };
        replace_components(&pool, svc, Source::Cluster, &[image])
            .await
            .unwrap();
        assert!(pending_image_digests(&pool).await.unwrap().is_empty());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn sync_declared_removes_dropped_services(pool: PgPool) {
        let decl = |realm: &str, service: &str, purl: &str| DeclaredComponent {
            realm: realm.into(),
            service: service.into(),
            purl: purl.into(),
        };
        sync_declared(
            &pool,
            &[
                decl("prod", "api", A),
                decl("prod", "web", B),
                decl("dev", "api", C),
            ],
        )
        .await
        .unwrap();
        sync_declared(&pool, &[decl("prod", "api", A)])
            .await
            .unwrap();
        assert_eq!(effective_purls(&pool, "prod").await, set(&[A]));
        assert!(effective_purls(&pool, "dev").await.is_empty());
        sync_declared(&pool, &[]).await.unwrap();
        assert!(effective_purls(&pool, "prod").await.is_empty());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn empty_items_clears_service_source(pool: PgPool) {
        let svc = upsert_service(&pool, "prod", "api").await.unwrap();
        replace_components(&pool, svc, Source::Git, &[item(A), item(B)])
            .await
            .unwrap();
        replace_components(&pool, svc, Source::Cluster, &[item(C)])
            .await
            .unwrap();
        let report = replace_components(&pool, svc, Source::Git, &[])
            .await
            .unwrap();
        assert_eq!((report.added, report.removed), (0, 2));
        assert_eq!(effective_purls(&pool, "prod").await, set(&[C]));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn failed_replace_rolls_back(pool: PgPool) {
        let svc = upsert_service(&pool, "prod", "api").await.unwrap();
        replace_components(&pool, svc, Source::Git, &[item(A), item(B)])
            .await
            .unwrap();
        let result =
            replace_components(&pool, svc, Source::Git, &[item(C), item("not a purl")]).await;
        assert!(result.is_err());
        assert_eq!(effective_purls(&pool, "prod").await, set(&[A, B]));
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM components WHERE purl = $1")
            .bind(C)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "component insert must roll back too");
    }
}
