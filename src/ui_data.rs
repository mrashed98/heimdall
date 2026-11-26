// Bounded, realm-scoped projections for the data pages. Legacy endpoints keep
// their original response shapes and defaults.
#[derive(Deserialize)]
struct UiQuery {
    realms: Option<String>, limit: Option<String>, offset: Option<String>,
    sort: Option<String>, order: Option<String>, kind: Option<String>, tab: Option<String>,
    search: Option<String>, version_lt: Option<String>,
}
fn ui_data_routes() -> Router<AppState> {
    Router::new().route("/api/v1/ui/services", get(ui_services))
        .route("/api/v1/ui/services/{id}/{section}", get(ui_service_section))
        .route("/api/v1/ui/releases", get(ui_releases))
        .route("/api/v1/ui/oaths", get(ui_oaths))
        .route("/api/v1/components", get(component_search))
}
fn ui_realms(state: &AppState, p: &Principal, q: &UiQuery) -> Result<Vec<String>, ApiError> {
    p.require_read()?;
    let allowed = p.readable_realms(&state.cfg.realms);
    match given(&q.realms) {
        None => Ok(allowed),
        Some(value) => {
            let mut result = Vec::new();
            for realm in value.split(',') {
                check_realm(&state.cfg, Some(realm))?;
                if allowed.iter().any(|r| r == realm) && !result.iter().any(|r| r == realm) { result.push(realm.to_owned()); }
            }
            Ok(result)
        }
    }
}
// Sort expressions and directions come only from fixed caller-provided allowlists.
fn ui_sort<'a>(q: &UiQuery, fields: &'a [(&str, &str)], default: &'a str) -> Result<(&'a str, &'static str), ApiError> {
    let field = match given(&q.sort) { None => default, Some(s) => fields.iter().find(|(name, _)| *name == s).map(|(_, sql)| *sql).ok_or_else(|| ApiError::BadRequest("unknown sort field".into()))? };
    let order = match given(&q.order).unwrap_or("asc") { "asc" => "ASC", "desc" => "DESC", _ => return Err(ApiError::BadRequest("unknown sort order".into())) };
    Ok((field, order))
}
async fn ui_services(State(state): State<AppState>, p: Principal, Query(q): Query<UiQuery>) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let realms = ui_realms(&state, &p, &q)?;
    let (sort, order) = ui_sort(&q, &[("name","name"),("realm","realm"),("critical","critical"),("high","high"),("medium","medium"),("low","low"),("unknown","unknown")], "realm")?;
    let sql = format!("SELECT row_to_json(t) FROM (SELECT s.id,s.name,s.realm, count(f.id) FILTER (WHERE f.severity='critical') AS critical, count(f.id) FILTER (WHERE f.severity='high') AS high, count(f.id) FILTER (WHERE f.severity='medium') AS medium, count(f.id) FILTER (WHERE f.severity='low') AS low, count(f.id) FILTER (WHERE f.severity='unknown') AS unknown FROM services s LEFT JOIN findings f ON f.service_id=s.id AND f.realm=s.realm AND f.status='open' WHERE s.realm=ANY($1) GROUP BY s.id ORDER BY {sort} {order}, s.id LIMIT $2 OFFSET $3) t");
    Ok(Json(sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str())).bind(realms).bind(parse_limit(&q.limit)?).bind(parse_offset(&q.offset)?).fetch_all(&state.pool).await?))
}
async fn ui_service_section(State(state): State<AppState>, p: Principal, UrlPath((id, section)): UrlPath<(i64,String)>, Query(q): Query<UiQuery>) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let realms = ui_realms(&state, &p, &q)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM services WHERE id=$1 AND realm=ANY($2))").bind(id).bind(&realms).fetch_one(&state.pool).await?;
    if !exists { return Err(ApiError::NotFound); }
    let (fields, default, select) = match section.as_str() {
        "info" => (vec![("name","s.name")], "s.name", "SELECT s.id,s.name,s.realm FROM services s WHERE s.id=$1"),
        "components" => (vec![("purl","c.purl"),("version","c.version"),("source","sc.source")], "c.purl", "SELECT c.purl,c.version,sc.source,sc.direct FROM service_components sc JOIN components c ON c.id=sc.component_id WHERE sc.service_id=$1"),
        "images" => (vec![("image","i.image_ref"),("digest","sc.via_image_digest")], "sc.via_image_digest", "SELECT DISTINCT sc.via_image_digest AS digest,i.image_ref AS image FROM service_components sc LEFT JOIN image_sboms i ON i.digest=sc.via_image_digest WHERE sc.service_id=$1 AND sc.via_image_digest IS NOT NULL"),
        "findings" => (vec![("advisory","f.ref_id"),("severity","CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"),("kind","f.kind"),("opened","f.opened_at")], "f.opened_at", "SELECT f.id,f.ref_id,f.kind,f.severity,f.status,f.opened_at,c.purl FROM findings f LEFT JOIN components c ON c.id=f.component_id WHERE f.service_id=$1 AND f.status='open'"),
        _ => return Err(ApiError::NotFound),
    };
    // DISTINCT image rows need output aliases in ORDER BY.
    let (sort, order) = ui_sort(&q, &fields, default)?;
    let sort = if section == "images" { if sort == "i.image_ref" { "image" } else { "digest" } } else { sort };
    let sql = format!("SELECT row_to_json(t) FROM ({select} ORDER BY {sort} {order} NULLS LAST LIMIT $2 OFFSET $3) t");
    Ok(Json(sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str())).bind(id).bind(parse_limit(&q.limit)?).bind(parse_offset(&q.offset)?).fetch_all(&state.pool).await?))
}
async fn ui_releases(State(state): State<AppState>, p: Principal, Query(q): Query<UiQuery>) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let realms = ui_realms(&state, &p, &q)?;
    let kind = given(&q.kind);
    if kind.is_some_and(|k| !["majorrelease","eol","releasenotecve"].contains(&k)) { return Err(ApiError::BadRequest("unknown release kind".into())); }
    let (sort, order) = ui_sort(&q, &[("target","f.details->>'target'"),("kind","f.kind"),("realm","f.realm"),("date","f.opened_at")], "f.opened_at")?;
    let sql = format!("SELECT row_to_json(t) FROM (SELECT f.id,f.kind,f.realm,f.ref_id,f.details,f.opened_at,r.notes_class,r.notes_url FROM findings f LEFT JOIN releases r ON r.target=f.details->>'target' AND r.version=f.details->>'version' WHERE f.realm=ANY($1) AND f.status='open' AND f.kind IN ('majorrelease','eol','releasenotecve') AND ($2::text IS NULL OR f.kind=$2) ORDER BY {sort} {order} NULLS LAST, f.id DESC LIMIT $3 OFFSET $4) t");
    Ok(Json(sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str())).bind(realms).bind(kind).bind(parse_limit(&q.limit)?).bind(parse_offset(&q.offset)?).fetch_all(&state.pool).await?))
}
async fn ui_oaths(State(state): State<AppState>, p: Principal, Query(q): Query<UiQuery>) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let realms = ui_realms(&state, &p, &q)?;
    let tab = given(&q.tab).unwrap_or("active");
    if !["active","expiring","past"].contains(&tab) { return Err(ApiError::BadRequest("unknown oath tab".into())); }
    let (sort, order) = ui_sort(&q, &[("advisory","advisory_id"),("service","service_name"),("realm","realm"),("kind","kind"),("date","COALESCE(expires_at,review_at)"),("status","status")], "id")?;
    let sql = format!("SELECT row_to_json(t) FROM (SELECT id,advisory_id,name_key,service_name,realm,kind,reason,version_at_creation,expires_at,review_at,created_by,created_at,status FROM oaths WHERE (realm=ANY($1) OR (realm IS NULL AND cardinality($1::text[])>0)) AND CASE $2 WHEN 'active' THEN status='active' AND (COALESCE(expires_at,review_at) IS NULL OR COALESCE(expires_at,review_at)>now()) WHEN 'expiring' THEN status='active' AND COALESCE(expires_at,review_at)>now() AND COALESCE(expires_at,review_at)<=now()+interval '7 days' ELSE status IN ('expired','revoked') OR (status='active' AND COALESCE(expires_at,review_at)<=now()) END ORDER BY {sort} {order} NULLS LAST, id DESC LIMIT $3 OFFSET $4) t");
    Ok(Json(sqlx::query_scalar(sqlx::AssertSqlSafe(sql.as_str())).bind(realms).bind(tab).bind(parse_limit(&q.limit)?).bind(parse_offset(&q.offset)?).fetch_all(&state.pool).await?))
}

/// A search matching more components than this is refused, so one request
/// never holds a whole inventory in memory; the caller narrows the text.
const COMPONENT_SEARCH_CAP: usize = 10_000;
/// Components whose package URL contains `search`, each with the services and
/// images that carry it in the caller's realms. `version_lt` keeps versions
/// below it, compared the way the component's ecosystem orders versions.
async fn component_search(State(state): State<AppState>, p: Principal, Query(q): Query<UiQuery>) -> Result<Json<Vec<serde_json::Value>>, ApiError> {
    let realms = ui_realms(&state, &p, &q)?;
    let search = given(&q.search).map(str::trim).unwrap_or("");
    if search.chars().count() < 2 { return Err(ApiError::BadRequest("search needs at least 2 characters".into())); }
    let below = given(&q.version_lt).map(str::trim).filter(|v| !v.is_empty());
    let (limit, offset) = (parse_limit(&q.limit)? as usize, parse_offset(&q.offset)? as usize);
    let pattern = format!("%{}%", search.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
    let candidates: Vec<(i64, String, String)> = sqlx::query_as("SELECT c.id,c.ecosystem,c.version FROM components c WHERE c.purl ILIKE $1 AND EXISTS (SELECT 1 FROM service_components sc JOIN services s ON s.id=sc.service_id WHERE sc.component_id=c.id AND s.realm=ANY($2)) ORDER BY c.name_key, c.version, c.id LIMIT $3")
        .bind(pattern).bind(&realms).bind(COMPONENT_SEARCH_CAP as i64 + 1).fetch_all(&state.pool).await?;
    if candidates.len() > COMPONENT_SEARCH_CAP { return Err(ApiError::BadRequest(format!("more than {COMPONENT_SEARCH_CAP} components match; narrow the search"))); }
    let page: Vec<i64> = candidates.into_iter()
        .filter(|(_, ecosystem, version)| below.is_none_or(|b| crate::version::compare(ecosystem, version, b) == Some(std::cmp::Ordering::Less)))
        .skip(offset).take(limit).map(|(id, _, _)| id).collect();
    Ok(Json(sqlx::query_scalar("SELECT row_to_json(t) FROM (SELECT c.purl,c.name_key,c.ecosystem,c.version, \
        (SELECT json_agg(json_build_object('id',s.id,'name',s.name,'realm',s.realm) ORDER BY s.realm,s.name) FROM services s WHERE s.realm=ANY($2) AND EXISTS (SELECT 1 FROM service_components sc WHERE sc.service_id=s.id AND sc.component_id=c.id)) AS services, \
        (SELECT coalesce(array_agg(DISTINCT i.image_ref ORDER BY i.image_ref),'{}') FROM service_components sc JOIN services s ON s.id=sc.service_id AND s.realm=ANY($2) JOIN image_sboms i ON i.digest=sc.via_image_digest WHERE sc.component_id=c.id) AS images \
        FROM unnest($1::bigint[]) WITH ORDINALITY AS p(id,n) JOIN components c ON c.id=p.id ORDER BY p.n) t")
        .bind(page).bind(&realms).fetch_all(&state.pool).await?))
}
