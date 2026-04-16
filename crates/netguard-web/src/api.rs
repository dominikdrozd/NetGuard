use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use netguard_core::models::*;
use serde::Deserialize;
use tracing::info;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct PaginationParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub async fn list_connections(
    State(state): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Json<Vec<Connection>> {
    let limit = params.limit.unwrap_or(50).min(500);
    let offset = params.offset.unwrap_or(0).min(10_000);
    let connections = state.connection_log.recent(limit, offset).await;
    Json(connections)
}

pub async fn active_connections(State(state): State<AppState>) -> Json<Vec<Connection>> {
    let connections = state.connection_log.recent(100, 0).await;
    Json(connections)
}

pub async fn get_connection(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Connection>, StatusCode> {
    state
        .connection_log
        .get(id)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

pub async fn list_rules(State(state): State<AppState>) -> Json<Vec<Rule>> {
    let engine = state.rule_engine.read().unwrap_or_else(|e| e.into_inner());
    Json(engine.get_rules().to_vec())
}

pub async fn create_rule(
    State(state): State<AppState>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<Json<Rule>, (StatusCode, String)> {
    // Input validation
    if req.app_path.is_empty() || req.app_path.len() > 1024 {
        return Err((
            StatusCode::BAD_REQUEST,
            "app_path must be 1-1024 characters".into(),
        ));
    }
    if matches!(req.verdict, Verdict::Pending) {
        return Err((
            StatusCode::BAD_REQUEST,
            "verdict must be 'allow' or 'deny'".into(),
        ));
    }

    let duration_secs = req.duration_secs.map(|s| s.min(86400 * 365));

    let rule = Rule {
        id: Uuid::new_v4(),
        created_at: chrono::Utc::now(),
        enabled: true,
        app_path: req.app_path,
        direction: req.direction,
        remote_host: req.remote_host,
        remote_port: req.remote_port,
        protocol: req.protocol,
        verdict: req.verdict,
        temporary: req.temporary,
        expires_at: duration_secs
            .map(|s| chrono::Utc::now() + chrono::Duration::seconds(s as i64)),
        hit_count: 0,
        last_hit: None,
        note: req.note,
    };

    let mut engine = state.rule_engine.write().unwrap_or_else(|e| e.into_inner());
    engine
        .add_rule(rule.clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!(rule_id = %rule.id, app = %rule.app_path, verdict = ?rule.verdict, "Rule created");

    let _ = state
        .ws_broadcast_tx
        .send(WsEvent::RuleChanged(rule.clone()));

    Ok(Json(rule))
}

pub async fn update_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRuleRequest>,
) -> Result<Json<Rule>, (StatusCode, String)> {
    // Input validation on update fields
    if let Some(ref app_path) = req.app_path {
        if app_path.is_empty() || app_path.len() > 1024 {
            return Err((
                StatusCode::BAD_REQUEST,
                "app_path must be 1-1024 characters".into(),
            ));
        }
    }
    if let Some(ref verdict) = req.verdict {
        if matches!(verdict, Verdict::Pending) {
            return Err((
                StatusCode::BAD_REQUEST,
                "verdict must be 'allow' or 'deny'".into(),
            ));
        }
    }

    let mut engine = state.rule_engine.write().unwrap_or_else(|e| e.into_inner());
    engine
        .update_rule(id, req)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    let rule = engine
        .get_rule(id)
        .cloned()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Rule vanished".into()))?;
    let _ = state
        .ws_broadcast_tx
        .send(WsEvent::RuleChanged(rule.clone()));

    Ok(Json(rule))
}

pub async fn delete_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut engine = state.rule_engine.write().unwrap_or_else(|e| e.into_inner());
    engine
        .delete_rule(id)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    info!(rule_id = %id, "Rule deleted");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn toggle_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut engine = state.rule_engine.write().unwrap_or_else(|e| e.into_inner());
    let enabled = engine
        .toggle_rule(id)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    let rule = engine
        .get_rule(id)
        .cloned()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Rule vanished".into()))?;
    let _ = state.ws_broadcast_tx.send(WsEvent::RuleChanged(rule));

    info!(rule_id = %id, enabled = enabled, "Rule toggled");
    Ok(Json(serde_json::json!({ "enabled": enabled })))
}

pub async fn reorder_rules(
    State(state): State<AppState>,
    Json(order): Json<Vec<Uuid>>,
) -> Result<StatusCode, (StatusCode, String)> {
    if order.len() > 10_000 {
        return Err((StatusCode::BAD_REQUEST, "Too many rule IDs".into()));
    }
    let mut engine = state.rule_engine.write().unwrap_or_else(|e| e.into_inner());
    engine
        .reorder_rules(&order)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

pub async fn list_prompts(State(state): State<AppState>) -> Json<Vec<PendingPrompt>> {
    let prompts = state.pending_prompts.read().await;
    Json(prompts.values().cloned().collect())
}

pub async fn respond_prompt(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(mut response): Json<PromptResponse>,
) -> Result<StatusCode, (StatusCode, String)> {
    response.prompt_id = id;

    let Some(prompt) = ({
        let mut prompts = state.pending_prompts.write().await;
        prompts.remove(&id)
    }) else {
        return Err((StatusCode::NOT_FOUND, "Prompt not found".to_string()));
    };

    if response.remember {
        let mut engine = state.rule_engine.write().unwrap_or_else(|e| e.into_inner());
        if let Some(rule) = engine.create_rule_from_prompt(&prompt.connection, &response) {
            let _ = state.ws_broadcast_tx.send(WsEvent::RuleChanged(rule));
        }
    }

    let _ = state.ws_broadcast_tx.send(WsEvent::PromptResolved {
        prompt_id: id,
        verdict: response.verdict,
    });

    let _ = state.prompt_response_tx.send(response).await;

    Ok(StatusCode::OK)
}

pub async fn get_stats(State(state): State<AppState>) -> Json<DashboardStats> {
    let stats = state.connection_log.stats().await;
    Json(stats)
}
