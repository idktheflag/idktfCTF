use axum::response::Json;
use serde_json::{json, Value};

pub async fn handler() -> Json<Value> {
    Json(json!({ "status": "ok", "platform": "idktheflag" }))
}
