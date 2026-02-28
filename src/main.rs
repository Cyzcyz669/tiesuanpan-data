use axum::{
    extract::State,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use wasmtime::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Sha256, Digest};

// ============================================================
// 状态机：内存订单账本
// ============================================================
#[derive(Clone)]
struct BountyState {
    expected_hash: String,       // 发单方锁定的哈希（commit 时存入）
    clean_result: Option<String>, // Wasm 执行结果（commit 时缓存）
    gas_used: Option<u64>,
}

type BountyStore = Arc<Mutex<HashMap<String, BountyState>>>;

// ============================================================
// 请求 / 响应结构体
// ============================================================

// POST /api/bounty/commit — 第一步：提交任务 + 哈希锁
#[derive(Deserialize)]
struct CommitRequest {
    bounty_id: String,
    input_data: String,
    wasm_b64: String,
    expected_hash: String,  // SHA-256(salt + correct_output)，salt 此时不公开
}

#[derive(Serialize)]
struct CommitResponse {
    status: String,
    bounty_id: String,
    gas_used: u64,
    message: String,
}

// POST /api/bounty/reveal — 第二步：发单方公开 salt，铁算盘最终裁判
#[derive(Deserialize)]
struct RevealRequest {
    bounty_id: String,
    salt: String,
}

#[derive(Serialize)]
struct RevealResponse {
    status: String,
    bounty_id: String,
    verified: bool,
    clean_result: String,
    gas_used: u64,
    computed_hash: String,
}

// ============================================================
// 核心执行引擎（不变）
// ============================================================
fn run_wasm_skill(
    input_str: &str,
    wasm_bytes: &[u8],
) -> Result<(String, u64), Box<dyn std::error::Error>> {
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config)?;
    let module = Module::from_binary(&engine, wasm_bytes)?;
    let mut store = Store::new(&engine, ());
    let initial_gas = 100_000u64;
    store.set_fuel(initial_gas)?;

    let instance = Instance::new(&mut store, &module, &[])?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or("找不到内存模块")?;

    let allocate_fn = instance.get_typed_func::<u32, u32>(&mut store, "allocate")?;
    let clean_data_fn =
        instance.get_typed_func::<(u32, u32), u64>(&mut store, "clean_data")?;

    let input_bytes = input_str.as_bytes();
    let input_len = input_bytes.len() as u32;
    let ptr = allocate_fn.call(&mut store, input_len)?;
    memory.write(&mut store, ptr as usize, input_bytes)?;

    let packed = clean_data_fn.call(&mut store, (ptr, input_len))?;
    let result_ptr = (packed >> 32) as usize;
    let result_len = (packed & 0xFFFFFFFF) as usize;

    let mut buf = vec![0u8; result_len];
    memory.read(&store, result_ptr, &mut buf)?;
    let output = String::from_utf8(buf)?;

    let gas_used = initial_gas - store.get_fuel()?;
    Ok((output, gas_used))
}

// ============================================================
// Handler 1: POST /api/bounty/commit
// 发单方提交任务 + expected_hash，铁算盘执行 Wasm 并缓存结果
// salt 此时不公开 → 真正的盲测
// ============================================================
async fn commit_bounty(
    State(store): State<BountyStore>,
    Json(payload): Json<CommitRequest>,
) -> Json<CommitResponse> {
    println!("------------------------------------------------");
    println!("📥 [COMMIT] 收到悬赏委托，订单 ID: {}", payload.bounty_id);
    println!("🔒 哈希锁已封存: {}", payload.expected_hash);

    // 防 DOS
    if payload.wasm_b64.len() > 2 * 1024 * 1024 {
        return Json(CommitResponse {
            status: "FAILED_PAYLOAD_TOO_LARGE".to_string(),
            bounty_id: payload.bounty_id,
            gas_used: 0,
            message: "Payload 超过 2MB 限制".to_string(),
        });
    }

    let wasm_bytes = match BASE64.decode(&payload.wasm_b64) {
        Ok(b) => b,
        Err(_) => {
            return Json(CommitResponse {
                status: "FAILED_INVALID_BASE64".to_string(),
                bounty_id: payload.bounty_id,
                gas_used: 0,
                message: "Base64 解码失败".to_string(),
            });
        }
    };

    match run_wasm_skill(&payload.input_data, &wasm_bytes) {
        Ok((clean_result, gas_used)) => {
            println!("⚙️  铁算盘执行完毕，Gas: {}，结果已密封入账本", gas_used);

            // 写入内存状态机，结果密封，等待 Reveal
            let mut map = store.lock().unwrap();
            map.insert(
                payload.bounty_id.clone(),
                BountyState {
                    expected_hash: payload.expected_hash,
                    clean_result: Some(clean_result),
                    gas_used: Some(gas_used),
                },
            );

            Json(CommitResponse {
                status: "COMMITTED".to_string(),
                bounty_id: payload.bounty_id,
                gas_used,
                message: "任务已执行，结果密封。请发单方提交 salt 触发裁判。".to_string(),
            })
        }
        Err(e) => Json(CommitResponse {
            status: "FAILED_EXECUTION".to_string(),
            bounty_id: payload.bounty_id,
            gas_used: 0,
            message: e.to_string(),
        }),
    }
}

// ============================================================
// Handler 2: POST /api/bounty/reveal
// 发单方公开 salt，铁算盘用 SHA-256(salt + cached_result) 裁判
// ============================================================
async fn reveal_bounty(
    State(store): State<BountyStore>,
    Json(payload): Json<RevealRequest>,
) -> Json<RevealResponse> {
    println!("------------------------------------------------");
    println!("🔓 [REVEAL] 收到开盐请求，订单 ID: {}", payload.bounty_id);

    let map = store.lock().unwrap();
    let state = match map.get(&payload.bounty_id) {
        Some(s) => s.clone(),
        None => {
            return Json(RevealResponse {
                status: "FAILED_NOT_FOUND".to_string(),
                bounty_id: payload.bounty_id,
                verified: false,
                clean_result: "".to_string(),
                gas_used: 0,
                computed_hash: "".to_string(),
            });
        }
    };

    let clean_result = state.clean_result.unwrap_or_default();
    let gas_used = state.gas_used.unwrap_or(0);

    // SHA-256(salt + clean_result)
    let mut hasher = Sha256::new();
    hasher.update(payload.salt.as_bytes());
    hasher.update(clean_result.as_bytes());
    let computed_hash = hex::encode(hasher.finalize());

    let verified = computed_hash == state.expected_hash;
    let status = if verified { "VERIFIED_SUCCESS" } else { "HASH_MISMATCH" };

    if verified {
        println!("✅ [裁判] 盐值匹配，哈希一致，赏金授权！");
    } else {
        println!("❌ [裁判] 哈希不匹配，赏金扣押！");
        println!("   期望: {}", state.expected_hash);
        println!("   实际: {}", computed_hash);
    }

    Json(RevealResponse {
        status: status.to_string(),
        bounty_id: payload.bounty_id,
        verified,
        clean_result,
        gas_used,
        computed_hash,
    })
}

// ============================================================
// 启动
// ============================================================
#[tokio::main]
async fn main() {
    // 初始化共享状态
    let bounty_store: BountyStore = Arc::new(Mutex::new(HashMap::new()));

    let app = Router::new()
        .route("/api/bounty/commit", post(commit_bounty))
        .route("/api/bounty/reveal", post(reveal_bounty))
        .with_state(bounty_store);

        let addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .unwrap();


    println!("🚀 【大码头 v0.6】两阶段零信任法庭已启动！");
    println!("🌐 正在监听: http://{}", addr);
    println!("📋 端点:");
    println!("   POST /api/bounty/commit  ← 提交任务 + 哈希锁");
    println!("   POST /api/bounty/reveal  ← 公开 salt，触发最终裁判");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
