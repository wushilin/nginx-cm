use axum::{
    extract::{Form, State},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    env,
};
use tera::{Context, Tera};
use tokio::net::TcpListener;
use tracing::{info, error};
use aws_config::BehaviorVersion;
use aws_sdk_s3::primitives::ByteStream;
use rust_embed::RustEmbed;
use clap::Parser;
use anyhow::{Context as AnyhowContext, Result};

mod scheduled_tasks;
use scheduled_tasks::{TaskRunner, TaskContext, CleanupStatusTask};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the optional S3 configuration file
    #[arg(short, long)]
    config: Option<String>,
}

#[derive(RustEmbed)]
#[folder = "templates/"]
struct Asset;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
struct SniMapping {
    pattern: String,
    target: String, // Empty means passthrough ($ssl_preread_server_name)
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
struct ListenerConfig {
    #[serde(default = "default_bind")]
    bind: String,
    port: u16,
    mappings: Vec<SniMapping>,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: 9092,
            mappings: vec![
                SniMapping {
                    pattern: r"^b\d+-pkc-312o0\.ap-southeast-1\.aws\.confluent\.cloud$".to_string(),
                    target: "".to_string(),
                },
                SniMapping {
                    pattern: r"^pkc-312o0\.ap-southeast-1\.aws\.confluent\.cloud$".to_string(),
                    target: "".to_string(),
                },
            ],
        }
    }
}

fn default_bind() -> String {
    "0.0.0.0".to_string()
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct AppConfig {
    listeners: Vec<ListenerConfig>,
    #[serde(default = "default_resolver")]
    resolver: String,
    #[serde(default = "default_user")]
    user: String,
    #[serde(default = "default_stream_module_path")]
    stream_module_path: String,
    
    #[serde(default = "default_nginx_binary_path")]
    nginx_binary_path: String,
    #[serde(default = "default_nginx_working_dir")]
    nginx_working_dir: String,

    #[serde(default = "default_heartbeat_interval_minutes")]
    heartbeat_interval_minutes: u64,
}

fn default_resolver() -> String {
    "".to_string()
}

fn default_user() -> String {
    "www-data".to_string()
    }

fn default_stream_module_path() -> String {
    "modules/ngx_stream_module.so".to_string()
}

fn default_nginx_binary_path() -> String {
    "/usr/sbin/nginx".to_string()
}

fn default_nginx_working_dir() -> String {
    "/tmp/nginx".to_string()
}

fn default_heartbeat_interval_minutes() -> u64 {
    1
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            listeners: vec![ListenerConfig::default()],
            resolver: default_resolver(),
            user: default_user(),
            stream_module_path: default_stream_module_path(),
            
            nginx_binary_path: default_nginx_binary_path(),
            nginx_working_dir: default_nginx_working_dir(),
            heartbeat_interval_minutes: default_heartbeat_interval_minutes(),
        }
    }
}

#[derive(Clone, Debug)]
struct S3Config {
    s3_endpoint: String,
    s3_bucket: String,
    s3_folder: String,
    s3_access_key: String,
    s3_secret_key: String,
}

struct AppState {
    config: Mutex<AppConfig>,
    s3_config: S3Config,
    tera: Tera,
    config_path: PathBuf,
}

#[derive(Serialize, Debug)]
struct AgentStatus {
    hostname: String,
    last_seen: u64,
    is_running: bool,
    health: String, // "Active", "Warning", "Critical"
    pid: Option<u32>,
    config_version_ts: Option<u64>, // Epoch timestamp
    details: String,
    is_outdated: bool,
}

#[derive(Deserialize, Serialize)]
struct StatusReport {
    is_nginx_running: bool,
    nginx_pid: Option<u32>,
    config_version: Option<u64>,
    timestamp: u64,
    last_error_log: String,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
}

#[derive(Deserialize)]
struct AddListenerForm {
    #[serde(default = "default_bind")]
    bind: String,
    port: u16,
}

#[derive(Deserialize)]
struct DeleteListenerForm {
    #[serde(default = "default_bind")]
    bind: String,
    port: u16,
}

#[derive(Deserialize)]
struct AddMappingForm {
    #[serde(default = "default_bind")]
    bind: String,
    port: u16,
    pattern: String,
    target: Option<String>,
}

#[derive(Deserialize)]
struct DeleteMappingForm {
    #[serde(default = "default_bind")]
    bind: String,
    port: u16,
    pattern: String,
}

#[derive(Deserialize)]
struct UpdateNginxConfigForm {
    resolver: String,
    user: String,
    stream_module_path: String,
}

#[derive(Deserialize)]
struct UpdateGuardianConfigForm {
    nginx_binary_path: String,
    nginx_working_dir: String,
    heartbeat_interval_minutes: u64,
}

#[derive(Deserialize)]
struct DeleteStatusForm {
    hostname: String,
}

fn load_s3_config(config_path: Option<String>) -> Result<S3Config> {
    if let Some(path_str) = config_path {
        info!("Loading S3 config from specified file: {}", path_str);
        let config_path = PathBuf::from(path_str);
        let content = fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read S3 config from {:?}", config_path))?;
        let json: serde_json::Value = serde_json::from_str(&content)
             .with_context(|| "Failed to parse S3 config JSON")?;

        Ok(S3Config {
            s3_endpoint: json["s3_endpoint"].as_str().unwrap_or("").to_string(),
            s3_bucket: json["s3_bucket"].as_str().unwrap_or("").to_string(),
            s3_folder: json["s3_folder"].as_str().unwrap_or("").to_string(),
            s3_access_key: json["s3_access_key"].as_str().unwrap_or("").to_string(),
            s3_secret_key: json["s3_secret_key"].as_str().unwrap_or("").to_string(),
        })
    } else {
        info!("Loading S3 config from Environment Variables");
        // Check if essential env vars are present, at least bucket
        let bucket = env::var("S3_BUCKET").unwrap_or_default();
        if bucket.is_empty() {
            anyhow::bail!("S3_BUCKET environment variable is not set, and no config file provided.");
        }

        Ok(S3Config {
            s3_endpoint: env::var("S3_ENDPOINT").unwrap_or_default(),
            s3_bucket: bucket,
            s3_folder: env::var("S3_FOLDER").unwrap_or_default(),
            s3_access_key: env::var("S3_ACCESS_KEY").unwrap_or_default(),
            s3_secret_key: env::var("S3_SECRET_KEY").unwrap_or_default(),
        })
    }
}

async fn create_s3_client(config: &S3Config) -> aws_sdk_s3::Client {
    let region_provider = if !config.s3_endpoint.is_empty() {
        aws_config::meta::region::RegionProviderChain::first_try(aws_config::Region::new("us-east-1"))
    } else {
        aws_config::meta::region::RegionProviderChain::default_provider()
            .or_else("us-east-1")
    };

    let creds = aws_credential_types::Credentials::new(
        config.s3_access_key.clone(),
        config.s3_secret_key.clone(),
        None,
        None,
        "static"
    );

    let sdk_config = if !config.s3_endpoint.is_empty() {
        aws_config::defaults(BehaviorVersion::latest())
            .region(region_provider)
            .credentials_provider(creds)
            .endpoint_url(config.s3_endpoint.clone())
            .load()
            .await
    } else {
        aws_config::defaults(BehaviorVersion::latest())
            .region(region_provider)
            .credentials_provider(creds)
            .load()
            .await
    };

    if !config.s3_endpoint.is_empty() {
        let client_config = aws_sdk_s3::config::Builder::from(&sdk_config)
            .force_path_style(true)
            .build();
        aws_sdk_s3::Client::from_conf(client_config)
    } else {
        aws_sdk_s3::Client::new(&sdk_config)
    }
}

async fn verify_s3_access(config: &S3Config) -> Result<()> {
    info!("Verifying S3 access...");

    let client = create_s3_client(config).await;

    // Try to list objects in the bucket/prefix to verify access
    let prefix = if config.s3_folder.is_empty() {
        "".to_string()
    } else {
        format!("{}/", config.s3_folder.trim_end_matches('/'))
    };

    info!("Checking access to s3://{}/{}", config.s3_bucket, prefix);

    client.list_objects_v2()
        .bucket(&config.s3_bucket)
        .prefix(&prefix)
        .max_keys(1)
        .send()
        .await
        .with_context(|| format!("Failed to list objects in s3://{}/{}. Check credentials and permissions.", config.s3_bucket, prefix))?;

    info!("S3 access verified successfully.");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();

    if let Ok(cwd) = env::var("CM_WORKING_DIR") {
        info!("Changing working directory to: {}", cwd);
        if let Err(e) = env::set_current_dir(&cwd) {
            error!("Failed to set working directory to {}: {}", cwd, e);
            // We might want to exit here if it's critical, but for now let's just log
            anyhow::bail!("Failed to set working directory to {}: {}", cwd, e);
        }
    }

    let config_path = PathBuf::from("app_config.json");
    
    let s3_config = load_s3_config(args.config)?;

    // Check for app_config.json locally
    let config = if config_path.exists() {
        let content = fs::read_to_string(&config_path)?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        // Try to download from S3
        info!("app_config.json not found locally. Attempting to restore from S3...");
        let mut config = AppConfig::default();
        let mut restored = false;

        if !s3_config.s3_bucket.is_empty() {
            let client = create_s3_client(&s3_config).await;
            let folder = s3_config.s3_folder.trim_end_matches('/');
            let key = if folder.is_empty() {
                "app_config.json".to_string()
            } else {
                format!("{}/app_config.json", folder)
            };

            match client.get_object().bucket(&s3_config.s3_bucket).key(&key).send().await {
                Ok(resp) => {
                    match resp.body.collect().await {
                        Ok(bytes) => {
                             if let Ok(content) = String::from_utf8(bytes.into_bytes().to_vec()) {
                                 if let Ok(c) = serde_json::from_str::<AppConfig>(&content) {
                                     config = c;
                                     restored = true;
                                     info!("Successfully restored app_config.json from S3");
                                     // Save it locally
                                     if let Err(e) = fs::write(&config_path, content) {
                                         error!("Failed to save restored config locally: {}", e);
                                     }
                                 } else {
                                     error!("Failed to parse downloaded app_config.json");
                                 }
                             }
                        }
                        Err(e) => error!("Failed to read body of app_config.json from S3: {}", e),
                    }
                }
                Err(e) => info!("Could not download app_config.json from S3: {}", e),
            }
        }

        if !restored {
            info!("Using default configuration.");
        }
        config
    };

    
    // Verify S3 access before starting
    verify_s3_access(&s3_config).await?;

    // Start Scheduled Tasks
    let task_context = TaskContext {
        s3_config: s3_config.clone(),
        heartbeat_interval_minutes: config.heartbeat_interval_minutes,
    };
    let mut task_runner = TaskRunner::new(task_context);
    task_runner.add_task(CleanupStatusTask);
    tokio::spawn(async move {
        task_runner.start().await;
    });

    let mut tera = Tera::default();
    // Load templates from embedded assets
    for file in Asset::iter() {
        if let Some(content) = Asset::get(file.as_ref()) {
            let template_str = std::str::from_utf8(content.data.as_ref())?;
            tera.add_raw_template(file.as_ref(), template_str)?;
        }
    }

    let state = Arc::new(AppState {
        config: Mutex::new(config),
        s3_config,
        tera,
        config_path,
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/add_listener", post(add_listener))
        .route("/delete_listener", post(delete_listener))
        .route("/add_pattern", post(add_mapping))
        .route("/delete_pattern", post(delete_mapping))
        .route("/update_nginx", post(update_nginx_config))
        .route("/update_guardian", post(update_guardian_config))
        .route("/apply", post(apply_config))
        .route("/delete_status", post(delete_status))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("Listening on {}", addr);
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn fetch_statuses(config: &S3Config, heartbeat_interval_minutes: u64) -> Vec<AgentStatus> {
    if config.s3_bucket.is_empty() {
        return vec![];
    }

    let client = create_s3_client(config).await;

    // 1. Get Last Modified time of nginx.conf
    let folder = config.s3_folder.trim_end_matches('/');
    let conf_key = if folder.is_empty() {
        "nginx.conf".to_string()
    } else {
        format!("{}/nginx.conf", folder)
    };

    // Fetch nginx.conf metadata to check last modified time
    let published_config_ts = match client.head_object().bucket(&config.s3_bucket).key(&conf_key).send().await {
        Ok(resp) => resp.last_modified.map(|t| t.secs() as u64).unwrap_or(0),
        Err(_) => 0,
    };
    
    // 2. List objects in folder
    let prefix = if folder.is_empty() {
        "".to_string()
    } else {
        format!("{}/", folder)
    };

    struct StatusEntry {
        hostname: String,
        last_modified: aws_smithy_types::DateTime,
        key: String,
    }

    let mut status_entries = Vec::new();
    
    let mut paginator = client.list_objects_v2()
        .bucket(&config.s3_bucket)
        .prefix(&prefix)
        .into_paginator()
        .send();

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Thresholds
    let interval_secs = heartbeat_interval_minutes * 60;
    let warning_threshold = 3 * interval_secs;
    let critical_threshold = 6 * interval_secs;
    // remove_threshold used in scheduled tasks now

    while let Some(page) = paginator.next().await {
        if let Ok(output) = page {
            for obj in output.contents.unwrap_or_default() {
                let key = obj.key.as_deref().unwrap_or_default();
                if key == conf_key { continue; }

                let last_modified = obj.last_modified.unwrap();
                
                // Handle legacy .live files - delete them
                if key.ends_with(".live") {
                    // Legacy cleanup moved to scheduled_tasks.rs
                    continue;
                }
                
                if key.ends_with(".status") {
                    // Cleanup logic moved to scheduled_tasks.rs
                    // We just read here
                    let filename = key.strip_prefix(&prefix).unwrap_or(key);
                    let hostname = filename.strip_suffix(".status").unwrap_or(filename);
                    status_entries.push(StatusEntry {
                        hostname: hostname.to_string(),
                        last_modified,
                        key: key.to_string(),
                    });
                } 
                // Handle legacy loaded_ok/error - delete them
                else if key.ends_with(".loaded_ok") || key.ends_with(".loaded_error") {
                    // Legacy cleanup also moved to scheduled_tasks.rs
                }
            }
        }
    }

    // Process Statuses
    let mut agent_statuses = Vec::new();

    for entry in status_entries {
        let last_modified_secs = entry.last_modified.secs() as u64;
        let diff = if current_time > last_modified_secs { current_time - last_modified_secs } else { 0 };
        
        let health = if diff < warning_threshold { 
            "Active".to_string()
        } else if diff < critical_threshold { 
            "Warning".to_string()
        } else {
            "Critical".to_string()
        };

        let mut is_running = false;
        let mut pid = None;
        let mut config_version_ts = None;
        let mut details = "".to_string();
        let mut is_outdated = false;

        // Fetch content
        if let Ok(get_obj) = client.get_object().bucket(&config.s3_bucket).key(&entry.key).send().await {
            if let Ok(bytes) = get_obj.body.collect().await {
                let content = String::from_utf8_lossy(&bytes.into_bytes()).to_string();
                if let Ok(report) = serde_json::from_str::<StatusReport>(&content) {
                    is_running = report.is_nginx_running;
                    pid = report.nginx_pid;
                    config_version_ts = report.config_version;
                    
                    if let Some(ts) = report.config_version {
                        // Check if outdated
                        if ts < published_config_ts {
                            is_outdated = true;
                        }
                    } else {
                        // No config version means definitely outdated if we have a published config
                        if published_config_ts > 0 {
                            is_outdated = true;
                        }
                    }

                    // Combine logs if error
                    let mut parts = Vec::new();
                    if !report.last_error_log.is_empty() {
                        parts.push(format!("=== Nginx Error Log ===\n{}", report.last_error_log));
                    }
                    if !report.stderr.is_empty() {
                        parts.push(format!("=== Stderr ===\n{}", report.stderr));
                    }
                    if !report.stdout.is_empty() {
                        parts.push(format!("=== Stdout ===\n{}", report.stdout));
                    }
                    details = parts.join("\n\n");
                }
            }
        }

        agent_statuses.push(AgentStatus {
            hostname: entry.hostname.clone(),
            last_seen: last_modified_secs,
            is_running,
            health,
            pid,
            config_version_ts,
            details,
            is_outdated,
        });
    }
    
    // Sorting Agent Status: Newest First
    agent_statuses.sort_by(|a, b| {
        b.last_seen.cmp(&a.last_seen)
    });

    agent_statuses
}

async fn index(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Lock config once to clone needed parts, then release lock before long async call
    let config_clone = state.config.lock().unwrap().clone();
    let s3_config = &state.s3_config;

    let mut context = Context::new();
    context.insert("listeners", &config_clone.listeners);
    context.insert("resolver", &config_clone.resolver);
    context.insert("user", &config_clone.user);
    context.insert("stream_module_path", &config_clone.stream_module_path);
    
    context.insert("nginx_binary_path", &config_clone.nginx_binary_path);
    context.insert("nginx_working_dir", &config_clone.nginx_working_dir);
    context.insert("heartbeat_interval_minutes", &config_clone.heartbeat_interval_minutes);

    // Fetch statuses if S3 is configured
    if !s3_config.s3_bucket.is_empty() {
        let agent_statuses = fetch_statuses(s3_config, config_clone.heartbeat_interval_minutes).await;
        context.insert("agent_statuses", &agent_statuses);
        
        let agent_active = agent_statuses.iter().filter(|s| s.health == "Active").count();
        let agent_warn = agent_statuses.iter().filter(|s| s.health == "Warning").count();
        let agent_crit = agent_statuses.iter().filter(|s| s.health == "Critical").count();
        
        context.insert("agent_active_count", &agent_active);
        context.insert("agent_warning_count", &agent_warn);
        context.insert("agent_critical_count", &agent_crit);

    } else {
        context.insert("agent_statuses", &Vec::<AgentStatus>::new());
        context.insert("agent_active_count", &0);
        context.insert("agent_warning_count", &0);
        context.insert("agent_critical_count", &0);
    }

    // Generate preview
    let preview = state.tera.render("nginx.conf.tera", &context).unwrap_or_else(|e| format!("Error rendering preview: {}", e));
    context.insert("config_preview", &preview);

    let rendered = state.tera.render("index.html.tera", &context).unwrap();
    Html(rendered)
}

async fn add_listener(
    State(state): State<Arc<AppState>>,
    Form(form): Form<AddListenerForm>,
) -> impl IntoResponse {
    {
        let mut config = state.config.lock().unwrap();
        if !config.listeners.iter().any(|l| l.port == form.port && l.bind == form.bind) {
            config.listeners.push(ListenerConfig {
                bind: form.bind,
                port: form.port,
                mappings: vec![],
            });
            // Sort listeners by port for consistent UI
            config.listeners.sort_by(|a, b| a.port.cmp(&b.port).then(a.bind.cmp(&b.bind)));
            save_config(&config, &state.config_path);
        }
    }
    Redirect::to("/?tab=listeners")
}

async fn delete_listener(
    State(state): State<Arc<AppState>>,
    Form(form): Form<DeleteListenerForm>,
) -> impl IntoResponse {
    {
        let mut config = state.config.lock().unwrap();
        config.listeners.retain(|l| l.port != form.port || l.bind != form.bind);
        save_config(&config, &state.config_path);
    }
    Redirect::to("/?tab=listeners")
}

async fn add_mapping(
    State(state): State<Arc<AppState>>,
    Form(form): Form<AddMappingForm>,
) -> impl IntoResponse {
    {
        let mut config = state.config.lock().unwrap();
        if let Some(listener) = config.listeners.iter_mut().find(|l| l.port == form.port && l.bind == form.bind) {
            // Strip regex prefix if present, as it will be added in the template
            let mut pattern = form.pattern.trim();
            if pattern.starts_with("~*") {
                pattern = &pattern[2..];
            } else if pattern.starts_with("~") {
                pattern = &pattern[1..];
            }
            let pattern = pattern.to_string();

            if !listener.mappings.iter().any(|m| m.pattern == pattern) && !pattern.is_empty() {
                listener.mappings.push(SniMapping {
                    pattern,
                    target: form.target.unwrap_or_default(),
                });
                save_config(&config, &state.config_path);
            }
        }
    }
    Redirect::to("/?tab=listeners")
}

async fn delete_mapping(
    State(state): State<Arc<AppState>>,
    Form(form): Form<DeleteMappingForm>,
) -> impl IntoResponse {
    {
        let mut config = state.config.lock().unwrap();
        if let Some(listener) = config.listeners.iter_mut().find(|l| l.port == form.port && l.bind == form.bind) {
            listener.mappings.retain(|m| m.pattern != form.pattern);
            save_config(&config, &state.config_path);
        }
    }
    Redirect::to("/?tab=listeners")
}

async fn update_nginx_config(
    State(state): State<Arc<AppState>>,
    Form(form): Form<UpdateNginxConfigForm>,
) -> impl IntoResponse {
    {
        let mut config = state.config.lock().unwrap();
        config.resolver = form.resolver;
        config.user = form.user;
        config.stream_module_path = form.stream_module_path;
        
        save_config(&config, &state.config_path);
    }
    Redirect::to("/?tab=nginx-config")
}

async fn update_guardian_config(
    State(state): State<Arc<AppState>>,
    Form(form): Form<UpdateGuardianConfigForm>,
) -> impl IntoResponse {
    {
        let mut config = state.config.lock().unwrap();
        config.nginx_binary_path = form.nginx_binary_path;
        config.nginx_working_dir = form.nginx_working_dir;
        config.heartbeat_interval_minutes = form.heartbeat_interval_minutes;
        
        save_config(&config, &state.config_path);
    }
    Redirect::to("/?tab=guardian-config")
}

async fn apply_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let (config, preview) = {
        let config = state.config.lock().unwrap();
        let mut context = Context::new();
        context.insert("listeners", &config.listeners);
        context.insert("resolver", &config.resolver);
        context.insert("user", &config.user);
        context.insert("stream_module_path", &config.stream_module_path);
        let preview = state.tera.render("nginx.conf.tera", &context).unwrap();
        (config.clone(), preview)
    };

    let s3_config = &state.s3_config;

    // Upload to S3
    info!("Starting S3 upload...");
    
    let client = create_s3_client(s3_config).await;
    
    let folder = s3_config.s3_folder.trim_end_matches('/');
    let key = if folder.is_empty() {
        "nginx.conf".to_string()
    } else {
        format!("{}/nginx.conf", folder)
    };

    // Upload nginx.conf
    let result = client.put_object()
        .bucket(&s3_config.s3_bucket)
        .key(&key)
        .body(ByteStream::from(preview.into_bytes()))
        .send()
        .await;
        
    // Also upload ngguard.json (trimmed config)
    let ngguard_key = if folder.is_empty() {
        "ngguard.json".to_string()
    } else {
        format!("{}/ngguard.json", folder)
    };
    
    // Create trimmed config json
    let trimmed_config = serde_json::json!({
        "nginx_binary_path": config.nginx_binary_path,
        "nginx_working_dir": config.nginx_working_dir,
        "heartbeat_interval_minutes": config.heartbeat_interval_minutes,
    });
    
    if let Ok(json_bytes) = serde_json::to_vec_pretty(&trimmed_config) {
        let _ = client.put_object()
            .bucket(&s3_config.s3_bucket)
            .key(&ngguard_key)
            .body(ByteStream::from(json_bytes))
            .send()
            .await;
        info!("Uploaded ngguard.json to s3://{}/{}", s3_config.s3_bucket, ngguard_key);
    }

    // UPLOAD app_config.json
    let app_config_key = if folder.is_empty() {
        "app_config.json".to_string()
    } else {
        format!("{}/app_config.json", folder)
    };

    if let Ok(json_bytes) = serde_json::to_vec_pretty(&config) {
        let _ = client.put_object()
            .bucket(&s3_config.s3_bucket)
            .key(&app_config_key)
            .body(ByteStream::from(json_bytes))
            .send()
            .await;
        info!("Uploaded app_config.json to s3://{}/{}", s3_config.s3_bucket, app_config_key);
    }

    let (status, message) = match result {
        Ok(_) => {
             info!("Successfully uploaded config to s3://{}/{}", s3_config.s3_bucket, key);
             ("success", format!("Successfully published config to s3://{}/{}", s3_config.s3_bucket, key))
        }
        Err(e) => {
             error!("Failed to upload config to S3: {}", e);
             ("error", format!("Failed to publish to S3: {}", e))
        }
    };

    Redirect::to(&format!("/?tab=preview&status={}&message={}", status, urlencoding::encode(&message)))
}

async fn delete_status(
    State(state): State<Arc<AppState>>,
    Form(form): Form<DeleteStatusForm>,
) -> impl IntoResponse {
    let s3_config = &state.s3_config;
    
    if s3_config.s3_bucket.is_empty() {
        return Redirect::to("/?tab=status&status=error&message=S3+not+configured");
    }

    let client = create_s3_client(s3_config).await;

    let folder = s3_config.s3_folder.trim_end_matches('/');
    let prefix = if folder.is_empty() {
        "".to_string()
    } else {
        format!("{}/", folder)
    };

    // Try deleting .status
    let status_key = format!("{}{}.status", prefix, form.hostname);
    let _ = client.delete_object().bucket(&s3_config.s3_bucket).key(status_key).send().await;

    // Clean up legacy files just in case
    let ok_key = format!("{}{}.loaded_ok", prefix, form.hostname);
    let _ = client.delete_object().bucket(&s3_config.s3_bucket).key(ok_key).send().await;
    let error_key = format!("{}{}.loaded_error", prefix, form.hostname);
    let _ = client.delete_object().bucket(&s3_config.s3_bucket).key(error_key).send().await;
    let live_key = format!("{}{}.live", prefix, form.hostname);
    let _ = client.delete_object().bucket(&s3_config.s3_bucket).key(live_key).send().await;

    Redirect::to("/?tab=status")
}

fn save_config(config: &AppConfig, path: &PathBuf) {
    if let Ok(json) = serde_json::to_string_pretty(config) {
        if let Err(e) = fs::write(path, json) {
            error!("Failed to save app config: {}", e);
        }
    }
}
