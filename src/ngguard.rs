use std::process::Stdio;
use std::time::Duration;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use anyhow::{Result, Context};
use tracing::{info, error, warn};
use serde::{Deserialize, Serialize};
use tokio::time;
use tokio::process::{Command, Child};
use tokio::io::{AsyncReadExt, BufReader};
use aws_config::BehaviorVersion;
use aws_sdk_s3::primitives::ByteStream;
use clap::Parser;
use std::env;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the optional S3 configuration file
    #[arg(short, long)]
    config: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
struct AppSettings {
    nginx_binary_path: String,
    nginx_working_dir: String,
    // nginx_conf_download_path removed, derived from working_dir
}

#[derive(Deserialize, Debug, Clone)]
struct S3Config {
    s3_endpoint: String,
    s3_bucket: String,
    s3_folder: String,
    s3_access_key: String,
    s3_secret_key: String,
}

#[derive(Debug, Clone)]
struct GuardConfig {
    app: AppSettings,
    s3: S3Config,
}

impl GuardConfig {
    async fn load(s3_config_path: Option<&str>) -> Result<Self> {
        // 1. Load S3 Settings
        let s3 = if let Some(path) = s3_config_path {
            info!("Loading S3 config from file: {}", path);
            let s3_content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read S3 config from {}", path))?;
            let s3_json: serde_json::Value = serde_json::from_str(&s3_content)?;
            
            S3Config {
                s3_endpoint: s3_json["s3_endpoint"].as_str().unwrap_or("").to_string(),
                s3_bucket: s3_json["s3_bucket"].as_str().unwrap_or("").to_string(),
                s3_folder: s3_json["s3_folder"].as_str().unwrap_or("").to_string(),
                s3_access_key: s3_json["s3_access_key"].as_str().unwrap_or("").to_string(),
                s3_secret_key: s3_json["s3_secret_key"].as_str().unwrap_or("").to_string(),
            }
        } else {
            info!("Loading S3 config from environment variables");
            S3Config {
                s3_endpoint: env::var("S3_ENDPOINT").unwrap_or_default(),
                s3_bucket: env::var("S3_BUCKET").unwrap_or_default(),
                s3_folder: env::var("S3_FOLDER").unwrap_or_default(),
                s3_access_key: env::var("S3_ACCESS_KEY").unwrap_or_default(),
                s3_secret_key: env::var("S3_SECRET_KEY").unwrap_or_default(),
            }
        };

        if s3.s3_bucket.is_empty() {
            anyhow::bail!("S3_BUCKET is required but not set.");
        }

        // 2. Initialize temp S3 Client to download app settings
        let region_provider = if !s3.s3_endpoint.is_empty() {
            aws_config::meta::region::RegionProviderChain::first_try(aws_config::Region::new("us-east-1"))
        } else {
            aws_config::meta::region::RegionProviderChain::default_provider()
                .or_else("us-east-1")
        };

        let creds = aws_credential_types::Credentials::new(
            s3.s3_access_key.clone(),
            s3.s3_secret_key.clone(),
            None,
            None,
            "static"
        );

        let sdk_config = if !s3.s3_endpoint.is_empty() {
            aws_config::defaults(BehaviorVersion::latest())
                .region(region_provider)
                .credentials_provider(creds)
                .endpoint_url(s3.s3_endpoint.clone())
                .load()
                .await
        } else {
            aws_config::defaults(BehaviorVersion::latest())
                .region(region_provider)
                .credentials_provider(creds)
                .load()
                .await
        };

        let client = if !s3.s3_endpoint.is_empty() {
            let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
                .force_path_style(true)
                .build();
            aws_sdk_s3::Client::from_conf(s3_config)
        } else {
            aws_sdk_s3::Client::new(&sdk_config)
        };

        // 3. Download ngguard.json
        let folder = s3.s3_folder.trim_end_matches('/');
        let key = if folder.is_empty() {
            "ngguard.json".to_string()
        } else {
            format!("{}/ngguard.json", folder)
        };

        info!("Downloading app settings from s3://{}/{}", s3.s3_bucket, key);
        
        let get_resp = client.get_object()
            .bucket(&s3.s3_bucket)
            .key(&key)
            .send()
            .await
            .with_context(|| format!("Failed to download ngguard.json from s3://{}/{}", s3.s3_bucket, key))?;

        let bytes = get_resp.body.collect().await?.into_bytes();
        let app_content = String::from_utf8(bytes.to_vec())?;
        
        let app_json: serde_json::Value = serde_json::from_str(&app_content)?;
        
        let app = AppSettings {
            nginx_binary_path: app_json["nginx_binary_path"].as_str().unwrap_or("/usr/sbin/nginx").to_string(),
            nginx_working_dir: app_json["nginx_working_dir"].as_str().unwrap_or("/etc/nginx").to_string(),
        };

        info!("Loaded app settings: nginx_binary={}", app.nginx_binary_path);

        Ok(GuardConfig { app, s3 })
    }
}

#[derive(Serialize)]
struct StatusReport {
    success: bool,
    timestamp: u64,
    last_100_error_logs: String,
    stdout: String,
    stderr: String,
}

fn cleanup_existing_processes(config: &GuardConfig) {
    info!("Scanning for stale Nginx processes to clean up...");
    
    // Try to canonicalize config paths for better matching
    let target_binary = std::fs::canonicalize(&config.app.nginx_binary_path)
        .unwrap_or_else(|_| PathBuf::from(&config.app.nginx_binary_path));
        
    let target_cwd = std::fs::canonicalize(&config.app.nginx_working_dir)
        .unwrap_or_else(|_| PathBuf::from(&config.app.nginx_working_dir));
    
    let target_cwd_str = target_cwd.to_string_lossy();

    if let Ok(processes) = procfs::process::all_processes() {
        for p in processes {
            if let Ok(process) = p {
                let pid = process.pid;
                let mut matched_binary = false;
                let mut matched_cwd = false;

                // Check Binary
                if let Ok(exe) = process.exe() {
                    if exe == target_binary {
                        matched_binary = true;
                    } else if let Some(name) = exe.file_name() {
                        // Log if we see an nginx process that doesn't match our binary path, just for diagnostics
                        if name.to_string_lossy() == "nginx" {
                            info!("[PID {}] Found 'nginx' binary but path mismatch: {:?} != {:?}", pid, exe, target_binary);
                        }
                    }
                }

                if !matched_binary {
                    continue;
                }

                // Check CWD
                if let Ok(cwd) = process.cwd() {
                    if cwd == target_cwd {
                        matched_cwd = true;
                    } else {
                        info!("[PID {}] Binary matched, but CWD mismatch: {:?} != {:?}", pid, cwd, target_cwd);
                    }
                }
                
                // If CWD matching failed, check command line args for -p <working_dir>
                // This handles cases where CWD is different (e.g. started elsewhere) but -p was used
                if !matched_cwd {
                    if let Ok(cmdline) = process.cmdline() {
                        // Join all args to handle potential Nginx process title rewriting which might mess up array slotting
                        let full_cmdline = cmdline.join(" ");
                        
                        // Construct the expected argument string
                        let p_arg = format!("-p {}", target_cwd_str);
                        
                        if full_cmdline.contains(&p_arg) {
                            info!("[PID {}] Matched via cmdline argument: '{}'", pid, p_arg);
                            matched_cwd = true;
                        } else {
                            info!("[PID {}] Cmdline did not contain '{}'. Saw: '{}'", pid, p_arg, full_cmdline);
                        }
                    }
                }
                
                if matched_binary && matched_cwd {
                    info!("Found stale Nginx process (PID: {}). Killing...", pid);
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        }
    }
}

struct NginxManager {
    child: Option<Child>,
    config: GuardConfig,
    hostname: String,
    client: aws_sdk_s3::Client,
    last_config_timestamp: Option<aws_smithy_types::DateTime>,
    last_config_etag: Option<String>,
    failed_config_timestamp: Option<aws_smithy_types::DateTime>,
    
    last_app_config_timestamp: Option<aws_smithy_types::DateTime>,
    last_app_config_etag: Option<String>,
    
    stdout_buffer: Arc<Mutex<String>>,
    stderr_buffer: Arc<Mutex<String>>,
}

impl NginxManager {
    async fn new(config: GuardConfig) -> Result<Self> {
        let hostname = hostname::get()?.into_string().unwrap_or_else(|_| "unknown_host".to_string());
        
        let region_provider = if !config.s3.s3_endpoint.is_empty() {
            aws_config::meta::region::RegionProviderChain::first_try(aws_config::Region::new("us-east-1"))
        } else {
            aws_config::meta::region::RegionProviderChain::default_provider()
                .or_else("us-east-1")
        };

        let creds = aws_credential_types::Credentials::new(
            config.s3.s3_access_key.clone(),
            config.s3.s3_secret_key.clone(),
            None,
            None,
            "static"
        );

        let sdk_config = if !config.s3.s3_endpoint.is_empty() {
            aws_config::defaults(BehaviorVersion::latest())
                .region(region_provider)
                .credentials_provider(creds)
                .endpoint_url(config.s3.s3_endpoint.clone())
                .load()
                .await
        } else {
            aws_config::defaults(BehaviorVersion::latest())
                .region(region_provider)
                .credentials_provider(creds)
                .load()
                .await
        };

        let client = if !config.s3.s3_endpoint.is_empty() {
            let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
                .force_path_style(true)
                .build();
            aws_sdk_s3::Client::from_conf(s3_config)
        } else {
            aws_sdk_s3::Client::new(&sdk_config)
        };

        Ok(Self {
            child: None,
            config,
            hostname,
            client,
            last_config_timestamp: None,
            last_config_etag: None,
            failed_config_timestamp: None,
            last_app_config_timestamp: None,
            last_app_config_etag: None,
            stdout_buffer: Arc::new(Mutex::new(String::new())),
            stderr_buffer: Arc::new(Mutex::new(String::new())),
        })
    }

    fn get_error_log_path(&self) -> PathBuf {
        PathBuf::from(&self.config.app.nginx_working_dir).join("error.log")
    }

    async fn upload_status(&self, success: bool, content: Option<String>) -> Result<()> {
        let folder = self.config.s3.s3_folder.trim_end_matches('/');
        let prefix = if folder.is_empty() {
            "".to_string()
        } else {
            format!("{}/", folder)
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let stdout_content = self.stdout_buffer.lock().unwrap().clone();
        let stderr_content = self.stderr_buffer.lock().unwrap().clone();

        let report = StatusReport {
            success,
            timestamp,
            last_100_error_logs: content.unwrap_or_default(),
            stdout: stdout_content,
            stderr: stderr_content,
        };

        let json_body = serde_json::to_string(&report)?;
        let status_key = format!("{}{}.status", prefix, self.hostname);

        self.client.put_object()
            .bucket(&self.config.s3.s3_bucket)
            .key(&status_key)
            .body(ByteStream::from(json_body.into_bytes()))
            .send()
            .await?;

        // Clean up old status files if they exist (legacy cleanup)
        let old_ok_key = format!("{}{}.loaded_ok", prefix, self.hostname);
        let _ = self.client.delete_object().bucket(&self.config.s3.s3_bucket).key(&old_ok_key).send().await;
        let old_err_key = format!("{}{}.loaded_error", prefix, self.hostname);
        let _ = self.client.delete_object().bucket(&self.config.s3.s3_bucket).key(&old_err_key).send().await;

        Ok(())
    }

    async fn check_and_reload(&mut self) -> Result<()> {
        info!("Heartbeat: Checking for config updates...");
        let folder = self.config.s3.s3_folder.trim_end_matches('/');
        let prefix = if folder.is_empty() {
            "".to_string()
        } else {
            format!("{}/", folder)
        };
        let config_key = format!("{}nginx.conf", prefix);
        let app_config_key = format!("{}ngguard.json", prefix);

        let mut restart_required = false;

        // 1. Check ngguard.json (App Config)
        let app_head_resp = self.client.head_object()
            .bucket(&self.config.s3.s3_bucket)
            .key(&app_config_key)
            .send()
            .await;

        if let Ok(resp) = app_head_resp {
            let etag = resp.e_tag.unwrap_or_default();
            let last_modified = resp.last_modified.unwrap();

            let app_config_changed = match &self.last_app_config_timestamp {
                Some(ts) => last_modified.as_nanos() > ts.as_nanos(),
                None => true,
            };

            if app_config_changed {
                info!("App config update detected (Timestamp: {:?}). Downloading new ngguard.json...", last_modified);
                // Download new ngguard.json
                let get_resp = self.client.get_object()
                    .bucket(&self.config.s3.s3_bucket)
                    .key(&app_config_key)
                    .send()
                    .await;

                if let Ok(get_resp) = get_resp {
                    if let Ok(bytes) = get_resp.body.collect().await {
                        if let Ok(app_content) = String::from_utf8(bytes.into_bytes().to_vec()) {
                            if let Ok(app_json) = serde_json::from_str::<serde_json::Value>(&app_content) {
                                // Update config
                                self.config.app = AppSettings {
                                    nginx_binary_path: app_json["nginx_binary_path"].as_str().unwrap_or("/usr/sbin/nginx").to_string(),
                                    nginx_working_dir: app_json["nginx_working_dir"].as_str().unwrap_or("/etc/nginx").to_string(),
                                };
                                
                                self.last_app_config_timestamp = Some(last_modified);
                                self.last_app_config_etag = Some(etag);
                                restart_required = true;
                                info!("App config updated successfully.");
                            } else {
                                error!("Failed to parse ngguard.json");
                            }
                        }
                    }
                }
            }
        }

        // 2. Check nginx.conf
        // Head object to check for changes
        let head_resp = self.client.head_object()
            .bucket(&self.config.s3.s3_bucket)
            .key(&config_key)
            .send()
            .await;

        let (etag, last_modified) = match head_resp {
            Ok(resp) => (resp.e_tag.unwrap_or_default(), resp.last_modified.unwrap()),
            Err(_) => {
                warn!("Could not fetch nginx.conf metadata from S3");
                return Ok(());
            }
        };

        // Determine if we need to download new config
        // Derive config path from working dir
        let config_path = PathBuf::from(&self.config.app.nginx_working_dir).join("nginx.conf");
        let config_exists = config_path.exists();
        
        // Check if config has changed based on timestamp
        // Also consider it changed if local file is missing
        let is_new_timestamp = match &self.last_config_timestamp {
            Some(ts) => last_modified.as_nanos() > ts.as_nanos(),
            None => true,
        };

        // If it's a known failed config timestamp, skip unless it's newer than the failed one
        if let Some(failed_ts) = &self.failed_config_timestamp {
            if last_modified.as_nanos() <= failed_ts.as_nanos() && is_new_timestamp {
                if last_modified.as_nanos() == failed_ts.as_nanos() {
                    info!("Skipping known bad config (Timestamp: {:?}). Waiting for update.", last_modified);
                    if !restart_required {
                        return Ok(());
                    }
                }
            }
        }

        let config_changed = is_new_timestamp || !config_exists;

        if config_changed {
            info!("Config update detected (Timestamp: {:?}, ETag: {}) or missing local config.", last_modified, etag);
            
            if let Some(last_etag) = &self.last_config_etag {
                if last_etag == &etag {
                    info!("Content identical to previous config (ETag match), but timestamp changed. Forcing restart.");
                }
            }

            // Backup existing config if it exists
            if config_exists {
                let backup_path = config_path.with_extension("bak");
                if let Err(e) = std::fs::copy(&config_path, &backup_path) {
                    warn!("Failed to backup existing config: {}", e);
                } else {
                    info!("Backed up existing config to {:?}", backup_path);
                }
            }
            
            // Download config
            info!("Fetching config from s3://{}/{}", self.config.s3.s3_bucket, config_key);
            let get_resp = self.client.get_object()
                .bucket(&self.config.s3.s3_bucket)
                .key(&config_key)
                .send()
                .await?;

            let data = get_resp.body.collect().await?.into_bytes();
            
            // Ensure directory exists
            if let Some(parent) = config_path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    let msg = format!("Failed to create directory {:?}: {}", parent, e);
                    error!("{}", msg);
                    let _ = self.upload_status(false, Some(msg)).await;
                    return Err(e.into());
                }
            }
            
            if let Err(e) = std::fs::write(&config_path, data) {
                let msg = format!("Failed to write config file {:?}: {}", config_path, e);
                error!("{}", msg);
                let _ = self.upload_status(false, Some(msg)).await;
                return Err(e.into());
            }

            info!("Successfully downloaded and wrote config to {:?}", config_path);
            restart_required = true;
        } else {
            info!("No configuration change detected (Timestamp: {:?}).", last_modified);
        }

        // Now decide if we need to restart/start Nginx
        let needs_restart = if restart_required {
            info!("Restart required due to configuration change.");
            true
        } else if let Some(child) = &mut self.child {
            if let Ok(Some(status)) = child.try_wait() {
                warn!("Nginx exited unexpectedly with status: {}. Restarting...", status);
                // Upload status because nginx died
                let error_log_path = self.get_error_log_path();
                let error_log_content = match std::fs::read_to_string(&error_log_path) {
                    Ok(content) => content.lines().rev().take(100).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n"),
                    Err(_) => "Nginx died unexpectedly. Could not read error log.".to_string(),
                };
                let _ = self.upload_status(false, Some(error_log_content)).await;
                true
            } else {
                false // Running fine, config match
            }
        } else {
            // Child is None (e.g. previous start failed)
            info!("Nginx is not running. Starting...");
            true
        };

        if needs_restart {
            // Stop existing nginx if running
            if let Some(mut child) = self.child.take() {
                if let Some(id) = child.id() {
                    info!("Stopping existing Nginx process group (PID: {})...", id);
                    // Kill the process group
                    unsafe {
                        libc::kill(-(id as i32), libc::SIGKILL);
                    }
                    let _ = child.wait().await;
                    info!("Existing Nginx process group terminated.");
                }
            }

            // Wait a bit for cleanup
            tokio::time::sleep(Duration::from_millis(500)).await;

            // Clear previous logs
            {
                let mut stdout = self.stdout_buffer.lock().unwrap();
                stdout.clear();
                let mut stderr = self.stderr_buffer.lock().unwrap();
                stderr.clear();
            }

            // Start Nginx
            info!("Spawning new Nginx process...");
            let mut child = Command::new(&self.config.app.nginx_binary_path)
                .arg("-p")
                .arg(&self.config.app.nginx_working_dir)
                .arg("-c")
                .arg(&config_path)
                .current_dir(&self.config.app.nginx_working_dir)
                .process_group(0) // Create a new process group for nginx and its children
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to spawn nginx")?;
            
            let pid = child.id().unwrap_or(0);
            info!("Nginx spawned with PID: {}", pid);

            // Capture stdout/stderr
            if let Some(stdout) = child.stdout.take() {
                let buffer = self.stdout_buffer.clone();
                tokio::spawn(async move {
                    let mut reader = BufReader::new(stdout);
                    let mut chunk = [0; 1024];
                    loop {
                        match reader.read(&mut chunk).await {
                            Ok(0) => break, // EOF
                            Ok(n) => {
                                let s = String::from_utf8_lossy(&chunk[..n]);
                                let mut buf = buffer.lock().unwrap();
                                buf.push_str(&s);
                                // Limit buffer size to ~10KB to prevent memory issues
                                if buf.len() > 10240 {
                                    let len = buf.len();
                                    let new_start = len - 10240;
                                    *buf = buf[new_start..].to_string();
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }

            if let Some(stderr) = child.stderr.take() {
                let buffer = self.stderr_buffer.clone();
                tokio::spawn(async move {
                    let mut reader = BufReader::new(stderr);
                    let mut chunk = [0; 1024];
                    loop {
                        match reader.read(&mut chunk).await {
                            Ok(0) => break, // EOF
                            Ok(n) => {
                                let s = String::from_utf8_lossy(&chunk[..n]);
                                let mut buf = buffer.lock().unwrap();
                                buf.push_str(&s);
                                // Limit buffer size to ~10KB
                                if buf.len() > 10240 {
                                    let len = buf.len();
                                    let new_start = len - 10240;
                                    *buf = buf[new_start..].to_string();
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }

            // Wait up to 10 seconds to check if it stays alive
            let mut success = true;
            
            // Simple poll for 10 seconds
            for i in 0..20 {
                if let Ok(Some(status)) = child.try_wait() {
                    error!("Nginx exited immediately with status: {}", status);
                    success = false;
                    break;
                }
                if i % 5 == 0 {
                    info!("Nginx is running... (check {}/20)", i + 1);
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            if success {
                info!("Nginx successfully started and stable.");
                self.child = Some(child);
                self.upload_status(true, None).await?;
                
                // Update state on success
                if config_changed {
                    self.last_config_timestamp = Some(last_modified);
                    self.last_config_etag = Some(etag);
                    // Clear failed timestamp if we succeeded with a newer config
                    self.failed_config_timestamp = None; 
                }
            } else {
                warn!("Nginx failed to start. Collecting error logs...");
                // Collect error log
                let error_log_path = self.get_error_log_path();
                let error_log_content = match std::fs::read_to_string(&error_log_path) {
                    Ok(content) => {
                        // Get last 100 lines or so
                        content.lines().rev().take(100).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n")
                    },
                    Err(e) => format!("Could not read error log from {:?}: {}", error_log_path, e),
                };

                self.upload_status(false, Some(error_log_content)).await?;
                
                if config_changed {
                    self.failed_config_timestamp = Some(last_modified);
                    error!("New configuration failed. Rollback is DISABLED as per configuration.");
                }
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    if let Some(path) = &args.config {
        info!("Starting ngguard using S3 config file: {}", path);
    } else {
        info!("Starting ngguard using Environment Variables for S3 config");
    }

    let config = GuardConfig::load(args.config.as_deref())
        .await
        .context("Failed to load configuration")?;
    
    // Initial cleanup: kill any existing nginx processes before starting management
    // Use robust process matching instead of broad pkill
    cleanup_existing_processes(&config);
    
    // Give it a moment to clean up
    time::sleep(Duration::from_secs(1)).await;
    
    let mut manager = NginxManager::new(config).await?;

    // Initial run
    if let Err(e) = manager.check_and_reload().await {
        error!("Error in initial check: {}", e);
        // Upload initial error status if something critical failed early
        let _ = manager.upload_status(false, Some(format!("Critical ngguard error: {}", e))).await;
    }

    let mut interval = time::interval(Duration::from_secs(10));
    loop {
        interval.tick().await;
        if let Err(e) = manager.check_and_reload().await {
            error!("Error checking/reloading nginx: {}", e);
        }
    }
}
