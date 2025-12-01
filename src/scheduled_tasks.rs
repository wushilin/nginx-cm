use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, error};
use crate::{S3Config, create_s3_client};

// Trait for individual tasks
#[async_trait::async_trait]
pub trait ScheduledTask: Send + Sync {
    fn name(&self) -> &str;
    fn interval(&self) -> Duration;
    async fn run(&self, context: &TaskContext) -> anyhow::Result<()>;
}

// Context passed to tasks (can be expanded)
pub struct TaskContext {
    pub s3_config: S3Config,
    pub heartbeat_interval_minutes: u64,
}

// Task Runner
pub struct TaskRunner {
    tasks: Vec<Box<dyn ScheduledTask>>,
    last_success: Vec<Option<Instant>>,
    context: Arc<TaskContext>,
}

impl TaskRunner {
    pub fn new(context: TaskContext) -> Self {
        Self {
            tasks: Vec::new(),
            last_success: Vec::new(),
            context: Arc::new(context),
        }
    }

    pub fn add_task<T: ScheduledTask + 'static>(&mut self, task: T) {
        self.tasks.push(Box::new(task));
        self.last_success.push(None);
    }

    pub async fn start(self) {
        let mut runner = self; // Move ownership into the async block
        let mut interval = tokio::time::interval(Duration::from_secs(60)); // Global tick every minute

        loop {
            interval.tick().await;
            
            // Reload config dynamically to catch interval changes or S3 updates
            // In a real app we might want a better way to share this, but loading env/file is cheap enough for 1 min
            // However, for now we rely on the initial context, but let's refresh the heartbeat interval from the main config lock if possible.
            // Since we don't have easy access to AppState here, we'll stick to the context provided.
            // Ideally, we should pass an Arc<Mutex<AppConfig>> to context.
            
            for (i, task) in runner.tasks.iter().enumerate() {
                let should_run = match runner.last_success[i] {
                    Some(last) => last.elapsed() >= task.interval(),
                    None => true,
                };

                if should_run {
                    info!("Running task: {}", task.name());
                    match task.run(&runner.context).await {
                        Ok(_) => {
                            info!("Task {} completed successfully.", task.name());
                            runner.last_success[i] = Some(Instant::now());
                        }
                        Err(e) => {
                            error!("Task {} failed: {}", task.name(), e);
                            // Don't update last_success, so it retries next tick (or whenever condition allows)
                        }
                    }
                }
            }
        }
    }
}

// --- Specific Tasks ---

pub struct CleanupStatusTask;

#[async_trait::async_trait]
impl ScheduledTask for CleanupStatusTask {
    fn name(&self) -> &str {
        "Cleanup Stale Status Files"
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(60) // Run check every minute
    }

    async fn run(&self, context: &TaskContext) -> anyhow::Result<()> {
        if context.s3_config.s3_bucket.is_empty() {
            return Ok(());
        }

        let client = create_s3_client(&context.s3_config).await;
        let folder = context.s3_config.s3_folder.trim_end_matches('/');
        let prefix = if folder.is_empty() {
            "".to_string()
        } else {
            format!("{}/", folder)
        };

        let mut paginator = client.list_objects_v2()
            .bucket(&context.s3_config.s3_bucket)
            .prefix(&prefix)
            .into_paginator()
            .send();

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Threshold: 20x heartbeat interval
        // We need to access the heartbeat interval. For now, let's use the one from context.
        // Note: This doesn't strictly sync with the "AppConfig" mutex if changed at runtime without restart,
        // unless we wire that up. But for now, using the startup value or value passed in is fine.
        let interval_secs = context.heartbeat_interval_minutes * 60;
        let remove_threshold = 20 * interval_secs;

        while let Some(page) = paginator.next().await {
            if let Ok(output) = page {
                for obj in output.contents.unwrap_or_default() {
                    let key = obj.key.as_deref().unwrap_or_default();
                    
                    let last_modified = match obj.last_modified {
                        Some(t) => t,
                        None => continue,
                    };
                    let last_modified_secs = last_modified.secs() as u64;

                    let should_delete = if key.ends_with(".status") {
                        current_time > last_modified_secs && (current_time - last_modified_secs) > remove_threshold
                    } else if key.ends_with(".live") || key.ends_with(".loaded_ok") || key.ends_with(".loaded_error") {
                        // Always delete legacy files
                        true
                    } else {
                        false
                    };

                    if should_delete {
                        info!("Deleting stale/legacy file: {} (Last modified: {:?})", key, last_modified);
                        let _ = client.delete_object()
                            .bucket(&context.s3_config.s3_bucket)
                            .key(key)
                            .send()
                            .await;
                    }
                }
            }
        }

        Ok(())
    }
}

