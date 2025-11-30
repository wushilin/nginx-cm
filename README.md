# Nginx Configuration Manager & Guardian

This project provides a centralized configuration management system for Nginx reverse proxies, specifically focused on SNI routing and stream modules. It consists of two main components: `nginx-cm` (Configuration Manager) and `ngguard` (Guardian).

These tools use AWS S3 (or compatible object storage) as a synchronization medium, allowing for a decoupled architecture where the control plane (`nginx-cm`) does not need direct network access to the data plane (`ngguard` running on Nginx servers).

## Components

### 1. nginx-cm (Configuration Manager)

A web-based control plane to manage Nginx configurations.

**Features:**
- **Web Interface:** Easy-to-use UI to manage Listeners and SNI Mappings.
- **Configuration Generation:** automatically generates `nginx.conf` based on defined rules using templates.
- **S3 Publishing:** Pushes generated configurations (`nginx.conf`) and agent settings (`ngguard.json`) to an S3 bucket.
- **Configuration Backup:** Automatically backs up its own state (`app_config.json`) to S3 and restores it on startup.
- **Status Monitoring:** Displays the health and status of connected Nginx nodes by reading status files from S3.

**Usage:**
```bash
# Run with S3 config file
./nginx-cm --config s3_config.json

# Or run with Environment Variables
export S3_BUCKET=my-bucket
export S3_ACCESS_KEY=...
export S3_SECRET_KEY=...
./nginx-cm
```

### 2. ngguard (Guardian)

An agent that runs alongside Nginx on your edge/proxy servers.

**Features:**
- **Automatic Updates:** Polls S3 for configuration changes.
- **Process Management:** Manages the Nginx process lifecycle (Start, Stop, Restart).
- **Cleanup:** Automatically detects and kills stale Nginx processes that don't match the current configuration.
- **Health Reporting:** Uploads status reports (including success/failure states, error logs, stdout/stderr) back to S3.
- **Error Handling:** Captures Nginx error logs upon startup failure to aid debugging via the `nginx-cm` UI.

**Usage:**
```bash
# Run with S3 config file
./ngguard --config s3_config.json

# Or run with Environment Variables
export S3_BUCKET=my-bucket
export S3_ACCESS_KEY=...
export S3_SECRET_KEY=...
./ngguard
```

## Workflow

1.  **Configure:** Admin uses `nginx-cm` UI to define listeners (ports) and SNI mappings (domain patterns -> target backends).
2.  **Publish:** Admin clicks "Publish to S3". `nginx-cm` uploads `nginx.conf` and `ngguard.json` to the configured S3 bucket.
3.  **Sync:** `ngguard` instances running on remote servers detect the change in S3.
4.  **Apply:** `ngguard` downloads the new config, writes it to disk, and restarts the Nginx process.
5.  **Report:** `ngguard` uploads a status report to S3.
6.  **Monitor:** `nginx-cm` reads the status report from S3 and updates the UI to show if the deployment was successful.

## Configuration

### S3 Configuration
Both components require access to the same S3 bucket. You can provide this via a JSON file or Environment Variables.

**JSON Format (`s3_config.json`):**
```json
{
  "s3_endpoint": "https://s3.us-east-1.amazonaws.com",
  "s3_bucket": "my-nginx-configs",
  "s3_folder": "prod/cluster-1",
  "s3_access_key": "YOUR_ACCESS_KEY",
  "s3_secret_key": "YOUR_SECRET_KEY"
}
```

**Environment Variables:**
- `S3_ENDPOINT` (Optional, defaults to AWS US-East-1)
- `S3_BUCKET` (Required)
- `S3_FOLDER` (Optional, prefix for keys)
- `S3_ACCESS_KEY`
- `S3_SECRET_KEY`

### Application Config (`app_config.json`)
`nginx-cm` stores its state in `app_config.json`. This file is automatically backed up to S3 upon publish and restored on startup if missing.

## Building

The project is written in Rust.

```bash
# Build both binaries
cargo build --release
```

Binaries will be available in `target/release/nginx-cm` and `target/release/ngguard`.

## License

Apache-2.0

