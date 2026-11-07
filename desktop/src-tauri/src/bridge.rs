use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

const MAX_RESPONSE: u64 = 1_048_576;
const MAX_CLI_OUTPUT: usize = 1_048_576;
const DEADLINE: Duration = Duration::from_secs(8);
const DAEMON_STARTUP_DEADLINE: Duration = Duration::from_secs(3);

#[derive(Default)]
pub struct DaemonSupervisor {
    owned: Mutex<Option<Child>>,
}

impl DaemonSupervisor {
    pub fn shutdown(&self) {
        if let Ok(mut owned) = self.owned.lock() {
            if let Some(mut child) = owned.take() {
                stop_daemon(&mut child);
            }
        }
    }

    pub fn ensure_running(&self) -> Result<(), String> {
        require_user()?;
        // An explicit socket is managed by its caller; never start a daemon for it.
        if std::env::var_os("FBI_GO_SOCKET").is_some() {
            return Ok(());
        }
        let path = socket_path()?;
        let cli = cli_path()?;
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or("XDG_RUNTIME_DIR is required for the read-only daemon")?;
        self.ensure_at(&runtime, &path, &cli)
    }

    fn ensure_at(&self, runtime: &Path, socket: &Path, cli: &Path) -> Result<(), String> {
        let mut owned = self
            .owned
            .lock()
            .map_err(|_| "daemon supervisor lock failed")?;
        match fs::symlink_metadata(socket) {
            Ok(_) => {
                return daemon_read_at(socket, "daemon.ping")
                    .and_then(|result| {
                        (result["pong"] == true)
                            .then_some(())
                            .ok_or("daemon ping did not succeed".into())
                    })
                    .map_err(|e| format!("existing daemon socket is unavailable: {e}"));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("inspect daemon socket: {e}")),
        }
        if let Some(child) = owned.as_mut() {
            if child
                .try_wait()
                .map_err(|e| format!("inspect managed daemon: {e}"))?
                .is_none()
            {
                return Err("managed daemon is running but its socket is unavailable".into());
            }
            *owned = None;
        }
        prepare_default_socket_dir(runtime, socket)?;
        let mut command = Command::new(cli);
        command
            .args(["daemon", "serve", "--dry-run", "--socket"])
            .arg(socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .map_err(|e| format!("start bundled read-only daemon: {e}"))?;
        let start = Instant::now();
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|e| format!("wait for daemon: {e}"))?
            {
                let mut message = String::new();
                if let Some(stderr) = child.stderr.take() {
                    let _ = stderr.take(4096).read_to_string(&mut message);
                }
                return Err(format!(
                    "read-only daemon exited {status}: {}",
                    message.trim()
                ));
            }
            if fs::symlink_metadata(socket).is_ok()
                && daemon_read_at(socket, "daemon.ping").is_ok_and(|value| value["pong"] == true)
            {
                *owned = Some(child);
                return Ok(());
            }
            if start.elapsed() >= DAEMON_STARTUP_DEADLINE {
                stop_daemon(&mut child);
                return Err("read-only daemon did not become ready within 3 seconds".into());
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for DaemonSupervisor {
    fn drop(&mut self) {
        if let Ok(owned) = self.owned.get_mut() {
            if let Some(mut child) = owned.take() {
                stop_daemon(&mut child);
            }
        }
    }
}

fn stop_daemon(child: &mut Child) {
    if !matches!(child.try_wait(), Ok(Some(_))) {
        unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn prepare_default_socket_dir(runtime: &Path, socket: &Path) -> Result<(), String> {
    if !runtime.is_absolute() || socket != runtime.join("fbi-go/control.sock") {
        return Err("default daemon socket must be inside XDG_RUNTIME_DIR/fbi-go".into());
    }
    let uid = unsafe { libc::geteuid() };
    let valid_private_dir = |path: &Path| -> Result<(), String> {
        let meta = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != uid
            || meta.mode() & 0o777 != 0o700
        {
            return Err(format!(
                "{} must be an owned private 0700 directory",
                path.display()
            ));
        }
        Ok(())
    };
    valid_private_dir(runtime)?;
    let parent = socket
        .parent()
        .ok_or("daemon socket has no parent directory")?;
    match fs::DirBuilder::new().mode(0o700).create(parent) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("create private daemon socket directory: {e}")),
    }
    valid_private_dir(parent)
}

#[derive(Serialize)]
pub struct BackendInfo {
    pub socket: String,
    pub cli: String,
    pub host_apply: &'static str,
}

#[derive(Deserialize)]
pub struct PolicyChange {
    pub id: String,
    pub mode: String,
    pub wan: Option<String>,
    pub behavior: Option<String>,
    pub fallback: Option<String>,
}

fn require_user() -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        Err("desktop backend refuses UID 0".into())
    } else {
        Ok(())
    }
}

fn socket_path() -> Result<PathBuf, String> {
    let path = if let Some(path) = std::env::var_os("FBI_GO_SOCKET") {
        PathBuf::from(path)
    } else {
        let runtime =
            std::env::var_os("XDG_RUNTIME_DIR").ok_or("set FBI_GO_SOCKET or XDG_RUNTIME_DIR")?;
        PathBuf::from(runtime).join("fbi-go/control.sock")
    };
    if !path.is_absolute() {
        return Err("FBI_GO_SOCKET must be absolute".into());
    }
    Ok(path)
}

fn cli_path() -> Result<PathBuf, String> {
    let path = if let Some(path) = std::env::var_os("FBI_GO_BIN") {
        PathBuf::from(path)
    } else {
        std::env::current_exe()
            .map_err(|e| format!("current executable: {e}"))?
            .with_file_name("fbi")
    };
    if !path.is_absolute() {
        return Err("FBI_GO_BIN must be absolute".into());
    }
    let meta = fs::metadata(&path).map_err(|e| format!("CLI {}: {e}", path.display()))?;
    if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
        return Err("CLI path is not an executable regular file".into());
    }
    Ok(path)
}

pub fn backend_info() -> BackendInfo {
    BackendInfo {
        socket: socket_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|e| e),
        cli: cli_path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|e| e),
        host_apply: "UNSUPPORTED",
    }
}

pub(crate) fn valid_method(method: &str) -> bool {
    matches!(
        method,
        "daemon.ping"
            | "daemon.version"
            | "daemon.capabilities"
            | "daemon.status"
            | "daemon.diagnostics"
            | "daemon.plan"
    )
}

fn verify_socket(path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or("socket has no parent")?;
    let dir = fs::symlink_metadata(parent).map_err(|e| format!("socket directory: {e}"))?;
    let sock = fs::symlink_metadata(path).map_err(|e| format!("daemon socket: {e}"))?;
    let uid = unsafe { libc::geteuid() };
    if !dir.is_dir() || dir.file_type().is_symlink() || dir.uid() != uid || dir.mode() & 0o077 != 0
    {
        return Err("daemon socket directory must be private and owned by this user".into());
    }
    if !sock.file_type().is_socket() || sock.uid() != uid || sock.mode() & 0o077 != 0 {
        return Err("daemon socket must be private and owned by this user".into());
    }
    Ok(())
}

fn decode_daemon_response(data: &[u8]) -> Result<Value, String> {
    if data.len() > MAX_RESPONSE as usize || !data.ends_with(b"\n") {
        return Err("invalid daemon response framing or size".into());
    }
    let value: Value = serde_json::from_slice(&data[..data.len() - 1])
        .map_err(|e| format!("daemon response JSON: {e}"))?;
    if value.get("version").and_then(Value::as_i64) != Some(1) {
        return Err("unsupported daemon protocol version".into());
    }
    if let Some(error) = value.get("error") {
        let code = error.get("code").and_then(Value::as_str).unwrap_or("ERROR");
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("daemon rejected request");
        return Err(format!("{code}: {message}"));
    }
    value
        .get("result")
        .cloned()
        .ok_or("daemon response lacks result".into())
}

pub fn daemon_read(method: &str) -> Result<Value, String> {
    require_user()?;
    if !valid_method(method) {
        return Err("method is outside the read-only allowlist".into());
    }
    let path = socket_path()?;
    daemon_read_at(&path, method)
}

fn daemon_read_at(path: &Path, method: &str) -> Result<Value, String> {
    verify_socket(path)?;
    let mut stream = UnixStream::connect(path).map_err(|e| format!("connect daemon: {e}"))?;
    stream
        .set_read_timeout(Some(DEADLINE))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(DEADLINE))
        .map_err(|e| e.to_string())?;
    let request = json!({"version": 1, "method": method, "params": if method == "daemon.plan" {
        json!({"policy": {"id": "desktop-preview", "mode": "AUTO", "enabled": true}})
    } else { Value::Null }});
    let mut frame = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    frame.push(b'\n');
    stream
        .write_all(&frame)
        .map_err(|e| format!("send request: {e}"))?;
    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut response)
        .map_err(|e| format!("read response: {e}"))?;
    decode_daemon_response(&response)
}

fn cli_args(kind: &str) -> Result<&'static [&'static str], String> {
    match kind {
        "apps" => Ok(&["app", "list", "--json"]),
        "policies" => Ok(&["app", "policy", "list", "--json"]),
        _ => Err("CLI read is outside the allowlist".into()),
    }
}

fn collect_limited(mut reader: impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let available = MAX_CLI_OUTPUT.saturating_add(1).saturating_sub(bytes.len());
                bytes.extend_from_slice(&chunk[..n.min(available)]);
            }
        }
    }
    bytes
}

fn run_cli(args: &[String]) -> Result<String, String> {
    require_user()?;
    let path = cli_path()?;
    let mut child = Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("start CLI: {e}"))?;
    let stdout = child.stdout.take().ok_or("CLI stdout unavailable")?;
    let stderr = child.stderr.take().ok_or("CLI stderr unavailable")?;
    let out_thread = thread::spawn(move || collect_limited(stdout));
    let err_thread = thread::spawn(move || collect_limited(stderr));
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < DEADLINE => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_thread.join();
                let _ = err_thread.join();
                return Err("CLI timed out".into());
            }
            Err(e) => return Err(format!("wait for CLI: {e}")),
        }
    };
    let out = out_thread.join().map_err(|_| "CLI output reader failed")?;
    let err = err_thread.join().map_err(|_| "CLI error reader failed")?;
    if out.len() > MAX_CLI_OUTPUT || err.len() > MAX_CLI_OUTPUT {
        return Err("CLI output exceeded limit".into());
    }
    if !status.success() {
        return Err(format!(
            "CLI exit {}: {}",
            status.code().unwrap_or(-1),
            String::from_utf8_lossy(&err).trim()
        ));
    }
    String::from_utf8(out).map_err(|e| format!("CLI output encoding: {e}"))
}

pub fn cli_read(kind: &str) -> Result<Value, String> {
    let args = cli_args(kind)?
        .iter()
        .map(|arg| (*arg).to_string())
        .collect::<Vec<_>>();
    let output = run_cli(&args)?;
    serde_json::from_str(&output).map_err(|e| format!("CLI JSON: {e}"))
}

fn valid_desktop_id(id: &str) -> bool {
    id.len() <= 255
        && id.ends_with(".desktop")
        && !id.starts_with('-')
        && !id.contains("..")
        && !id
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control() || c.is_whitespace())
}

fn valid_mac_id(id: &str) -> bool {
    let Some(raw) = id.strip_prefix("mac:") else {
        return false;
    };
    let parts = raw.split(':').collect::<Vec<_>>();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn policy_args(change: &PolicyChange) -> Result<Vec<String>, String> {
    if !valid_desktop_id(&change.id) {
        return Err("invalid desktop entry ID".into());
    }
    let mut args = vec![
        "app".into(),
        "policy".into(),
        "set".into(),
        change.id.clone(),
    ];
    match change.mode.as_str() {
        "AUTO"
            if change.wan.is_none() && change.fallback.is_none() && change.behavior.is_none() =>
        {
            args.push("--auto".into())
        }
        "PINNED_WAN" => {
            let wan = change.wan.as_deref().ok_or("preferred WAN required")?;
            if !valid_mac_id(wan) {
                return Err("preferred WAN must be a MAC identity".into());
            }
            args.extend(["--wan".into(), wan.into(), "--mode".into()]);
            match change.behavior.as_deref() {
                Some("STRICT") if change.fallback.is_none() => args.push("strict".into()),
                Some("FAILOVER") => {
                    let fallback = change.fallback.as_deref().ok_or("fallback WAN required")?;
                    if !valid_mac_id(fallback) || fallback == wan {
                        return Err("fallback WAN must be a distinct MAC identity".into());
                    }
                    args.extend(["failover".into(), "--fallback".into(), fallback.into()]);
                }
                _ => return Err("invalid pinned failure behavior".into()),
            }
        }
        _ => return Err("unsupported policy change".into()),
    }
    Ok(args)
}

pub fn policy_set(change: PolicyChange) -> Result<(), String> {
    run_cli(&policy_args(&change)?)?;
    Ok(())
}

pub fn policy_remove(id: &str) -> Result<(), String> {
    if !valid_desktop_id(id) {
        return Err("invalid desktop entry ID".into());
    }
    run_cli(&["app".into(), "policy".into(), "remove".into(), id.into()])?;
    Ok(())
}

fn icon_roots() -> Vec<PathBuf> {
    let mut roots = vec![
        PathBuf::from("/usr/share/icons"),
        PathBuf::from("/usr/local/share/icons"),
        PathBuf::from("/usr/share/pixmaps"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        roots.push(PathBuf::from(home).join(".local/share/icons"));
    }
    roots
}

fn icon_file(name: &str) -> Option<PathBuf> {
    if name.len() > 128 || name.contains("..") || name.chars().any(|c| c.is_control()) {
        return None;
    }
    let roots = icon_roots();
    let mut candidates = Vec::new();
    if Path::new(name).is_absolute() {
        candidates.push(PathBuf::from(name));
    } else if !name.contains('/') && !name.contains('\\') {
        for root in &roots {
            for size in ["64x64", "48x48", "32x32", "128x128"] {
                candidates.push(
                    root.join("hicolor")
                        .join(size)
                        .join("apps")
                        .join(format!("{name}.png")),
                );
            }
            candidates.push(root.join(format!("{name}.png")));
        }
    }
    candidates.into_iter().find(|candidate| {
        let Ok(canonical) = candidate.canonicalize() else {
            return false;
        };
        let allowed = roots
            .iter()
            .any(|root| root.canonicalize().is_ok_and(|r| canonical.starts_with(r)));
        allowed
            && matches!(
                canonical.extension().and_then(|v| v.to_str()),
                Some("png") | Some("webp")
            )
            && fs::metadata(&canonical).is_ok_and(|m| m.is_file() && m.len() <= 512_000)
    })
}

pub fn icon_data(name: &str) -> Option<String> {
    let file = icon_file(name)?;
    let bytes = fs::read(&file).ok()?;
    let mime = if file.extension()?.to_str()? == "webp" {
        "image/webp"
    } else {
        "image/png"
    };
    Some(format!(
        "data:{mime};base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::os::unix::net::UnixListener;

    #[test]
    fn allowlists_reject_mutation_and_arbitrary_commands() {
        assert!(valid_method("daemon.plan"));
        assert!(!valid_method("daemon.apply"));
        assert!(!valid_method("HOST_APPLY"));
        assert!(cli_args("apps").is_ok());
        assert!(cli_args("run").is_err());
    }

    #[test]
    fn policy_arguments_cannot_become_shell_or_host_commands() {
        let mut change = PolicyChange {
            id: "org.example.App.desktop".into(),
            mode: "PINNED_WAN".into(),
            wan: Some("mac:aa:bb:cc:dd:ee:ff".into()),
            behavior: Some("STRICT".into()),
            fallback: None,
        };
        assert_eq!(
            policy_args(&change).unwrap(),
            [
                "app",
                "policy",
                "set",
                "org.example.App.desktop",
                "--wan",
                "mac:aa:bb:cc:dd:ee:ff",
                "--mode",
                "strict"
            ]
        );
        change.id = "../../evil.desktop".into();
        assert!(policy_args(&change).is_err());
        change.id = "org.example.App.desktop".into();
        change.wan = Some("--help".into());
        assert!(policy_args(&change).is_err());
    }

    #[test]
    fn response_contract_requires_v1_and_result() {
        assert_eq!(
            decode_daemon_response(b"{\"version\":1,\"result\":{\"pong\":true}}\n").unwrap()
                ["pong"],
            true
        );
        assert!(decode_daemon_response(b"{\"version\":2,\"result\":{}}\n").is_err());
        assert!(decode_daemon_response(b"{\"version\":1,\"result\":{}}").is_err());
    }

    #[test]
    fn private_socket_uses_newline_framing() {
        let dir = std::env::temp_dir().join(format!(
            "fbi-go-ui-ipc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let server = thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            let mut frame = Vec::new();
            std::io::BufReader::new(&mut connection)
                .read_until(b'\n', &mut frame)
                .unwrap();
            let request: Value = serde_json::from_slice(&frame[..frame.len() - 1]).unwrap();
            assert_eq!(frame.last(), Some(&b'\n'));
            assert_eq!(request["method"], "daemon.ping");
            connection
                .write_all(b"{\"version\":1,\"result\":{\"pong\":true}}\n")
                .unwrap();
        });
        assert_eq!(daemon_read_at(&path, "daemon.ping").unwrap()["pong"], true);
        server.join().unwrap();
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn packaged_sidecar_starts_read_only_daemon_and_cleans_up() {
        let target = match std::env::consts::ARCH {
            "x86_64" => "x86_64-unknown-linux-gnu",
            "aarch64" => "aarch64-unknown-linux-gnu",
            other => panic!("unsupported test architecture: {other}"),
        };
        let cli = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("binaries")
            .join(format!("fbi-{target}"));
        assert!(cli.is_file(), "build the Go sidecar before cargo test");
        let runtime = std::env::temp_dir().join(format!(
            "fbi-ui-daemon-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&runtime).unwrap();
        let socket = runtime.join("fbi-go/control.sock");
        let supervisor = DaemonSupervisor::default();
        thread::scope(|scope| {
            let calls: Vec<_> = (0..4)
                .map(|_| scope.spawn(|| supervisor.ensure_at(&runtime, &socket, &cli)))
                .collect();
            for call in calls {
                call.join().unwrap().unwrap();
            }
        });
        assert_eq!(
            daemon_read_at(&socket, "daemon.ping").unwrap()["pong"],
            true
        );
        assert_eq!(
            daemon_read_at(&socket, "daemon.capabilities").unwrap()["mode"],
            "PLAN_ONLY"
        );
        assert_eq!(
            daemon_read_at(&socket, "daemon.capabilities").unwrap()["host_apply"],
            "UNSUPPORTED"
        );
        assert_eq!(fs::symlink_metadata(&socket).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            fs::symlink_metadata(socket.parent().unwrap())
                .unwrap()
                .mode()
                & 0o777,
            0o700
        );

        // A second desktop instance reuses the authenticated socket without owning its process.
        let second = DaemonSupervisor::default();
        second.ensure_at(&runtime, &socket, &cli).unwrap();
        assert!(second.owned.lock().unwrap().is_none());
        drop(second);
        assert!(socket.exists());

        supervisor.shutdown();
        supervisor.shutdown();
        assert!(
            !socket.exists(),
            "the daemon must remove its owned socket on shutdown"
        );
        drop(supervisor);
        fs::remove_dir(runtime.join("fbi-go")).unwrap();
        fs::remove_dir(runtime).unwrap();
    }

    #[test]
    fn daemon_startup_refuses_nonprivate_or_substituted_directories() {
        let runtime = std::env::temp_dir().join(format!(
            "fbi-ui-unsafe-runtime-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&runtime).unwrap();
        let socket = runtime.join("fbi-go/control.sock");
        let foreign = runtime.join("foreign");
        fs::DirBuilder::new().mode(0o700).create(&foreign).unwrap();
        std::os::unix::fs::symlink(&foreign, runtime.join("fbi-go")).unwrap();
        assert!(prepare_default_socket_dir(&runtime, &socket).is_err());
        assert!(foreign.is_dir());
        fs::remove_file(runtime.join("fbi-go")).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(prepare_default_socket_dir(&runtime, &socket).is_err());
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        prepare_default_socket_dir(&runtime, &socket).unwrap();
        fs::write(&socket, b"foreign").unwrap();
        assert!(DaemonSupervisor::default()
            .ensure_at(&runtime, &socket, Path::new("/nonexistent-fbi"))
            .is_err());
        assert_eq!(fs::read(&socket).unwrap(), b"foreign");
        fs::remove_file(socket).unwrap();
        fs::remove_dir(runtime.join("fbi-go")).unwrap();
        fs::remove_dir(foreign).unwrap();
        fs::remove_dir(runtime).unwrap();
    }

    #[test]
    #[ignore = "requires a running read-only Go daemon, built CLI, and disposable XDG config path"]
    fn real_go_contract() {
        let config =
            std::env::var("FBI_GO_DESKTOP_TEST_XDG").expect("temporary XDG config path required");
        assert!(Path::new(&config).is_absolute());
        std::env::set_var("XDG_CONFIG_HOME", &config);
        let capabilities = daemon_read("daemon.capabilities").unwrap();
        assert_eq!(capabilities["mode"], "PLAN_ONLY");
        assert_eq!(capabilities["host_apply"], "UNSUPPORTED");
        assert_eq!(daemon_read("daemon.ping").unwrap()["pong"], true);
        assert_eq!(daemon_read("daemon.version").unwrap()["protocol"], 1);
        let status = daemon_read("daemon.status").unwrap();
        assert_eq!(status["applied"], false);
        assert!(status["snapshot"]["devices"].is_array());
        assert_eq!(
            daemon_read("daemon.diagnostics").unwrap()["read_only"],
            true
        );
        assert_eq!(daemon_read("daemon.plan").unwrap()["applied"], false);
        assert!(cli_read("apps").unwrap().is_array());
        let id = "org.example.FBIUiBridgeTest.desktop";
        policy_set(PolicyChange {
            id: id.into(),
            mode: "AUTO".into(),
            wan: None,
            behavior: None,
            fallback: None,
        })
        .unwrap();
        let policies = cli_read("policies").unwrap();
        assert!(policies
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["policy"]["id"] == id));
        policy_remove(id).unwrap();
        let policies = cli_read("policies").unwrap();
        assert!(!policies
            .as_array()
            .is_some_and(|v| v.iter().any(|p| p["policy"]["id"] == id)));
    }
}
