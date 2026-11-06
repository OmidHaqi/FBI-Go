#[cfg_attr(not(feature = "desktop"), allow(dead_code))]
mod bridge;

#[cfg(feature = "desktop")]
use bridge::{BackendInfo, PolicyChange};
#[cfg(feature = "desktop")]
use serde_json::Value;

#[cfg(feature = "desktop")]
#[tauri::command]
fn backend_info() -> BackendInfo {
    bridge::backend_info()
}

#[cfg(feature = "desktop")]
#[tauri::command]
fn daemon_read(method: String) -> Result<Value, String> {
    bridge::daemon_read(&method)
}

#[cfg(feature = "desktop")]
#[tauri::command]
fn cli_read(kind: String) -> Result<Value, String> {
    bridge::cli_read(&kind)
}

#[cfg(feature = "desktop")]
#[tauri::command]
fn policy_set(change: PolicyChange) -> Result<(), String> {
    bridge::policy_set(change)
}

#[cfg(feature = "desktop")]
#[tauri::command]
fn policy_remove(id: String) -> Result<(), String> {
    bridge::policy_remove(&id)
}

#[cfg(feature = "desktop")]
#[tauri::command]
fn icon_data(icon: String) -> Option<String> {
    bridge::icon_data(&icon)
}

#[cfg(feature = "desktop")]
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("FBI-Go desktop must run as a regular user");
        std::process::exit(1);
    }
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            backend_info,
            daemon_read,
            cli_read,
            policy_set,
            policy_remove,
            icon_data
        ])
        .run(tauri::generate_context!())
        .expect("error while running FBI-Go desktop");
}
