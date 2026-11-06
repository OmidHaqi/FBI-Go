#[cfg_attr(not(feature = "desktop"), allow(dead_code))]
mod bridge;
#[cfg(feature = "desktop")]
mod desktop_runtime;
mod traffic;

#[cfg(feature = "desktop")]
use bridge::{BackendInfo, PolicyChange};
#[cfg(feature = "desktop")]
use serde_json::Value;
#[cfg(feature = "desktop")]
use std::sync::atomic::Ordering;
#[cfg(feature = "desktop")]
use std::sync::Arc;
#[cfg(feature = "desktop")]
use tauri::State;

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
#[tauri::command]
fn traffic_snapshot(
    state: State<'_, Arc<desktop_runtime::RuntimeState>>,
) -> Vec<traffic::TrafficSample> {
    state.samples()
}

#[cfg(feature = "desktop")]
#[tauri::command]
fn set_tray_mode(state: State<'_, Arc<desktop_runtime::RuntimeState>>, enabled: bool) {
    state.tray_mode.store(enabled, Ordering::Relaxed);
}

#[cfg(feature = "desktop")]
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("FBI-Go desktop must run as a regular user");
        std::process::exit(1);
    }
    tauri::Builder::default()
        .setup(|app| {
            desktop_runtime::setup(app).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        })
        .on_window_event(desktop_runtime::window_event)
        .invoke_handler(tauri::generate_handler![
            backend_info,
            daemon_read,
            cli_read,
            policy_set,
            policy_remove,
            icon_data,
            traffic_snapshot,
            set_tray_mode
        ])
        .run(tauri::generate_context!())
        .expect("error while running FBI-Go desktop");
}
