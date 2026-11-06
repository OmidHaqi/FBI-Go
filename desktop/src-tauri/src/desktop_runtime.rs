use crate::traffic::{TrafficMonitor, TrafficSample};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::menu::MenuBuilder;
use tauri::tray::TrayIconBuilder;
use tauri::{App, AppHandle, Manager, WindowEvent};

pub struct RuntimeState {
    pub monitor: Mutex<TrafficMonitor>,
    pub tray_mode: AtomicBool,
    pub stop: AtomicBool,
}

impl RuntimeState {
    fn new() -> Self {
        Self {
            monitor: Mutex::new(TrafficMonitor::default()),
            tray_mode: AtomicBool::new(true),
            stop: AtomicBool::new(false),
        }
    }

    pub fn samples(&self) -> Vec<TrafficSample> {
        self.monitor.lock().map(|m| m.current()).unwrap_or_default()
    }
}

fn speed(value: Option<u64>) -> String {
    match value {
        None => "Initializing".into(),
        Some(bytes) if bytes >= 1_000_000 => format!("{:.1} MB/s", bytes as f64 / 1_000_000.0),
        Some(bytes) if bytes >= 1_000 => format!("{:.0} KB/s", bytes as f64 / 1_000.0),
        Some(bytes) => format!("{bytes} B/s"),
    }
}

fn interface_label(sample: &TrafficSample, details: &HashMap<String, (String, bool)>) -> String {
    details
        .get(&sample.name)
        .map(|(kind, up)| {
            if *up {
                format!("{} - {}", sample.name, kind.replace('_', " "))
            } else {
                format!("{} - Disconnected", sample.name)
            }
        })
        .unwrap_or_else(|| format!("{} - Type unknown", sample.name))
}

fn menu(
    app: &AppHandle,
    samples: &[TrafficSample],
    details: &HashMap<String, (String, bool)>,
) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    let mut builder = MenuBuilder::new(app)
        .text("heading", "FBI-Go · PLAN ONLY")
        .separator()
        .text("interfaces", "NETWORK INTERFACES");
    for (index, sample) in samples
        .iter()
        .filter(|s| s.name != "lo")
        .take(32)
        .enumerate()
    {
        let label = interface_label(sample, details);
        builder = builder
            .text(format!("device-{index}"), label)
            .text(
                format!("download-{index}"),
                format!("  Download: {}", speed(sample.rx_bytes_per_second)),
            )
            .text(
                format!("upload-{index}"),
                format!("  Upload: {}", speed(sample.tx_bytes_per_second)),
            );
    }
    if samples.len() <= 1 {
        builder = builder.text("empty", "No network interfaces observed");
    }
    builder
        .separator()
        .text("open", "Open FBI-Go")
        .text("quit", "Quit")
        .build()
}

fn device_details() -> HashMap<String, (String, bool)> {
    let mut details = HashMap::new();
    if let Ok(status) = crate::bridge::daemon_read("daemon.status") {
        if let Some(devices) = status["snapshot"]["devices"].as_array() {
            for device in devices {
                if let (Some(name), Some(kind)) = (device["name"].as_str(), device["kind"].as_str())
                {
                    details.insert(name.to_owned(), (kind.to_owned(), device["state"] == "up"));
                }
            }
        }
    }
    details
}

pub fn setup(app: &mut App) -> tauri::Result<()> {
    let state = Arc::new(RuntimeState::new());
    if let Ok(mut monitor) = state.monitor.lock() {
        monitor.sample(Path::new("/sys/class/net"), Instant::now());
    }
    app.manage(Arc::clone(&state));
    let initial = menu(app.handle(), &state.samples(), &HashMap::new())?;
    let tray = TrayIconBuilder::with_id("fbi-go")
        .icon(
            app.default_window_icon()
                .expect("configured FBI-Go icon")
                .clone(),
        )
        .menu(&initial)
        .on_menu_event(|app, event| match event.id().0.as_str() {
            "open" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    let handle = app.handle().clone();
    std::thread::spawn(move || {
        let mut ticks = 0;
        while !state.stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(1));
            if state.stop.load(Ordering::Relaxed) {
                break;
            }
            if let Ok(mut monitor) = state.monitor.lock() {
                monitor.sample(Path::new("/sys/class/net"), Instant::now());
            }
            ticks += 1;
            if ticks % 3 == 0 {
                let samples = state.samples();
                let details = device_details();
                let app = handle.clone();
                let tray = tray.clone();
                let _ = handle.run_on_main_thread(move || {
                    if let Ok(menu) = menu(&app, &samples, &details) {
                        let _ = tray.set_menu(Some(menu));
                    }
                });
            }
        }
    });
    Ok(())
}

pub fn window_event(window: &tauri::Window, event: &WindowEvent) {
    if let WindowEvent::CloseRequested { api, .. } = event {
        if let Some(state) = window.try_state::<Arc<RuntimeState>>() {
            api.prevent_close();
            if state.tray_mode.load(Ordering::Relaxed) {
                let _ = window.hide();
            } else {
                window.app_handle().exit(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_label_uses_observed_type_and_state() {
        let sample = TrafficSample {
            name: "usb0".into(),
            rx_bytes: 10,
            tx_bytes: 5,
            rx_bytes_per_second: Some(420_000),
            tx_bytes_per_second: Some(35_000),
        };
        let mut details = HashMap::new();
        assert_eq!(interface_label(&sample, &details), "usb0 - Type unknown");
        details.insert("usb0".into(), ("usb_network".into(), true));
        assert_eq!(interface_label(&sample, &details), "usb0 - usb network");
        assert_eq!(speed(sample.rx_bytes_per_second), "420 KB/s");
        details.insert("usb0".into(), ("usb_network".into(), false));
        assert_eq!(interface_label(&sample, &details), "usb0 - Disconnected");
    }
}
