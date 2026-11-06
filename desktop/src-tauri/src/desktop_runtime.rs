use crate::traffic::{TrafficMonitor, TrafficSample};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::menu::{Menu, MenuBuilder, MenuItem};
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

struct InterfaceRow {
    name: String,
    label: MenuItem<tauri::Wry>,
    download: MenuItem<tauri::Wry>,
    upload: MenuItem<tauri::Wry>,
    displayed: (String, String, String),
}

struct TrayMenu {
    menu: Menu<tauri::Wry>,
    rows: Vec<InterfaceRow>,
    empty: Option<MenuItem<tauri::Wry>>,
}

impl TrayMenu {
    fn new(app: &AppHandle) -> tauri::Result<Self> {
        let menu = MenuBuilder::new(app)
            .text("heading", "FBI-Go · PLAN ONLY")
            .separator()
            .text("interfaces", "NETWORK INTERFACES")
            .separator()
            .text("open", "Open FBI-Go")
            .text("quit", "Quit")
            .build()?;
        Ok(Self {
            menu,
            rows: Vec::new(),
            empty: None,
        })
    }

    fn update(
        &mut self,
        app: &AppHandle,
        samples: &[TrafficSample],
        details: &HashMap<String, (String, bool)>,
    ) -> tauri::Result<()> {
        let visible: Vec<_> = samples
            .iter()
            .filter(|sample| sample.name != "lo")
            .take(32)
            .collect();
        let same_devices = (visible.is_empty() == self.empty.is_some())
            && self.rows.len() == visible.len()
            && self
                .rows
                .iter()
                .zip(&visible)
                .all(|(row, sample)| row.name == sample.name);
        if !same_devices {
            for row in self.rows.drain(..) {
                self.menu.remove(&row.label)?;
                self.menu.remove(&row.download)?;
                self.menu.remove(&row.upload)?;
            }
            if let Some(empty) = self.empty.take() {
                self.menu.remove(&empty)?;
            }
            for (index, sample) in visible.iter().enumerate() {
                let label_text = interface_label(sample, details);
                let download_text = format!("  Download: {}", speed(sample.rx_bytes_per_second));
                let upload_text = format!("  Upload: {}", speed(sample.tx_bytes_per_second));
                let label = MenuItem::with_id(
                    app,
                    format!("device-{index}"),
                    &label_text,
                    false,
                    None::<&str>,
                )?;
                let download = MenuItem::with_id(
                    app,
                    format!("download-{index}"),
                    &download_text,
                    false,
                    None::<&str>,
                )?;
                let upload = MenuItem::with_id(
                    app,
                    format!("upload-{index}"),
                    &upload_text,
                    false,
                    None::<&str>,
                )?;
                self.menu.insert(&label, 3 + index * 3)?;
                self.menu.insert(&download, 4 + index * 3)?;
                self.menu.insert(&upload, 5 + index * 3)?;
                self.rows.push(InterfaceRow {
                    name: sample.name.clone(),
                    label,
                    download,
                    upload,
                    displayed: (label_text, download_text, upload_text),
                });
            }
            if visible.is_empty() {
                let empty = MenuItem::with_id(
                    app,
                    "empty",
                    "No network interfaces observed",
                    false,
                    None::<&str>,
                )?;
                self.menu.insert(&empty, 3)?;
                self.empty = Some(empty);
            }
            return Ok(());
        }
        for (row, sample) in self.rows.iter_mut().zip(visible) {
            let next = (
                interface_label(sample, details),
                format!("  Download: {}", speed(sample.rx_bytes_per_second)),
                format!("  Upload: {}", speed(sample.tx_bytes_per_second)),
            );
            if row.displayed.0 != next.0 {
                row.label.set_text(&next.0)?;
            }
            if row.displayed.1 != next.1 {
                row.download.set_text(&next.1)?;
            }
            if row.displayed.2 != next.2 {
                row.upload.set_text(&next.2)?;
            }
            row.displayed = next;
        }
        Ok(())
    }
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
    let mut tray_menu = TrayMenu::new(app.handle())?;
    tray_menu.update(app.handle(), &state.samples(), &HashMap::new())?;
    let initial = tray_menu.menu.clone();
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
    let tray_menu = Arc::new(Mutex::new(tray_menu));
    std::thread::spawn(move || {
        let _tray_keepalive = tray;
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
                let tray_menu = Arc::clone(&tray_menu);
                let _ = handle.run_on_main_thread(move || {
                    if let Ok(mut menu) = tray_menu.lock() {
                        let _ = menu.update(&app, &samples, &details);
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
