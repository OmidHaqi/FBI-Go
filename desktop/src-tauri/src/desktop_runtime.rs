use crate::traffic::{TrafficMonitor, TrafficSample};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::menu::{Menu, MenuBuilder, MenuItem, Submenu};
use tauri::tray::TrayIconBuilder;
use tauri::{App, AppHandle, Emitter, Manager, WindowEvent};

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

#[derive(Clone, Debug, Default)]
struct DeviceDetail {
    kind: String,
    up: bool,
    candidate: bool,
}

fn interface_label(sample: &TrafficSample, details: &HashMap<String, DeviceDetail>) -> String {
    details
        .get(&sample.name)
        .map(|detail| {
            if detail.up {
                format!("{} - {}", sample.name, detail.kind.replace('_', " "))
            } else {
                format!("{} - Disconnected", sample.name)
            }
        })
        .unwrap_or_else(|| format!("{} - Type unknown", sample.name))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MenuLayout {
    top: Vec<String>,
    groups: Vec<(String, Vec<String>, usize)>,
}

fn menu_layout(samples: &[TrafficSample], details: &HashMap<String, DeviceDetail>) -> MenuLayout {
    let mut ranked: Vec<_> = samples.iter().filter(|s| s.name != "lo").collect();
    let priority = |name: &str| -> u8 {
        let Some(d) = details.get(name) else { return 8 };
        if !d.up {
            return 7;
        }
        if d.candidate
            && matches!(
                d.kind.as_str(),
                "wifi" | "ethernet" | "usb_network" | "wwan"
            )
        {
            return 0;
        }
        match d.kind.as_str() {
            "usb_network" => 1,
            "vpn" => 2,
            "wifi" | "ethernet" | "wwan" => 3,
            "bridge" | "virtual" => 6,
            _ => 5,
        }
    };
    ranked.sort_by_key(|s| (priority(&s.name), s.name.clone()));
    let top: Vec<String> = ranked
        .iter()
        .filter(|s| priority(&s.name) <= 3)
        .take(3)
        .map(|s| s.name.clone())
        .collect();
    let mut groups: Vec<(String, Vec<String>, usize)> = Vec::new();
    for group in [
        "Other physical interfaces",
        "VPN interfaces",
        "Virtual interfaces",
        "Disconnected interfaces",
        "Unclassified interfaces",
    ] {
        let all: Vec<_> = ranked
            .iter()
            .filter(|s| !top.contains(&s.name))
            .filter(|s| {
                let d = details.get(&s.name);
                match group {
                    "Disconnected interfaces" => d.is_some_and(|d| !d.up),
                    "VPN interfaces" => d.is_some_and(|d| d.up && d.kind == "vpn"),
                    "Virtual interfaces" => {
                        d.is_some_and(|d| d.up && matches!(d.kind.as_str(), "bridge" | "virtual"))
                    }
                    "Unclassified interfaces" => d.is_none_or(|d| {
                        d.up && !matches!(
                            d.kind.as_str(),
                            "wifi"
                                | "ethernet"
                                | "usb_network"
                                | "wwan"
                                | "vpn"
                                | "bridge"
                                | "virtual"
                        )
                    }),
                    _ => d.is_some_and(|d| {
                        d.up && matches!(
                            d.kind.as_str(),
                            "wifi" | "ethernet" | "usb_network" | "wwan"
                        )
                    }),
                }
            })
            .collect();
        if !all.is_empty() {
            let count = all.len();
            groups.push((
                group.into(),
                all.into_iter().take(5).map(|s| s.name.clone()).collect(),
                count,
            ));
        }
    }
    MenuLayout { top, groups }
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
    submenu_rows: Vec<(String, MenuItem<tauri::Wry>, String)>,
    submenus: Vec<Submenu<tauri::Wry>>,
    layout: Option<MenuLayout>,
    empty: Option<MenuItem<tauri::Wry>>,
}

impl TrayMenu {
    fn new(app: &AppHandle) -> tauri::Result<Self> {
        let menu = MenuBuilder::new(app)
            .text("heading", "FBI-Go · PLAN ONLY")
            .separator()
            .text("interfaces", "ACTIVE NETWORKS")
            .separator()
            .text("open-networks", "Open Networks")
            .text("open", "Open FBI-Go")
            .text("quit", "Quit")
            .build()?;
        Ok(Self {
            menu,
            rows: Vec::new(),
            submenu_rows: Vec::new(),
            submenus: Vec::new(),
            layout: None,
            empty: None,
        })
    }

    fn update(
        &mut self,
        app: &AppHandle,
        samples: &[TrafficSample],
        details: &HashMap<String, DeviceDetail>,
    ) -> tauri::Result<()> {
        let layout = menu_layout(samples, details);
        let same_devices = self.layout.as_ref() == Some(&layout);
        if !same_devices {
            for row in self.rows.drain(..) {
                self.menu.remove(&row.label)?;
                self.menu.remove(&row.download)?;
                self.menu.remove(&row.upload)?;
            }
            if let Some(empty) = self.empty.take() {
                self.menu.remove(&empty)?;
            }
            for submenu in self.submenus.drain(..) {
                self.menu.remove(&submenu)?;
            }
            self.submenu_rows.clear();
            for (index, name) in layout.top.iter().enumerate() {
                let sample = samples
                    .iter()
                    .find(|s| &s.name == name)
                    .expect("layout sample");
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
            if layout.top.is_empty() {
                let empty = MenuItem::with_id(
                    app,
                    "empty",
                    "No active priority interfaces",
                    false,
                    None::<&str>,
                )?;
                self.menu.insert(&empty, 3)?;
                self.empty = Some(empty);
            }
            let submenu_start = 3 + self.rows.len() * 3 + usize::from(self.empty.is_some());
            for (group_index, (title, names, total)) in layout.groups.iter().enumerate() {
                let submenu = Submenu::with_id(app, format!("group-{group_index}"), title, true)?;
                for (index, name) in names.iter().enumerate() {
                    let sample = samples
                        .iter()
                        .find(|s| &s.name == name)
                        .expect("layout sample");
                    let label = format!(
                        "{}  ↓ {}  ↑ {}",
                        interface_label(sample, details),
                        speed(sample.rx_bytes_per_second),
                        speed(sample.tx_bytes_per_second)
                    );
                    let item = MenuItem::with_id(
                        app,
                        format!("group-{group_index}-{index}"),
                        &label,
                        false,
                        None::<&str>,
                    )?;
                    submenu.append(&item)?;
                    self.submenu_rows.push((name.clone(), item, label));
                }
                if *total > names.len() {
                    let more = MenuItem::with_id(
                        app,
                        format!("open-networks-{group_index}"),
                        format!("{} more · Open Networks", total - names.len()),
                        true,
                        None::<&str>,
                    )?;
                    submenu.append(&more)?;
                }
                self.menu.insert(&submenu, submenu_start + group_index)?;
                self.submenus.push(submenu);
            }
            self.layout = Some(layout);
            return Ok(());
        }
        for row in &mut self.rows {
            let Some(sample) = samples.iter().find(|s| s.name == row.name) else {
                continue;
            };
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
        for (name, item, displayed) in &mut self.submenu_rows {
            if let Some(sample) = samples.iter().find(|s| &s.name == name) {
                let next = format!(
                    "{}  ↓ {}  ↑ {}",
                    interface_label(sample, details),
                    speed(sample.rx_bytes_per_second),
                    speed(sample.tx_bytes_per_second)
                );
                if *displayed != next {
                    item.set_text(&next)?;
                    *displayed = next;
                }
            }
        }
        Ok(())
    }
}

fn device_details() -> HashMap<String, DeviceDetail> {
    let mut details = HashMap::new();
    if let Ok(status) = crate::bridge::daemon_read("daemon.status") {
        if let Some(devices) = status["snapshot"]["devices"].as_array() {
            for device in devices {
                if let (Some(name), Some(kind)) = (device["name"].as_str(), device["kind"].as_str())
                {
                    details.insert(
                        name.to_owned(),
                        DeviceDetail {
                            kind: kind.to_owned(),
                            up: device["state"] == "up",
                            candidate: device["candidate"] == true,
                        },
                    );
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
            "open" => show_main_window(app),
            "open-networks" => {
                show_main_window(app);
                let _ = app.emit("open-networks", ());
            }
            "quit" => app.exit(0),
            id if id.starts_with("open-networks-") => {
                show_main_window(app);
                let _ = app.emit("open-networks", ());
            }
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

pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus(); // Wayland may deny activation; showing still restores it.
    }
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
        details.insert(
            "usb0".into(),
            DeviceDetail {
                kind: "usb_network".into(),
                up: true,
                candidate: true,
            },
        );
        assert_eq!(interface_label(&sample, &details), "usb0 - usb network");
        assert_eq!(speed(sample.rx_bytes_per_second), "420 KB/s");
        details.insert(
            "usb0".into(),
            DeviceDetail {
                kind: "usb_network".into(),
                up: false,
                candidate: true,
            },
        );
        assert_eq!(interface_label(&sample, &details), "usb0 - Disconnected");
    }

    #[test]
    fn compact_layout_prioritizes_wans_and_bounds_every_group() {
        let mut samples = Vec::new();
        let mut details = HashMap::new();
        for (name, kind, up, candidate) in [
            ("wifi0", "wifi", true, true),
            ("usb0", "usb_network", true, true),
            ("eth0", "ethernet", true, true),
            ("tun0", "vpn", true, false),
            ("eth1", "ethernet", true, false),
        ] {
            samples.push(TrafficSample {
                name: name.into(),
                rx_bytes: 0,
                tx_bytes: 0,
                rx_bytes_per_second: Some(0),
                tx_bytes_per_second: Some(0),
            });
            details.insert(
                name.into(),
                DeviceDetail {
                    kind: kind.into(),
                    up,
                    candidate,
                },
            );
        }
        for index in 0..50 {
            let name = format!("veth{index}");
            samples.push(TrafficSample {
                name: name.clone(),
                rx_bytes: 0,
                tx_bytes: 0,
                rx_bytes_per_second: Some(0),
                tx_bytes_per_second: Some(0),
            });
            details.insert(
                name,
                DeviceDetail {
                    kind: "virtual".into(),
                    up: index % 2 == 0,
                    candidate: false,
                },
            );
        }
        let layout = menu_layout(&samples, &details);
        assert_eq!(layout.top, ["eth0", "usb0", "wifi0"]);
        assert_eq!(
            layout
                .groups
                .iter()
                .map(|(_, names, _)| names.len())
                .sum::<usize>(),
            12
        );
        assert_eq!(
            layout
                .groups
                .iter()
                .find(|(name, _, _)| name == "Virtual interfaces")
                .unwrap()
                .2,
            25
        );
        assert_eq!(
            layout
                .groups
                .iter()
                .find(|(name, _, _)| name == "Disconnected interfaces")
                .unwrap()
                .2,
            25
        );
        assert_eq!(menu_layout(&samples, &details), layout);
        samples.retain(|s| s.name != "eth0");
        assert_ne!(menu_layout(&samples, &details), layout);
        assert!(menu_layout(&[], &details).top.is_empty());
    }

    #[test]
    fn tray_layout_stays_bounded_as_interfaces_change() {
        for count in [0, 1, 3, 5, 20, 50] {
            let samples: Vec<_> = (0..count)
                .map(|i| TrafficSample {
                    name: format!("eth{i}"),
                    rx_bytes: 0,
                    tx_bytes: 0,
                    rx_bytes_per_second: Some(i as u64),
                    tx_bytes_per_second: Some(0),
                })
                .collect();
            let details: HashMap<_, _> = samples
                .iter()
                .map(|sample| {
                    (
                        sample.name.clone(),
                        DeviceDetail {
                            kind: "ethernet".into(),
                            up: true,
                            candidate: true,
                        },
                    )
                })
                .collect();
            let layout = menu_layout(&samples, &details);
            assert_eq!(layout.top.len(), count.min(3));
            assert!(layout
                .groups
                .iter()
                .all(|(_, preview, _)| preview.len() <= 5));
            assert!(layout.groups.len() <= 5);
            if count > 3 {
                assert_eq!(layout.groups[0].2, count - 3);
            }
        }
    }
}
