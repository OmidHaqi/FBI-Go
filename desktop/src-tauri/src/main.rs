#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(feature = "desktop")]
fn main() {
    fbi_go_desktop_lib::run();
}

#[cfg(not(feature = "desktop"))]
fn main() {}
