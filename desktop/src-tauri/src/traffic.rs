use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Instant;

#[derive(Clone, Debug, Serialize)]
pub struct TrafficSample {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bytes_per_second: Option<u64>,
    pub tx_bytes_per_second: Option<u64>,
}

#[derive(Default)]
pub struct TrafficMonitor {
    previous: HashMap<String, (u64, u64, Instant)>,
    current: Vec<TrafficSample>,
}

impl TrafficMonitor {
    pub fn current(&self) -> Vec<TrafficSample> {
        self.current.clone()
    }

    pub fn sample(&mut self, root: &Path, now: Instant) {
        let Ok(entries) = fs::read_dir(root) else {
            self.current.clear();
            self.previous.clear();
            return;
        };
        let mut next = HashMap::new();
        let mut samples = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.is_empty() || name.contains('/') {
                continue;
            }
            let base = entry.path().join("statistics");
            let (Some(rx), Some(tx)) = (
                read_counter(&base.join("rx_bytes")),
                read_counter(&base.join("tx_bytes")),
            ) else {
                continue;
            };
            let (rx_rate, tx_rate) = self
                .previous
                .get(&name)
                .and_then(|(old_rx, old_tx, before)| {
                    let elapsed = now.checked_duration_since(*before)?.as_secs_f64();
                    if !(0.2..=10.0).contains(&elapsed) || rx < *old_rx || tx < *old_tx {
                        return None;
                    }
                    Some((
                        ((rx - old_rx) as f64 / elapsed) as u64,
                        ((tx - old_tx) as f64 / elapsed) as u64,
                    ))
                })
                .map_or((None, None), |(rx, tx)| (Some(rx), Some(tx)));
            samples.push(TrafficSample {
                name: name.clone(),
                rx_bytes: rx,
                tx_bytes: tx,
                rx_bytes_per_second: rx_rate,
                tx_bytes_per_second: tx_rate,
            });
            next.insert(name, (rx, tx, now));
        }
        samples.sort_by(|a, b| a.name.cmp(&b.name));
        self.previous = next;
        self.current = samples;
    }
}

fn read_counter(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn write(root: &Path, name: &str, rx: u64, tx: u64) {
        let path = root.join(name).join("statistics");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("rx_bytes"), rx.to_string()).unwrap();
        fs::write(path.join("tx_bytes"), tx.to_string()).unwrap();
    }

    #[test]
    fn rates_reset_and_device_lifecycle() {
        let root = std::env::temp_dir().join(format!(
            "fbi-traffic-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let mut monitor = TrafficMonitor::default();
        let now = Instant::now();
        write(&root, "wan-a", 100, 50);
        monitor.sample(&root, now);
        assert_eq!(monitor.current()[0].rx_bytes_per_second, None);
        write(&root, "wan-a", 500, 150);
        monitor.sample(&root, now + Duration::from_secs(1));
        assert_eq!(monitor.current()[0].rx_bytes_per_second, Some(400));
        assert_eq!(monitor.current()[0].tx_bytes_per_second, Some(100));
        monitor.sample(&root, now + Duration::from_secs(2));
        assert_eq!(monitor.current()[0].rx_bytes_per_second, Some(0));
        write(&root, "wan-a", 1, 0);
        monitor.sample(&root, now + Duration::from_secs(3));
        assert_eq!(monitor.current()[0].rx_bytes_per_second, None);
        fs::remove_dir_all(root.join("wan-a")).unwrap();
        monitor.sample(&root, now + Duration::from_secs(4));
        assert!(monitor.current().is_empty());
        write(&root, "wan-a", 20, 10);
        monitor.sample(&root, now + Duration::from_secs(5));
        assert_eq!(monitor.current()[0].rx_bytes_per_second, None);
        write(&root, "wan-a", u64::MAX, 10);
        monitor.sample(&root, now + Duration::from_secs(6));
        assert!(monitor.current()[0].rx_bytes_per_second.is_some());
        write(&root, "wan-a", 0, 11);
        monitor.sample(&root, now + Duration::from_secs(7));
        assert_eq!(monitor.current()[0].rx_bytes_per_second, None);
        fs::remove_dir_all(root).unwrap();
    }
}
