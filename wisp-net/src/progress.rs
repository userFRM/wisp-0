use std::io::{self, Write};
use std::time::{Duration, Instant};

const BAR_WIDTH: usize = 28;
const REFRESH_INTERVAL: Duration = Duration::from_millis(200);

pub struct TransferProgress {
    label: &'static str,
    total: u64,
    done: u64,
    started_at: Instant,
    last_draw: Instant,
    finished: bool,
}

impl TransferProgress {
    pub fn new(label: &'static str, total: u64) -> Self {
        let now = Instant::now();
        let mut p = Self {
            label,
            total,
            done: 0,
            started_at: now,
            last_draw: now - REFRESH_INTERVAL,
            finished: false,
        };
        p.draw(true);
        p
    }

    pub fn inc(&mut self, delta: u64) {
        self.done = self.done.saturating_add(delta).min(self.total);
        self.draw(false);
    }

    pub fn set(&mut self, done: u64) {
        self.done = done.min(self.total);
        self.draw(false);
    }

    pub fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.done = self.total;
        self.draw(true);
        eprintln!();
        self.finished = true;
    }

    fn draw(&mut self, force: bool) {
        let now = Instant::now();
        if !force && now.duration_since(self.last_draw) < REFRESH_INTERVAL {
            return;
        }
        self.last_draw = now;

        let elapsed = now.duration_since(self.started_at).as_secs_f64().max(1e-6);
        let speed = self.done as f64 / elapsed;
        let pct = if self.total == 0 {
            100.0
        } else {
            (self.done as f64 * 100.0) / self.total as f64
        };
        let filled = if self.total == 0 {
            BAR_WIDTH
        } else {
            ((self.done as f64 / self.total as f64) * BAR_WIDTH as f64) as usize
        }
        .min(BAR_WIDTH);

        let eta_secs = if self.total > self.done && speed > 0.0 {
            ((self.total - self.done) as f64 / speed).round() as u64
        } else {
            0
        };

        let bar = format!(
            "{}{}",
            "#".repeat(filled),
            "-".repeat(BAR_WIDTH.saturating_sub(filled))
        );
        let line = format!(
            "\r{} [{}] {:>6.2}% {}/{} {}/s ETA {}",
            self.label,
            bar,
            pct,
            fmt_bytes(self.done),
            fmt_bytes(self.total),
            fmt_size(speed),
            fmt_eta(eta_secs),
        );
        eprint!("{line}");
        let _ = io::stderr().flush();
    }
}

impl Drop for TransferProgress {
    fn drop(&mut self) {
        if !self.finished {
            eprintln!();
        }
    }
}

fn fmt_bytes(bytes: u64) -> String {
    fmt_size(bytes as f64)
}

fn fmt_size(bytes: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes.max(0.0);
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

fn fmt_eta(mut secs: u64) -> String {
    let h = secs / 3600;
    secs %= 3600;
    let m = secs / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h:02}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}
