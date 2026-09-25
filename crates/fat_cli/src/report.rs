//! Small terminal reports shared by identification and inspection commands.
//! Presentation only: widths and colors never change which evidence is shown.
use crate::style::Palette;
use crate::terminal_table;
use crate::terminal_text::{display_width, key_value, prefixed};

const DEFAULT_WIDTH: usize = 100;
const MAX_WIDTH: usize = 120;

pub struct Report {
    palette: Palette,
    width: usize,
    lines: Vec<String>,
}

impl Report {
    pub fn new(title: &str) -> Self {
        Self::with_layout(title, Palette::stdout(), terminal_width())
    }

    fn with_layout(title: &str, palette: Palette, width: usize) -> Self {
        let mut report = Self {
            palette,
            width: width.clamp(1, MAX_WIDTH),
            lines: Vec::new(),
        };
        report.text(palette.heading(title));
        report.lines.push(palette.muted("─".repeat(report.width)));
        report
    }

    pub fn palette(&self) -> Palette {
        self.palette
    }

    pub fn section(&mut self, title: &str) {
        self.blank();
        let title_width = display_width(title);
        if title_width + 3 <= self.width {
            self.lines.push(format!(
                "{} {}",
                self.palette.heading(title),
                self.palette.muted("─".repeat(self.width - title_width - 1))
            ));
        } else {
            self.text(self.palette.heading(title));
        }
    }

    pub fn kv(&mut self, key: &str, value: impl AsRef<str>) {
        self.lines
            .extend(key_value(key, value.as_ref(), self.width, self.palette));
    }

    pub fn text(&mut self, text: impl AsRef<str>) {
        self.lines
            .extend(prefixed("", "", text.as_ref(), self.width, self.palette));
    }

    pub fn table(&mut self, headers: &[&str], rows: &[Vec<String>]) {
        self.lines.extend(terminal_table::render(
            headers,
            rows,
            self.width,
            self.palette,
        ));
    }

    pub fn finish(self) -> String {
        self.lines.join("\n")
    }

    fn blank(&mut self) {
        if self.lines.last().is_some_and(|line| !line.is_empty()) {
            self.lines.push(String::new());
        }
    }
}

fn terminal_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|width| *width > 0)
        .or_else(stdout_width)
        .unwrap_or(DEFAULT_WIDTH)
        .min(MAX_WIDTH)
}

#[cfg(unix)]
fn stdout_width() -> Option<usize> {
    let mut size = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    // SAFETY: ioctl receives a valid pointer to the fixed-size winsize buffer.
    // It writes no more than that buffer; the initialized value is read only on success.
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, size.as_mut_ptr()) } == 0 {
        // SAFETY: the buffer was zero-initialized and ioctl succeeded.
        let width = usize::from(unsafe { size.assume_init() }.ws_col);
        (width > 0).then_some(width)
    } else {
        None
    }
}

#[cfg(not(unix))]
fn stdout_width() -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn palette(styled: bool) -> Palette {
        Palette::stdout_with_color(Some(if styled { "always" } else { "never" }))
    }
    fn plain(text: &str) -> String {
        crate::terminal_text::wrap(text, usize::MAX, false).join("\n")
    }

    #[test]
    fn widths_40_80_120_retain_long_cells_without_overflow() {
        for width in [40, 80, 120] {
            for styled in [false, true] {
                let mut report =
                    Report::with_layout("Firmware identification", palette(styled), width);
                report.section("Evidence");
                report.kv("Image", "/very/long/path/".repeat(12));
                report.kv("Mapping", "candidate");
                let rows = vec![
                    vec!["ASCII".into(), "0x00003298".into(), "Ω".repeat(200)],
                    vec![
                        "UTF-16LE".into(),
                        "0x00003364".into(),
                        "NXP LPC13XX IFLASH".into(),
                    ],
                ];
                report.table(&["Encoding", "Offset", "Identity string"], &rows);
                let output = report.finish();
                for line in output.lines() {
                    assert!(display_width(line) <= width, "width={width}: {line:?}");
                }
                let visible = plain(&output);
                assert_eq!(visible.matches("Ω").count(), 200, "{visible}");
                assert!(visible.contains("UTF-16LE"));
                assert!(visible.contains("0x00003364"));
                assert_eq!(output.contains('\u{1b}'), styled);
                if width >= 64 {
                    let lines = visible.lines().collect::<Vec<_>>();
                    let top = lines
                        .iter()
                        .position(|line| line.starts_with('┌'))
                        .expect("table has a top border");
                    let table_width = display_width(lines[top]);
                    assert!(lines[top..]
                        .iter()
                        .all(|line| display_width(line) == table_width));
                    assert!(lines.last().unwrap().starts_with('└'));
                    assert_eq!(
                        lines[top..]
                            .iter()
                            .filter(|line| { line.starts_with('├') })
                            .count(),
                        2,
                        "separate headers and logical rows, keeping wrapped cells together"
                    );
                }
            }
        }
    }

    #[test]
    fn narrow_and_ragged_tables_keep_every_header_and_value() {
        let mut report = Report::with_layout("Table", palette(false), 40);
        report.table(
            &["First", "Second"],
            &[
                vec!["alpha".into(), "beta".into(), "extra-value".into()],
                vec!["last-row".into()],
            ],
        );
        let output = report.finish();
        for expected in [
            "First",
            "Second",
            "Column 3",
            "alpha",
            "beta",
            "extra-value",
            "last-row",
        ] {
            assert!(output.contains(expected), "{output}");
        }
        assert!(output.lines().all(|line| display_width(line) <= 40));
    }

    #[test]
    fn styled_long_headings_unicode_and_multiline_values_are_not_clipped() {
        let mut report = Report::with_layout(&"heading ".repeat(25), palette(true), 40);
        report.section(&"section ".repeat(20));
        report.kv("Description", "first line\nsecond line");
        report.text(format!("{} {}", "漢字".repeat(20), "e\u{301}".repeat(20)));
        let output = report.finish();
        assert!(output.lines().all(|line| display_width(line) <= 40));
        let visible = plain(&output);
        assert_eq!(visible.matches("heading").count(), 25);
        assert_eq!(visible.matches("section").count(), 20);
        assert!(visible.contains("first line"));
        assert!(visible.contains("second line"));
        assert_eq!(visible.matches('漢').count(), 20);
    }
}
