use std::borrow::Cow;
use std::env;
use std::io::{stderr, stdout, IsTerminal};
use std::time::Duration;

use fat_core::finding::FindingSeverity;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use owo_colors::OwoColorize;

/// Interior width, in visible columns, between the borders of a framed panel.
/// Framed output is only produced when styling is enabled, so a fixed width
/// keeps the layout predictable without a terminal-size dependency.
pub const PANEL_CONTENT_WIDTH: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColorWhen {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy)]
pub struct Palette {
    enabled: bool,
}

impl Palette {
    pub fn stdout() -> Self {
        Self {
            enabled: should_color(Stream::Stdout),
        }
    }

    pub fn stdout_with_color(color: Option<&str>) -> Self {
        Self {
            enabled: should_color_with_override(Stream::Stdout, color),
        }
    }

    pub fn stderr() -> Self {
        Self {
            enabled: should_color(Stream::Stderr),
        }
    }

    pub fn heading(&self, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        if self.enabled {
            format!("{}", text.bold().bright_blue())
        } else {
            text.to_string()
        }
    }

    pub fn key(&self, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        if self.enabled {
            format!("{}", text.bold().cyan())
        } else {
            text.to_string()
        }
    }

    pub fn info(&self, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        if self.enabled {
            format!("{}", text.cyan())
        } else {
            text.to_string()
        }
    }

    pub fn good(&self, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        if self.enabled {
            format!("{}", text.green().bold())
        } else {
            text.to_string()
        }
    }

    pub fn warn(&self, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        if self.enabled {
            format!("{}", text.yellow().bold())
        } else {
            text.to_string()
        }
    }

    pub fn bad(&self, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        if self.enabled {
            format!("{}", text.red().bold())
        } else {
            text.to_string()
        }
    }

    pub fn accent(&self, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        if self.enabled {
            format!("{}", text.magenta().bold())
        } else {
            text.to_string()
        }
    }

    pub fn muted(&self, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        if self.enabled {
            format!("{}", text.dimmed())
        } else {
            text.to_string()
        }
    }

    pub fn bullet(&self, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        if self.enabled {
            format!("{}", text.bright_black())
        } else {
            text.to_string()
        }
    }

    pub fn code(&self, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        if self.enabled {
            format!("{}", text.bright_magenta())
        } else {
            text.to_string()
        }
    }

    pub fn status_word(&self, word: &str) -> String {
        match word.to_ascii_lowercase().as_str() {
            "pass" | "available" | "proven" | "attested" | "confirmed" | "satisfying" => {
                self.good(word)
            }
            "candidate" | "warning" | "violating" | "unknown" | "partial" => self.warn(word),
            "fail" | "unavailable" | "rejected" | "error" => self.bad(word),
            _ => self.info(word),
        }
    }

    pub fn severity_tag(&self, severity: &FindingSeverity) -> String {
        let label = match severity {
            FindingSeverity::Critical => "CRIT",
            FindingSeverity::High => "HIGH",
            FindingSeverity::Medium => " MED",
            FindingSeverity::Low => " LOW",
            FindingSeverity::Info => "INFO",
        };
        if !self.enabled {
            return label.to_string();
        }
        match severity {
            FindingSeverity::Critical => format!("{}", label.bright_red().bold()),
            FindingSeverity::High => format!("{}", label.red().bold()),
            FindingSeverity::Medium => format!("{}", label.yellow().bold()),
            FindingSeverity::Low => format!("{}", label.blue().bold()),
            FindingSeverity::Info => format!("{}", label.cyan().bold()),
        }
    }

    pub fn kv(&self, key: &str, value: impl AsRef<str>) -> String {
        format!("{}: {}", self.key(key), value.as_ref())
    }

    /// Right-pad `key` to `width` so a column of `kv` lines aligns on the colon.
    pub fn kv_aligned(&self, key: &str, width: usize, value: impl AsRef<str>) -> String {
        let padded = format!("{key:<width$}");
        format!("{}: {}", self.key(padded), value.as_ref())
    }

    /// Green status dot for a healthy/found line.
    pub fn dot_ok(&self) -> String {
        if self.enabled {
            "●".green().to_string()
        } else {
            "●".to_string()
        }
    }

    /// Yellow status dot for a warning (optional tool missing, diagnostic).
    pub fn dot_warn(&self) -> String {
        if self.enabled {
            "●".yellow().to_string()
        } else {
            "●".to_string()
        }
    }

    /// Red status dot for a failure (required tool missing, unavailable).
    pub fn dot_bad(&self) -> String {
        if self.enabled {
            "●".red().to_string()
        } else {
            "●".to_string()
        }
    }

    /// Dimmed status dot for inert lines (feature-disabled integration).
    pub fn dot_muted(&self) -> String {
        if self.enabled {
            "●".dimmed().to_string()
        } else {
            "●".to_string()
        }
    }

    /// `✓` when a check passed, `✗` when it failed.
    pub fn check_glyph(&self, passed: bool) -> String {
        if !self.enabled {
            return if passed {
                "✓".to_string()
            } else {
                "✗".to_string()
            };
        }
        if passed {
            "✓".green().bold().to_string()
        } else {
            "✗".red().bold().to_string()
        }
    }

    /// Frame pre-styled `lines` inside a rounded panel titled `title`.
    ///
    /// Over-long lines wrap with a hanging indent aligned under the line's
    /// leading status glyph; padding uses ANSI-stripped visible widths. When
    /// styling is disabled the lines are joined verbatim with no borders or
    /// decorations so piped output stays machine-parseable.
    pub fn panel(&self, title: &str, lines: &[String]) -> String {
        if !self.enabled {
            return lines.join("\n");
        }
        let inner = PANEL_CONTENT_WIDTH;
        let title_text = format!(" {} ", title.bold().bright_blue());
        let fill = inner.saturating_sub(1 + visible_width(&title_text));
        let mut out = String::new();
        out.push('╭');
        out.push('─');
        out.push_str(&title_text);
        out.push_str("─".repeat(fill).as_str());
        out.push('╮');
        for line in lines {
            for row in wrap_panel_line(line, inner) {
                out.push('\n');
                out.push('│');
                out.push_str(&row);
                out.push_str(
                    " ".repeat(inner.saturating_sub(visible_width(&row)))
                        .as_str(),
                );
                out.push('│');
            }
        }
        out.push('\n');
        out.push('╰');
        out.push_str("─".repeat(inner).as_str());
        out.push('╯');
        out
    }

    /// `▮▮▮▮▮▮▮▮▯▯ 80%` — a small filled/dimmed fraction bar with the
    /// percentage appended. Filled cells are green and empty cells dimmed when
    /// styling is on; the plain form is glyph text only.
    pub fn bar(&self, frac: f32, width: usize) -> String {
        let frac = frac.clamp(0.0, 1.0);
        let filled = ((frac * width as f32).round() as usize).min(width);
        let empty = width - filled;
        let pct = format!(" {:.0}%", frac * 100.0);
        if !self.enabled {
            return format!("{}{}{}", "▮".repeat(filled), "▯".repeat(empty), pct);
        }
        format!(
            "{}{}{}",
            "▮".repeat(filled).green(),
            "▯".repeat(empty).dimmed(),
            pct
        )
    }

    /// The standard workflow hand-off line: `next: fat analyze <project>`.
    pub fn next_hint(&self, hint: &str) -> String {
        self.muted(format!("next: {hint}"))
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

/// A quiet spinner for long-running pipeline work: `{spinner} {msg}` on
/// stderr, animating with a steady tick so a silent phase still looks alive.
///
/// Spinners never appear in piped or `--json` runs: the draw target is stderr,
/// and a non-TTY stderr makes indicatif drop the bar entirely, which the
/// `pb: None` form mirrors so callers can treat the helper as inert.
pub struct PipelineProgress {
    pb: Option<ProgressBar>,
}

impl PipelineProgress {
    /// A no-op progress handle for paths that skip long work (early returns,
    /// cached results). Methods on it do nothing.
    pub fn none() -> Self {
        Self { pb: None }
    }

    /// Start a spinner on stderr with `msg`. Hidden entirely when stderr is
    /// not a terminal (piped runs, `--json`, CI logs).
    pub fn start(msg: impl Into<Cow<'static, str>>) -> Self {
        if !std::io::stderr().is_terminal() {
            return Self { pb: None };
        }

        let pb = ProgressBar::with_draw_target(Some(0), ProgressDrawTarget::stderr());
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_style(
            ProgressStyle::with_template("{spinner} {msg}")
                .expect("spinner template is static")
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏✔"),
        );
        pb.set_message(msg);
        Self { pb: Some(pb) }
    }

    /// Update the spinner text without printing anything new.
    pub fn set_message(&self, msg: impl Into<Cow<'static, str>>) {
        if let Some(pb) = &self.pb {
            pb.set_message(msg);
        }
    }

    /// Leave the last line showing `status` so the completed phase stays
    /// visible above whatever the command prints next.
    pub fn finish_with(&self, status: impl Into<Cow<'static, str>>) {
        if let Some(pb) = &self.pb {
            pb.finish_with_message(status);
        }
    }

    /// Whether a live spinner is driving output (a TTY stderr was detected).
    pub fn pb(&self) -> Option<&ProgressBar> {
        self.pb.as_ref()
    }
}

impl Drop for PipelineProgress {
    /// Clear the spinner line even when a command bails out mid-run, so a
    /// failed run never leaves a dangling counter behind.
    fn drop(&mut self) {
        if let Some(pb) = self.pb.take() {
            pb.finish_and_clear();
        }
    }
}

/// Remove ANSI CSI escape sequences so the remaining text's `char` count is
/// the width it occupies in a terminal cell grid.
pub fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            // Skip parameter bytes and the alphabetic final byte of the CSI.
            for n in chars.by_ref() {
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Visible terminal-column width of `text`, ignoring ANSI escapes.
pub fn visible_width(text: &str) -> usize {
    strip_ansi(text).chars().count()
}

/// One wrapped visual row of a panel line, SGR state preserved across rows.
fn wrap_panel_line(line: &str, width: usize) -> Vec<String> {
    // A leading status glyph gets a two-column hanging indent on continuations.
    let plain = strip_ansi(line);
    let indent = if plain.starts_with(['●', '✓', '✗']) {
        2.min(width)
    } else {
        0
    };

    // Parse the line into (pending-escapes, char) cells.
    let mut cells: Vec<(String, char)> = Vec::new();
    let mut pending = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            pending.push(c);
            for n in chars.by_ref() {
                pending.push(n);
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            cells.push((std::mem::take(&mut pending), c));
        }
    }

    // Group cells into words that remember how many spaces preceded them, so
    // multi-space gaps inside a line survive wrapping.
    struct Word {
        spaces: usize,
        cells: Vec<(String, char)>,
    }
    let mut words: Vec<Word> = Vec::new();
    let mut spaces = 0usize;
    let mut current: Vec<(String, char)> = Vec::new();
    for cell in cells {
        if cell.1 == ' ' {
            if !current.is_empty() {
                words.push(Word {
                    spaces: std::mem::take(&mut spaces),
                    cells: std::mem::take(&mut current),
                });
            }
            spaces += 1;
        } else {
            current.push(cell);
        }
    }
    if !current.is_empty() {
        words.push(Word {
            spaces,
            cells: current,
        });
    }

    // Greedy word wrap; a single word wider than the row is hard-chunked.
    let mut active = String::new();
    let mut rows: Vec<String> = Vec::new();
    let mut row = String::new();
    let mut row_w = 0usize;
    let mut first_row = true;
    let avail = |first: bool| -> usize { width.saturating_sub(if first { 0 } else { indent }) };
    let flush = |row: &mut String, rows: &mut Vec<String>, active: &str| {
        if !active.is_empty() {
            row.push_str("\u{1b}[0m");
        }
        rows.push(std::mem::take(row));
    };
    for word in &words {
        // Leading indentation on the first row is preserved so callers can
        // nest detail lines under a parent entry without a filler glyph.
        let mut spaces = word.spaces;
        if !row.is_empty() && row_w + spaces + word.cells.len() > avail(first_row) {
            flush(&mut row, &mut rows, &active);
            first_row = false;
            row.push_str(&" ".repeat(indent));
            row.push_str(&active);
            row_w = indent;
            spaces = 0;
        }
        row.push_str(&" ".repeat(spaces));
        row_w += spaces;
        for (escapes, ch) in &word.cells {
            // A word wider than the remaining row (and than a fresh row) is
            // chunked at cell boundaries so it can never overflow the border.
            let capacity = avail(first_row).saturating_sub(row_w);
            if capacity == 0 && !row.is_empty() {
                flush(&mut row, &mut rows, &active);
                first_row = false;
                row.push_str(&" ".repeat(indent));
                row.push_str(&active);
                row_w = indent;
            }
            if !escapes.is_empty() {
                row.push_str(escapes);
                apply_sgr(&mut active, escapes);
            }
            row.push(*ch);
            row_w += 1;
        }
    }
    flush(&mut row, &mut rows, &active);
    rows
}

/// Track SGR state: append non-reset sequences, clear on reset.
fn apply_sgr(active: &mut String, escapes: &str) {
    let mut rest = escapes;
    while let Some(start) = rest.find('\u{1b}') {
        let tail = &rest[start..];
        let end = tail
            .char_indices()
            .find(|(i, c)| *i > 1 && c.is_ascii_alphabetic())
            .map(|(i, _)| start + i + 1)
            .unwrap_or(rest.len());
        let seq = &rest[start..end];
        if seq.ends_with('m') {
            let params = &seq[2..seq.len() - 1];
            if params.is_empty() || params == "0" {
                active.clear();
            } else {
                active.push_str(seq);
            }
        }
        rest = &rest[end..];
    }
}

/// Cell values that carry no signal and should be de-emphasised in tables.
fn is_placeholder_cell(cell: &str) -> bool {
    matches!(
        cell.trim(),
        "" | "-" | "span unknown" | "unknown role" | "none" | "unknown" | "not indicated"
    )
}

fn is_table_row(line: &str) -> bool {
    line.trim_start().starts_with('|')
}

fn is_separator_row(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| matches!(ch, '-' | ':' | ' ')))
}

fn split_row(line: &str) -> Vec<String> {
    let trimmed = line.trim();
    let inner = trimmed
        .strip_prefix('|')
        .unwrap_or(trimmed)
        .strip_suffix('|')
        .unwrap_or(trimmed);
    inner.split('|').map(|c| c.trim().to_string()).collect()
}

fn render_table_block(block: &[&str], palette: &Palette) -> String {
    let rows: Vec<Vec<String>> = block.iter().map(|line| split_row(line)).collect();
    let (header, data): (&Vec<String>, Vec<&Vec<String>>) = match rows.split_first() {
        Some((header, rest)) => (
            header,
            rest.iter().filter(|r| !is_separator_row(r)).collect(),
        ),
        None => return String::new(),
    };

    let col_count = header.len();
    // Keep a column only if it has a header and at least one data cell carries signal.
    let keep: Vec<bool> = (0..col_count)
        .map(|c| {
            !header[c].is_empty()
                && (data.is_empty()
                    || data
                        .iter()
                        .any(|row| row.get(c).is_some_and(|cell| !is_placeholder_cell(cell))))
        })
        .collect();

    fn cell(row: &[String], c: usize) -> &str {
        row.get(c).map(String::as_str).unwrap_or("")
    }
    let widths: Vec<usize> = (0..col_count)
        .map(|c| {
            let mut w = header[c].chars().count();
            for row in &data {
                w = w.max(cell(row, c).chars().count());
            }
            w
        })
        .collect();

    let kept: Vec<usize> = (0..col_count).filter(|&c| keep[c]).collect();
    let mut out = String::new();

    let header_line = kept
        .iter()
        .map(|&c| palette.key(format!("{:<width$}", header[c], width = widths[c])))
        .collect::<Vec<_>>()
        .join("  ");
    out.push_str(&format!("  {header_line}\n"));

    let rule = kept
        .iter()
        .map(|&c| "─".repeat(widths[c]))
        .collect::<Vec<_>>()
        .join("──");
    out.push_str(&format!("  {}\n", palette.muted(rule)));

    for row in &data {
        let line = kept
            .iter()
            .map(|&c| {
                let raw = cell(row, c);
                let padded = format!("{raw:<width$}", width = widths[c]);
                if is_placeholder_cell(raw) {
                    palette.muted(padded)
                } else {
                    padded
                }
            })
            .collect::<Vec<_>>()
            .join("  ");
        out.push_str(&format!("  {line}\n"));
    }
    out
}

/// Beautify a plain-text/Markdown document for interactive display: bold section
/// headings and reflow Markdown pipe tables into aligned, de-noised columns.
///
/// When styling is disabled (piped output, `NO_COLOR`, `--json` paths) the input
/// is returned verbatim so machine-readable Markdown stays intact.
pub fn render_doc(text: &str, palette: &Palette) -> String {
    if !palette.enabled() {
        return text.to_string();
    }

    let lines: Vec<&str> = text.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut prev_blank = true;
    while i < lines.len() {
        let line = lines[i];
        if is_table_row(line) {
            let start = i;
            while i < lines.len() && is_table_row(lines[i]) {
                i += 1;
            }
            out.push_str(&render_table_block(&lines[start..i], palette));
            prev_blank = false;
            continue;
        }

        let is_heading = prev_blank
            && !line.is_empty()
            && !line.starts_with(' ')
            && !line.starts_with('-')
            && !line.starts_with('|')
            && !line.contains(": ");
        if is_heading {
            out.push_str(&palette.heading(line));
        } else {
            out.push_str(line);
        }
        out.push('\n');
        prev_blank = line.trim().is_empty();
        i += 1;
    }
    out
}

#[derive(Debug, Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

fn should_color(stream: Stream) -> bool {
    match color_when() {
        ColorWhen::Always => true,
        ColorWhen::Never => false,
        ColorWhen::Auto => match stream {
            Stream::Stdout => stdout().is_terminal(),
            Stream::Stderr => stderr().is_terminal(),
        },
    }
}

fn should_color_with_override(stream: Stream, color: Option<&str>) -> bool {
    match color.and_then(parse_color_when) {
        Some(ColorWhen::Always) => true,
        Some(ColorWhen::Never) => false,
        Some(ColorWhen::Auto) | None => should_color(stream),
    }
}

fn color_when() -> ColorWhen {
    if let Ok(value) = env::var("FAT_COLOR") {
        match value.to_ascii_lowercase().as_str() {
            "always" | "1" | "true" => return ColorWhen::Always,
            "never" | "0" | "false" => return ColorWhen::Never,
            "auto" | "" => {}
            _ => {}
        }
    }
    if env::var_os("NO_COLOR").is_some() {
        return ColorWhen::Never;
    }
    ColorWhen::Auto
}

fn parse_color_when(value: &str) -> Option<ColorWhen> {
    match value.to_ascii_lowercase().as_str() {
        "always" | "1" | "true" => Some(ColorWhen::Always),
        "never" | "0" | "false" => Some(ColorWhen::Never),
        "auto" | "" => Some(ColorWhen::Auto),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "\
| Offset | Kind | Span | Notes |
| --- | --- | --- | --- |
| 0x20 | compression | - | gzip |
| 0x40 | compression | - | lzma |
";

    #[test]
    fn disabled_palette_returns_input_verbatim() {
        let plain = Palette { enabled: false };
        assert_eq!(render_doc(TABLE, &plain), TABLE);
    }

    #[test]
    fn enabled_palette_drops_all_placeholder_columns() {
        let styled = Palette { enabled: true };
        let out = render_doc(TABLE, &styled);
        // The "Span" column is "-" in every row, so it is suppressed entirely.
        assert!(
            !out.contains("Span"),
            "placeholder column should be dropped:\n{out}"
        );
        // Signal-bearing columns survive.
        assert!(out.contains("Offset"));
        assert!(out.contains("Notes"));
        assert!(out.contains("gzip"));
        // The Markdown separator row is replaced, not echoed.
        assert!(
            !out.contains("---"),
            "markdown separator should be gone:\n{out}"
        );
    }

    #[test]
    fn enabled_palette_bolds_section_headings() {
        let styled = Palette { enabled: true };
        let out = render_doc(
            "Firmware layout\n| A | B |\n| --- | --- |\n| 1 | 2 |\n",
            &styled,
        );
        // Heading gets an ANSI sequence; a plain "key: value" line would not.
        assert!(out.contains("\u{1b}["), "expected styling:\n{out}");
    }

    #[test]
    fn panel_frames_when_enabled_and_passes_through_when_disabled() {
        let styled = Palette { enabled: true };
        let out = styled.panel(
            "fat doctor",
            &[
                format!("{} macOS · aarch64", styled.dot_ok()),
                "second line".to_string(),
            ],
        );
        assert!(out.starts_with('╭'), "missing top border:\n{out}");
        let rows: Vec<&str> = out.lines().collect();
        let width = visible_width(rows[0]);
        for row in &rows {
            assert_eq!(visible_width(row), width, "row: {row}");
        }
        assert!(rows.last().unwrap().starts_with('╰'));

        let plain = Palette { enabled: false };
        assert_eq!(
            plain.panel("title", &["alpha".to_string(), "beta".to_string()]),
            "alpha\nbeta"
        );
    }

    #[test]
    fn panel_wraps_overlong_line_with_hanging_indent() {
        let styled = Palette { enabled: true };
        let long = format!("{} {}", styled.dot_ok(), "word ".repeat(40).trim_end());
        let out = styled.panel("t", &[long]);
        let rows: Vec<&str> = out.lines().collect();
        let content: Vec<&str> = rows[1..rows.len() - 1]
            .iter()
            .map(|r| r.trim_matches('│').trim_end_matches('│').trim_end())
            .collect();
        assert!(content.len() > 1, "expected wrapped rows:\n{out}");
        for continuation in &content[1..] {
            assert!(
                strip_ansi(continuation).starts_with("  "),
                "continuation not indented: {continuation:?}"
            );
        }
    }

    #[test]
    fn panel_preserves_leading_indent_on_first_row() {
        let styled = Palette { enabled: true };
        let out = styled.panel("t", &["    nested detail".to_string()]);
        let rows: Vec<&str> = out.lines().collect();
        let visible = strip_ansi(rows[1].trim_matches('│'));
        assert!(
            visible.trim_end().ends_with("    nested detail"),
            "leading indent dropped: {visible:?}"
        );
    }

    #[test]
    fn bar_renders_and_clamps_fractions() {
        let plain = Palette { enabled: false };
        assert_eq!(plain.bar(0.8, 10), "▮▮▮▮▮▮▮▮▯▯ 80%");
        assert_eq!(plain.bar(-0.2, 10), "▯▯▯▯▯▯▯▯▯▯ 0%");
        assert_eq!(plain.bar(1.4, 10), "▮▮▮▮▮▮▮▮▮▮ 100%");
    }
}
