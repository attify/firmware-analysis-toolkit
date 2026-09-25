//! Shared terminal text measurement, wrapping, and labeled values.
use crate::style::Palette;

pub(super) fn key_value(key: &str, value: &str, width: usize, palette: Palette) -> Vec<String> {
    let mut lines = Vec::new();
    let key_width = 22.min(width / 3);
    let key_visible = display_width(key);
    if key_visible > key_width || key_width + 3 >= width {
        lines.extend(wrap(
            &palette.key(format!("{key}:")),
            width,
            palette.enabled(),
        ));
        let indent = " ".repeat(2.min(width.saturating_sub(1)));
        lines.extend(prefixed(&indent, &indent, value, width, palette));
    } else {
        let prefix = format!(
            "{}{}: ",
            palette.key(key),
            " ".repeat(key_width - key_visible)
        );
        lines.extend(prefixed(
            &prefix,
            &" ".repeat(key_width + 2),
            value,
            width,
            palette,
        ));
    }
    lines
}

pub(super) fn prefixed(
    first: &str,
    continuation: &str,
    text: &str,
    width: usize,
    palette: Palette,
) -> Vec<String> {
    let mut lines = Vec::new();
    let content_width = width
        .saturating_sub(display_width(first).max(display_width(continuation)))
        .max(1);
    for (index, line) in wrap(text, content_width, palette.enabled())
        .into_iter()
        .enumerate()
    {
        lines.push(format!(
            "{}{line}",
            if index == 0 { first } else { continuation }
        ));
    }
    lines
}

#[derive(Clone)]
struct Cell {
    prefix: String,
    character: char,
}

/// Parse SGR styling into zero-width prefixes. Other terminal controls are
/// omitted, but visible text and explicit line breaks are retained.
fn cells(text: &str, styled: bool) -> (Vec<Cell>, String) {
    let mut result = Vec::new();
    let mut pending = String::new();
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                let mut sequence = String::from("\u{1b}[");
                for next in chars.by_ref() {
                    sequence.push(next);
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
                if styled && sequence.ends_with('m') {
                    pending.push_str(&sequence);
                }
            } else if chars.peek() == Some(&']') {
                chars.next();
                while let Some(next) = chars.next() {
                    if next == '\u{7}' {
                        break;
                    }
                    if next == '\u{1b}' && chars.peek() == Some(&'\\') {
                        chars.next();
                        break;
                    }
                }
            }
            continue;
        }
        if character == '\t' {
            for _ in 0..4 {
                result.push(Cell {
                    prefix: std::mem::take(&mut pending),
                    character: ' ',
                });
            }
        } else if !character.is_control() || character == '\n' {
            result.push(Cell {
                prefix: std::mem::take(&mut pending),
                character,
            });
        }
    }
    (result, pending)
}

pub(super) fn max_line_width(text: &str) -> usize {
    text.split('\n').map(display_width).max().unwrap_or(0)
}

pub(super) fn display_width(text: &str) -> usize {
    cells(text, false)
        .0
        .iter()
        .map(|cell| char_width(cell.character))
        .sum()
}

// Conservative widths for common wide characters and combining marks. FAT's
// addresses and metric columns are ASCII; this also keeps common Unicode labels
// aligned without adding a terminal-layout dependency.
fn char_width(character: char) -> usize {
    let code = character as u32;
    if character == '\n'
        || matches!(code, 0x0300..=0x036f | 0x1ab0..=0x1aff | 0x1dc0..=0x1dff
        | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x206f | 0x20d0..=0x20ff
        | 0xfe00..=0xfe0f | 0xfe20..=0xfe2f)
    {
        0
    } else if matches!(code, 0x1100..=0x115f | 0x2329..=0x232a | 0x2e80..=0xa4cf
        | 0xac00..=0xd7a3 | 0xf900..=0xfaff | 0xfe10..=0xfe19 | 0xfe30..=0xfe6f
        | 0xff00..=0xff60 | 0xffe0..=0xffe6 | 0x1f300..=0x1faff | 0x20000..=0x3fffd)
    {
        2
    } else {
        1
    }
}

fn update_sgr(active: &mut String, prefix: &str) {
    for sequence in prefix.split_inclusive('m') {
        if sequence == "\u{1b}[m" || sequence == "\u{1b}[0m" {
            active.clear();
        } else {
            active.push_str(sequence);
        }
    }
}

pub(super) fn wrap(text: &str, width: usize, styled: bool) -> Vec<String> {
    let width = width.max(1);
    let (cells, trailing) = cells(text, styled);
    let mut result = Vec::new();
    let mut active = String::new();
    let mut paragraphs = Vec::new();
    let mut beginning = 0;
    for (index, cell) in cells.iter().enumerate() {
        if cell.character == '\n' {
            paragraphs.push((&cells[beginning..index], cell.prefix.as_str()));
            beginning = index + 1;
        }
    }
    paragraphs.push((&cells[beginning..], ""));
    for (paragraph, newline_style) in paragraphs {
        if paragraph.is_empty() {
            result.push(String::new());
        }
        let mut start = 0;
        while start < paragraph.len() {
            let mut end = start;
            let mut used = 0;
            let mut whitespace = None;
            while end < paragraph.len() {
                let next_width = char_width(paragraph[end].character);
                if used + next_width > width && end > start {
                    break;
                }
                used += next_width;
                if paragraph[end].character == ' ' {
                    whitespace = Some(end + 1);
                }
                end += 1;
                if used >= width {
                    // Keep combining marks attached to the preceding character.
                    while end < paragraph.len() && char_width(paragraph[end].character) == 0 {
                        end += 1;
                    }
                    break;
                }
            }
            if end < paragraph.len() {
                if let Some(space) = whitespace.filter(|space| *space > start + 1) {
                    end = space;
                }
            }
            let mut line = active.clone();
            for cell in &paragraph[start..end] {
                line.push_str(&cell.prefix);
                update_sgr(&mut active, &cell.prefix);
                line.push(cell.character);
            }
            if !active.is_empty() {
                line.push_str("\u{1b}[0m");
            }
            result.push(line);
            start = end;
        }
        update_sgr(&mut active, newline_style);
    }
    if styled && !trailing.is_empty() {
        if let Some(line) = result.last_mut() {
            line.push_str(&trailing);
            line.push_str("\u{1b}[0m");
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(text: &str) -> String {
        cells(text, false)
            .0
            .iter()
            .map(|cell| cell.character)
            .collect()
    }

    #[test]
    fn ansi_wrapping_preserves_visible_content_and_closes_each_row() {
        let content = "\u{1b}[31mabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\u{1b}[0m";
        let rows = wrap(content, 13, true);
        assert_eq!(rows.len(), 4);
        assert_eq!(
            rows.iter().map(|row| plain(row)).collect::<String>(),
            plain(content)
        );
        for row in rows {
            assert_eq!(display_width(&row), 13);
            assert!(row.ends_with("\u{1b}[0m"));
        }
        assert!(wrap(content, 13, false)
            .iter()
            .all(|row| !row.contains('\u{1b}')));
    }

    #[test]
    fn ansi_resets_on_explicit_newlines_do_not_color_following_values() {
        let rows = wrap("\u{1b}[31mred\u{1b}[0m\nplain", 40, true);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1], "plain");
        let rows = wrap("e\u{301}e\u{301}", 1, false);
        assert_eq!(rows, ["e\u{301}", "e\u{301}"]);
    }
}
