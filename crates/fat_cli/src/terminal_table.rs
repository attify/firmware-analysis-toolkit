//! Reusable bordered tables with wrapping and a narrow-terminal record layout.
//! Color affects ANSI styling only, never borders or layout.
use crate::style::Palette;
use crate::terminal_text::{display_width, key_value, max_line_width, wrap};

/// Tables wrap every cell. Narrow terminals use labeled records, including
/// extra cells in ragged rows rather than silently dropping those values.
/// The returned lines can be printed directly or embedded in a larger report.
pub fn render(
    headers: &[&str],
    rows: &[Vec<String>],
    width: usize,
    palette: Palette,
) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let columns = rows
        .iter()
        .map(Vec::len)
        .max()
        .unwrap_or(0)
        .max(headers.len());
    if columns == 0 {
        return lines;
    }
    let headers: Vec<String> = (0..columns)
        .map(|index| {
            headers
                .get(index)
                .filter(|header| !header.is_empty())
                .map(|header| (*header).to_string())
                .unwrap_or_else(|| format!("Column {}", index + 1))
        })
        .collect();
    if width < 64 || columns.saturating_mul(12) > width {
        return stacked(&headers, rows, width, palette);
    }
    // Each column has two padding spaces, with a border at both ends
    // and between columns.
    let available = width.saturating_sub(columns * 3 + 1);
    let mut widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(column, header)| {
            rows.iter()
                .filter_map(|row| row.get(column))
                .map(|cell| max_line_width(cell))
                .fold(max_line_width(header), usize::max)
                .max(1)
                .min(width)
        })
        .collect();
    let minima: Vec<usize> = widths.iter().map(|width| (*width).min(12)).collect();
    if minima.iter().sum::<usize>() > available {
        return stacked(&headers, rows, width, palette);
    }
    while widths.iter().sum::<usize>() > available {
        let column = (0..columns)
            .filter(|index| widths[*index] > minima[*index])
            .max_by_key(|index| widths[*index])
            .expect("minimum widths fit available columns");
        widths[column] -= 1;
    }
    let styled_headers: Vec<String> = headers.iter().map(|header| palette.key(header)).collect();
    lines.push(border(&widths, ['┌', '┬', '┐'], palette));
    lines.extend(row(&styled_headers, &widths, palette));
    if !rows.is_empty() {
        lines.push(border(&widths, ['├', '┼', '┤'], palette));
    }
    for (index, values) in rows.iter().enumerate() {
        lines.extend(row(values, &widths, palette));
        if index + 1 < rows.len() {
            lines.push(border(&widths, ['├', '┼', '┤'], palette));
        }
    }
    lines.push(border(&widths, ['└', '┴', '┘'], palette));
    lines
}

fn stacked(
    headers: &[String],
    rows: &[Vec<String>],
    width: usize,
    palette: Palette,
) -> Vec<String> {
    if rows.is_empty() {
        return wrap(&headers.join(" | "), width, palette.enabled());
    }
    let mut lines = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            lines.push(String::new());
        }
        for (column, header) in headers.iter().enumerate() {
            lines.extend(key_value(
                header,
                row.get(column).map(String::as_str).unwrap_or(""),
                width,
                palette,
            ));
        }
    }
    lines
}

fn border(widths: &[usize], [left, middle, right]: [char; 3], palette: Palette) -> String {
    let spans = widths
        .iter()
        .map(|width| "─".repeat(width + 2))
        .collect::<Vec<_>>()
        .join(&middle.to_string());
    palette.muted(format!("{left}{spans}{right}"))
}

fn row(cells: &[String], widths: &[usize], palette: Palette) -> Vec<String> {
    let mut lines = Vec::new();
    let wrapped: Vec<Vec<String>> = widths
        .iter()
        .enumerate()
        .map(|(column, width)| {
            wrap(
                cells.get(column).map(String::as_str).unwrap_or(""),
                *width,
                palette.enabled(),
            )
        })
        .collect();
    let height = wrapped.iter().map(Vec::len).max().unwrap_or(0);
    let edge = palette.muted("│");
    let separator = format!(" {edge} ");
    for row in 0..height {
        let line = wrapped
            .iter()
            .zip(widths)
            .map(|(column, width)| {
                let cell = column.get(row).map(String::as_str).unwrap_or("");
                format!(
                    "{cell}{}",
                    " ".repeat(width.saturating_sub(display_width(cell)))
                )
            })
            .collect::<Vec<_>>()
            .join(&separator);
        lines.push(format!("{edge} {line} {edge}"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_tables_keep_the_same_layout_with_and_without_color() {
        for width in [40, 80, 120] {
            let render_with_color = |color| {
                let palette = Palette::stdout_with_color(Some(color));
                render(
                    &["Address", "Description"],
                    &[
                        vec![palette.info("0x40020000"), "漢字 e\u{301} ".repeat(25)],
                        vec!["second".into(), "first line\nsecond line".into()],
                    ],
                    width,
                    palette,
                )
                .join("\n")
            };
            let plain = render_with_color("never");
            let colored = render_with_color("always");
            assert!(!plain.contains('\u{1b}'));
            assert!(colored.contains('\u{1b}'));
            assert_eq!(wrap(&colored, usize::MAX, false).join("\n"), plain);
            assert!(plain.lines().all(|line| display_width(line) <= width));
            assert_eq!(plain.matches('漢').count(), 25);
            assert_eq!(plain.matches("e\u{301}").count(), 25);
            assert!(plain.contains("0x40020000"));
            if width >= 64 {
                assert!(plain.starts_with('┌'));
                assert!(plain.ends_with('┘'));
                assert!(plain.contains('│'));
            }
        }
    }

    #[test]
    fn empty_tables_omit_empty_input_and_frame_headers() {
        let palette = Palette::stdout_with_color(Some("never"));
        assert!(render(&[], &[], 80, palette).is_empty());
        assert_eq!(
            render(&["Address", "Value"], &[], 80, palette),
            [
                "┌─────────┬───────┐",
                "│ Address │ Value │",
                "└─────────┴───────┘"
            ]
        );
    }
}
