//! The Bifröst banner: HEIMDALL in block letters under a rainbow.

use super::{dim, paint, Style};

/// Hand-made block letters, 5 rows, 54 columns.
const ART: &str = r"█   █  █████  █████  █   █  ████    ███   █      █
█   █  █        █    ██ ██  █   █  █   █  █      █
█████  ████     █    █ █ █  █   █  █████  █      █
█   █  █        █    █   █  █   █  █   █  █      █
█   █  █████  █████  █   █  ████   █   █  █████  █████";

/// The six rainbow bands as basic ANSI codes. There is no orange in the basic
/// palette, so yellow stands in for orange and bright yellow for yellow.
const BASIC_BANDS: [&str; 6] = ["31", "33", "93", "32", "34", "35"];

/// Hue in degrees for column `col` of `width`: red (0) to violet (270).
fn hue_for(col: usize, width: usize) -> f64 {
    let last = width.saturating_sub(1).max(1) as f64;
    270.0 * col as f64 / last
}

/// HSV with full saturation and value, as 8-bit RGB.
fn hue_to_rgb(hue: f64) -> (u8, u8, u8) {
    let x = 1.0 - ((hue / 60.0) % 2.0 - 1.0).abs();
    let (r, g, b) = match (hue / 60.0) as u32 {
        0 => (1.0, x, 0.0),
        1 => (x, 1.0, 0.0),
        2 => (0.0, 1.0, x),
        3 => (0.0, x, 1.0),
        4 => (x, 0.0, 1.0),
        _ => (1.0, 0.0, x),
    };
    ((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
}

/// The SGR code for one column.
fn column_code(style: &Style, col: usize, width: usize) -> String {
    if style.truecolor {
        let (r, g, b) = hue_to_rgb(hue_for(col, width));
        format!("38;2;{r};{g};{b}")
    } else {
        let band = (col * BASIC_BANDS.len() / width.max(1)).min(BASIC_BANDS.len() - 1);
        BASIC_BANDS[band].to_string()
    }
}

/// One art line, each non-blank character coloured by its column.
fn gradient_line(style: &Style, line: &str, width: usize) -> String {
    let mut out = String::new();
    for (col, ch) in line.chars().enumerate() {
        if ch == ' ' {
            out.push(ch);
        } else {
            out.push_str(&paint(
                style,
                &column_code(style, col, width),
                &ch.to_string(),
            ));
        }
    }
    out
}

pub fn render(style: &Style, subtitle: &str) -> String {
    let width = ART.lines().map(|l| l.chars().count()).max().unwrap_or(0);
    let mut out = String::new();
    for line in ART.lines() {
        if style.color {
            out.push_str(&gradient_line(style, line, width));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    let mut tagline = format!(
        "the watcher at the Bifröst · v{}",
        env!("CARGO_PKG_VERSION")
    );
    if !subtitle.is_empty() {
        tagline.push_str(" · ");
        tagline.push_str(subtitle);
    }
    out.push_str(&dim(style, &tagline));
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn color() -> Style {
        Style {
            color: true,
            truecolor: false,
        }
    }

    #[test]
    fn banner_plain_has_no_ansi_and_fits_72_cols() {
        let out = render(&Style::plain(), "sub");
        assert!(!out.contains('\x1b'));
        let art: Vec<&str> = out.lines().take(ART.lines().count()).collect();
        assert!(art.len() <= 7);
        for line in out.lines() {
            assert!(line.chars().count() <= 72, "too wide: {line}");
        }
        assert_eq!(art.join("\n"), ART);
        assert!(out.contains("the watcher at the Bifröst"));
        assert!(out.contains(env!("CARGO_PKG_VERSION")));
        assert!(out.contains("sub"));
    }

    #[test]
    fn banner_colored_has_ansi() {
        let out = render(&color(), "");
        assert!(out.contains("\x1b[31m"), "basic red at the left edge");
        assert!(out.contains("\x1b[35m"), "basic violet at the right edge");
        let tc = render(
            &Style {
                color: true,
                truecolor: true,
            },
            "",
        );
        assert!(tc.contains("\x1b[38;2;"));
    }
}
