// SPDX-License-Identifier: MPL-2.0
// Copyright (c) grith contributors

//! Line-based interactive primitives for the onboarding flow.
//!
//! On an interactive TTY the flow runs inside the terminal's **alternate
//! screen** (see [`enter_fullscreen`]): it takes over the full window, clears
//! between steps, and on exit restores the user's original screen (shell
//! history reappears, onboarding output vanishes) — the closing guide is then
//! printed to the restored screen so next-steps persist. Over a pipe / non-TTY
//! no alternate screen or escape codes are emitted; `select` falls back to a
//! numbered prompt read from stdin. Raw mode is entered only for the duration
//! of a single selection (or the final pause) and always restored.

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::{cursor, execute, queue, style::Print, terminal};
use std::io::{IsTerminal, Write};

/// Switch to the alternate screen, hide the cursor, and clear. Returns the
/// error if the terminal won't cooperate so the caller can fall back to the
/// inline (non-fullscreen) flow.
pub fn enter_fullscreen(out: &mut impl Write) -> std::io::Result<()> {
    execute!(
        out,
        EnterAlternateScreen,
        cursor::Hide,
        cursor::MoveTo(0, 0),
        terminal::Clear(terminal::ClearType::All),
    )
}

/// Restore the original screen + cursor. Best-effort; errors are ignored by the
/// caller (we're tearing down regardless).
pub fn leave_fullscreen(out: &mut impl Write) -> std::io::Result<()> {
    execute!(out, cursor::Show, LeaveAlternateScreen)
}

/// Async-signal-safe terminal restoration for the alternate-screen session.
///
/// The normal teardown ([`FullscreenGuard`]'s `Drop`) covers ordinary returns,
/// `?`-propagated errors and panic unwinding. It does **not** cover a signal:
/// during the device-auth browser wait the flow blocks in a poll loop with raw
/// mode *off*, so a Ctrl-C is delivered as `SIGINT` (not consumed as a key) and
/// the default disposition kills the process immediately — stranding the
/// terminal in the alternate buffer with a hidden cursor (wheel events then
/// arrive as cursor-key escapes, i.e. "odd characters"). This handler writes
/// the cursor-show + leave-alt-screen DEC private-mode resets straight to the
/// tty via `write(2)` (one of the few async-signal-safe libc calls) before
/// re-raising the signal with its default disposition so exit status stays
/// correct. Raw mode is necessarily already off when a signal can reach us, so
/// no termios restore is required here.
#[cfg(unix)]
mod sigrestore {
    use std::sync::atomic::{AtomicBool, Ordering};

    static ARMED: AtomicBool = AtomicBool::new(false);

    // `\x1b[?25h` show cursor; `\x1b[?1049l` leave the alternate screen.
    const RESTORE: &[u8] = b"\x1b[?25h\x1b[?1049l";

    extern "C" fn handle(sig: libc::c_int) {
        if ARMED.load(Ordering::SeqCst) {
            // SAFETY: write(2), signal(2) and raise(3) are async-signal-safe.
            // We ignore the write result; there is nothing useful to do on
            // failure mid-signal.
            unsafe {
                libc::write(
                    libc::STDOUT_FILENO,
                    RESTORE.as_ptr().cast::<libc::c_void>(),
                    RESTORE.len(),
                );
                libc::signal(sig, libc::SIG_DFL);
                libc::raise(sig);
            }
        }
    }

    /// Install handlers for the duration of a fullscreen session.
    pub fn arm() {
        ARMED.store(true, Ordering::SeqCst);
        // SAFETY: installing a signal disposition is sound; `handle` is a plain
        // `extern "C"` function with no captured state.
        unsafe {
            libc::signal(libc::SIGINT, handle as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, handle as *const () as libc::sighandler_t);
        }
    }

    /// Restore default dispositions when the session ends normally.
    pub fn disarm() {
        ARMED.store(false, Ordering::SeqCst);
        // SAFETY: as above.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
        }
    }
}

/// RAII guard for the alternate-screen session. Entering switches to the
/// alternate screen and hides the cursor (and, on unix, arms a signal handler);
/// dropping restores the cursor, leaves the alternate screen, and defensively
/// disables raw mode — on *every* exit path, including a panic unwind or a
/// `?`-propagated error from a screen. Construct with [`FullscreenGuard::enter`];
/// `None` means the terminal declined and the caller should render inline.
#[must_use = "dropping the guard is what restores the terminal"]
pub struct FullscreenGuard {
    _private: (),
}

impl FullscreenGuard {
    /// Enter the alternate screen. Returns `None` (leaving the terminal
    /// untouched) if the switch fails, so the caller falls back to inline.
    pub fn enter(out: &mut impl Write) -> Option<Self> {
        if enter_fullscreen(out).is_err() {
            return None;
        }
        #[cfg(unix)]
        sigrestore::arm();
        Some(Self { _private: () })
    }
}

impl Drop for FullscreenGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        sigrestore::disarm();
        // Raw mode may still be set if we unwound from inside a `select`.
        let _ = disable_raw_mode();
        // Write to a fresh stdout handle: the guard outlives the borrow of the
        // caller's writer, and onboarding only enters fullscreen on the real
        // terminal, so this targets the same tty.
        let mut out = std::io::stdout();
        let _ = leave_fullscreen(&mut out);
    }
}

/// Clear the (alternate) screen and home the cursor, so the next step renders
/// on a clean full window.
pub fn clear(out: &mut impl Write) -> std::io::Result<()> {
    execute!(
        out,
        cursor::MoveTo(0, 0),
        terminal::Clear(terminal::ClearType::All),
    )
}

/// Wait for the user to acknowledge the final screen before the alternate
/// screen is torn down (so an async result — e.g. trial activation — is
/// readable). Returns on Enter/Esc/Ctrl-C; any read error just returns Ok.
pub fn pause_for_enter(out: &mut impl Write, style: Style) -> std::io::Result<()> {
    write!(
        out,
        "\r\n  {}\r\n",
        style.dim("Press Enter to finish setup…")
    )?;
    out.flush()?;
    if enable_raw_mode().is_err() {
        return Ok(());
    }
    loop {
        match event::read() {
            Ok(Event::Key(key)) => match key.code {
                KeyCode::Enter | KeyCode::Esc => break,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                _ => {}
            },
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = disable_raw_mode();
    Ok(())
}

/// ANSI styling, suppressed when `--no-color` is in effect.
#[derive(Clone, Copy)]
pub struct Style {
    enabled: bool,
}

impl Style {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }
    fn wrap(self, code: &str, s: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    pub fn green(self, s: &str) -> String {
        self.wrap("1;32", s)
    }
    pub fn dim(self, s: &str) -> String {
        self.wrap("2", s)
    }
    pub fn bold(self, s: &str) -> String {
        self.wrap("1", s)
    }
}

/// A selectable option: a label plus optional indented detail lines.
pub struct Opt {
    pub label: String,
    pub detail: Vec<String>,
}

impl Opt {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            detail: Vec::new(),
        }
    }
    pub fn with_detail(label: impl Into<String>, detail: Vec<String>) -> Self {
        Self {
            label: label.into(),
            detail,
        }
    }
}

/// A single selection screen.
pub struct Prompt<'a> {
    pub step_label: Option<String>,
    pub title: &'a str,
    pub body: &'a [String],
    pub options: &'a [Opt],
    pub default: usize,
    pub allow_back: bool,
    /// When true, `v` returns [`Selection::View`] so the caller can show a
    /// detail panel and re-prompt (used by the welcome's "what's synced").
    pub allow_view: bool,
    pub footer: &'a str,
}

/// The outcome of a selection screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// User picked option `usize`.
    Chosen(usize),
    /// `s` — skip this step, accept its default.
    SkipStep,
    /// `S` — skip all remaining setup.
    SkipAll,
    /// `b` — go back (only offered when `allow_back`).
    Back,
    /// `v` — show a detail panel and re-prompt (only when `allow_view`).
    View,
    /// `Ctrl-C` / `Esc` — abort onboarding without completing.
    Abort,
}

/// Render a selection screen and block for the user's choice.
pub fn select(out: &mut impl Write, style: Style, prompt: &Prompt) -> std::io::Result<Selection> {
    // A malformed empty-options prompt would underflow the selection index;
    // treat it as a benign skip rather than panicking. (No real screen does
    // this; this guards the public primitive.)
    if prompt.options.is_empty() {
        debug_assert!(
            !prompt.options.is_empty(),
            "select() called with no options"
        );
        return Ok(Selection::SkipStep);
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return select_fallback(out, prompt);
    }
    if enable_raw_mode().is_err() {
        // Could not enter raw mode — fall back to a numbered prompt.
        return select_fallback(out, prompt);
    }
    // Print the static header (title / step / body) once. If rendering fails,
    // restore terminal mode before returning the error.
    if let Err(e) = print_header(out, style, prompt).and_then(|()| out.flush()) {
        let _ = disable_raw_mode();
        return Err(e);
    }
    let result = select_raw(out, style, prompt);
    let _ = disable_raw_mode();
    // Newline after the (raw-mode) options block so subsequent output is clean.
    writeln!(out)?;
    result
}

fn print_header(out: &mut impl Write, style: Style, prompt: &Prompt) -> std::io::Result<()> {
    // Runs in raw mode (the caller enables it first so a failed enable can't
    // leave a duplicate header behind). Raw mode disables output
    // post-processing (crossterm uses cfmakeraw → OPOST off), so each line must
    // end with an explicit `\r\n` — a bare `\n` would staircase. Mirrors
    // draw_options / draw_footer.
    write!(out, "\r\n")?;
    if let Some(step) = &prompt.step_label {
        write!(
            out,
            "  {}   {}\r\n",
            style.bold(prompt.title),
            style.dim(step)
        )?;
    } else {
        write!(out, "  {}\r\n", style.bold(prompt.title))?;
    }
    if !prompt.body.is_empty() {
        write!(out, "\r\n")?;
        for line in prompt.body {
            write!(out, "  {line}\r\n")?;
        }
    }
    write!(out, "\r\n")?;
    Ok(())
}

/// Number of *physical* terminal rows the options block + footer occupy at a
/// given terminal width. Long detail lines (e.g. the "Detected:" tool list)
/// wrap, so a logical-line count would under-count and corrupt the redraw on
/// narrow terminals. Widths are computed from the *unstyled* text (ANSI colour
/// codes have zero display width) plus the fixed draw prefixes.
fn block_physical_height(prompt: &Prompt, term_width: usize) -> u16 {
    // Label lines: "  " + 4-char marker + "  " = 8-col prefix. Detail lines:
    // 8-space indent. Footer: "  " = 2-col prefix.
    const LABEL_PREFIX: usize = 8;
    const DETAIL_PREFIX: usize = 8;
    const FOOTER_PREFIX: usize = 2;
    let mut rows = 0u16;
    for opt in prompt.options {
        rows = rows.saturating_add(line_rows(
            LABEL_PREFIX + opt.label.chars().count(),
            term_width,
        ));
        for d in &opt.detail {
            rows = rows.saturating_add(line_rows(DETAIL_PREFIX + d.chars().count(), term_width));
        }
    }
    rows.saturating_add(line_rows(
        FOOTER_PREFIX + prompt.footer.chars().count(),
        term_width,
    ))
}

/// Physical rows a single logical line of `visible` columns occupies at
/// `term_width` (minimum 1).
fn line_rows(visible: usize, term_width: usize) -> u16 {
    if term_width == 0 || visible == 0 {
        return 1;
    }
    u16::try_from(visible.div_ceil(term_width))
        .unwrap_or(u16::MAX)
        .max(1)
}

fn terminal_width() -> usize {
    crossterm::terminal::size()
        .map(|(cols, _)| cols as usize)
        .unwrap_or(80)
}

fn select_raw(out: &mut impl Write, style: Style, prompt: &Prompt) -> std::io::Result<Selection> {
    let mut cursor_idx = prompt.default.min(prompt.options.len().saturating_sub(1));
    let term_width = terminal_width();
    draw_options(out, style, prompt, cursor_idx, false)?;
    draw_footer(out, style, prompt)?;
    out.flush()?;

    let height = block_physical_height(prompt, term_width);

    loop {
        let key = match event::read()? {
            Event::Key(k) => k,
            _ => continue,
        };
        match classify_key(key) {
            KeyAction::Up => {
                cursor_idx = if cursor_idx == 0 {
                    prompt.options.len() - 1
                } else {
                    cursor_idx - 1
                };
            }
            KeyAction::Down => {
                cursor_idx = (cursor_idx + 1) % prompt.options.len();
            }
            KeyAction::Digit(n) if n >= 1 && n <= prompt.options.len() => {
                cursor_idx = n - 1;
            }
            KeyAction::Enter => return Ok(Selection::Chosen(cursor_idx)),
            KeyAction::SkipStep => return Ok(Selection::SkipStep),
            KeyAction::SkipAll => return Ok(Selection::SkipAll),
            KeyAction::Back if prompt.allow_back => return Ok(Selection::Back),
            KeyAction::View if prompt.allow_view => return Ok(Selection::View),
            KeyAction::Abort => return Ok(Selection::Abort),
            _ => continue,
        }
        // Redraw: move cursor back up over the options + footer and repaint.
        queue!(out, cursor::MoveToColumn(0), cursor::MoveUp(height))?;
        queue!(out, terminal::Clear(terminal::ClearType::FromCursorDown))?;
        draw_options(out, style, prompt, cursor_idx, false)?;
        draw_footer(out, style, prompt)?;
        out.flush()?;
    }
}

fn draw_options(
    out: &mut impl Write,
    style: Style,
    prompt: &Prompt,
    cursor_idx: usize,
    _final: bool,
) -> std::io::Result<()> {
    for (i, opt) in prompt.options.iter().enumerate() {
        let selected = i == cursor_idx;
        let marker = if selected { "›  ◉" } else { "   ○" };
        let label = if selected {
            style.green(&opt.label)
        } else {
            opt.label.clone()
        };
        queue!(out, Print(format!("  {marker}  {label}")), Print("\r\n"))?;
        for d in &opt.detail {
            queue!(
                out,
                Print(format!("        {}", style.dim(d))),
                Print("\r\n")
            )?;
        }
    }
    Ok(())
}

fn draw_footer(out: &mut impl Write, style: Style, prompt: &Prompt) -> std::io::Result<()> {
    queue!(
        out,
        Print(format!("  {}", style.dim(prompt.footer))),
        Print("\r\n")
    )?;
    Ok(())
}

/// Non-TTY fallback: print options as a numbered list, read a line from stdin.
/// `s`/`S` skip, `b` back, empty line accepts the default.
fn select_fallback(out: &mut impl Write, prompt: &Prompt) -> std::io::Result<Selection> {
    writeln!(out)?;
    if let Some(step) = &prompt.step_label {
        writeln!(out, "  {}   {step}", prompt.title)?;
    } else {
        writeln!(out, "  {}", prompt.title)?;
    }
    for line in prompt.body {
        writeln!(out, "  {line}")?;
    }
    for (i, opt) in prompt.options.iter().enumerate() {
        let def = if i == prompt.default {
            " (default)"
        } else {
            ""
        };
        writeln!(out, "    {}) {}{def}", i + 1, opt.label)?;
        for d in &opt.detail {
            writeln!(out, "        {d}")?;
        }
    }
    write!(out, "  Choice [s=skip, S=skip all]: ")?;
    out.flush()?;
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line)? == 0 {
        // EOF / no input → take the default.
        return Ok(Selection::Chosen(prompt.default));
    }
    let trimmed = line.trim();
    match trimmed {
        "" => Ok(Selection::Chosen(prompt.default)),
        "s" => Ok(Selection::SkipStep),
        "S" => Ok(Selection::SkipAll),
        "b" if prompt.allow_back => Ok(Selection::Back),
        "v" if prompt.allow_view => Ok(Selection::View),
        other => match other.parse::<usize>() {
            Ok(n) if n >= 1 && n <= prompt.options.len() => Ok(Selection::Chosen(n - 1)),
            _ => Ok(Selection::Chosen(prompt.default)),
        },
    }
}

/// Print a plain informational block (no selection), e.g. the welcome banner or
/// the closing guide. Used in cooked mode.
pub fn info_block(out: &mut impl Write, lines: &[String]) -> std::io::Result<()> {
    writeln!(out)?;
    for line in lines {
        writeln!(out, "  {line}")?;
    }
    writeln!(out)?;
    out.flush()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyAction {
    Up,
    Down,
    Enter,
    SkipStep,
    SkipAll,
    Back,
    View,
    Abort,
    Digit(usize),
    Ignore,
}

fn classify_key(key: KeyEvent) -> KeyAction {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return KeyAction::Abort;
    }
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => KeyAction::Up,
        KeyCode::Down | KeyCode::Char('j') => KeyAction::Down,
        KeyCode::Enter => KeyAction::Enter,
        KeyCode::Esc => KeyAction::Abort,
        KeyCode::Char('s') => KeyAction::SkipStep,
        KeyCode::Char('S') => KeyAction::SkipAll,
        KeyCode::Char('b') => KeyAction::Back,
        KeyCode::Char('v') | KeyCode::Char('V') => KeyAction::View,
        KeyCode::Char(c) if c.is_ascii_digit() => KeyAction::Digit((c as u8 - b'0') as usize),
        _ => KeyAction::Ignore,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn classify_navigation_keys() {
        assert_eq!(classify_key(key(KeyCode::Up)), KeyAction::Up);
        assert_eq!(classify_key(key(KeyCode::Char('k'))), KeyAction::Up);
        assert_eq!(classify_key(key(KeyCode::Down)), KeyAction::Down);
        assert_eq!(classify_key(key(KeyCode::Char('j'))), KeyAction::Down);
        assert_eq!(classify_key(key(KeyCode::Enter)), KeyAction::Enter);
    }

    #[test]
    fn classify_skip_and_abort() {
        assert_eq!(classify_key(key(KeyCode::Char('s'))), KeyAction::SkipStep);
        assert_eq!(classify_key(key(KeyCode::Char('S'))), KeyAction::SkipAll);
        assert_eq!(classify_key(key(KeyCode::Char('b'))), KeyAction::Back);
        assert_eq!(classify_key(key(KeyCode::Esc)), KeyAction::Abort);
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(classify_key(ctrl_c), KeyAction::Abort);
    }

    #[test]
    fn classify_digits() {
        assert_eq!(classify_key(key(KeyCode::Char('1'))), KeyAction::Digit(1));
        assert_eq!(classify_key(key(KeyCode::Char('3'))), KeyAction::Digit(3));
    }

    #[test]
    fn block_height_counts_labels_detail_and_footer_when_wide() {
        let options = vec![
            Opt::with_detail("a", vec!["d1".into(), "d2".into()]),
            Opt::new("b"),
        ];
        let prompt = Prompt {
            step_label: None,
            title: "t",
            body: &[],
            options: &options,
            default: 0,
            allow_back: false,
            allow_view: false,
            footer: "f",
        };
        // Wide terminal → no wrapping. a: 1 label + 2 detail, b: 1 label,
        // footer: 1 → 5 rows.
        assert_eq!(block_physical_height(&prompt, 200), 5);
    }

    #[test]
    fn block_height_accounts_for_wrapping_on_narrow_terminals() {
        // A detail line longer than the (narrow) width must count as 2 rows.
        // Detail prefix is 8 cols; a 30-char detail at width 20 → 8+30=38 cols
        // → ceil(38/20) = 2 rows.
        let long = "x".repeat(30);
        let options = vec![Opt::with_detail("a", vec![long])];
        let prompt = Prompt {
            step_label: None,
            title: "t",
            body: &[],
            options: &options,
            default: 0,
            allow_back: false,
            allow_view: false,
            footer: "",
        };
        // label "a": 8+1=9 cols → 1 row; detail → 2 rows; footer "" → 1 row.
        assert_eq!(block_physical_height(&prompt, 20), 4);
        // At a wide width the same block is 3 rows (no wrap).
        assert_eq!(block_physical_height(&prompt, 200), 3);
    }

    #[test]
    fn line_rows_is_ceil_with_min_one() {
        assert_eq!(line_rows(0, 80), 1);
        assert_eq!(line_rows(80, 80), 1);
        assert_eq!(line_rows(81, 80), 2);
        assert_eq!(line_rows(160, 80), 2);
        assert_eq!(line_rows(161, 80), 3);
        assert_eq!(line_rows(10, 0), 1); // unknown width → 1
    }

    #[test]
    fn style_respects_no_color() {
        let plain = Style::new(false);
        assert_eq!(plain.green("x"), "x");
        let colored = Style::new(true);
        assert!(colored.green("x").contains("\x1b["));
    }

    #[test]
    fn fullscreen_helpers_emit_expected_sequences() {
        let mut enter = Vec::new();
        super::enter_fullscreen(&mut enter).unwrap();
        let enter = String::from_utf8(enter).unwrap();
        assert!(enter.contains("\u{1b}[?1049h"), "enters alternate screen");
        assert!(enter.contains("\u{1b}[2J"), "clears on enter");

        let mut leave = Vec::new();
        super::leave_fullscreen(&mut leave).unwrap();
        assert!(
            String::from_utf8(leave).unwrap().contains("\u{1b}[?1049l"),
            "leaves alternate screen"
        );

        let mut cleared = Vec::new();
        super::clear(&mut cleared).unwrap();
        assert!(
            String::from_utf8(cleared).unwrap().contains("\u{1b}[2J"),
            "clear emits erase-screen"
        );
    }
}
