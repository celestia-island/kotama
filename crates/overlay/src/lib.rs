//! Platform-neutral model for a top-left hover toolbar.
//!
//! Tauri and egui shells share this crate: they only draw [OverlaySnapshot] and
//! translate pointer/key events into model calls. Actions are opaque ids supplied
//! by the host application; this crate never performs I/O and never executes an
//! action itself. Write actions are denied until the host grants [Capability::ReadWrite].

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Capability required to run an action.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub enum Capability {
    /// Observation only.
    ReadOnly,
    /// May mutate the target.
    ReadWrite,
}

impl Capability {
    /// True when this granted capability satisfies the required one.
    #[must_use]
    pub const fn allows(self, required: Self) -> bool {
        matches!(
            (self, required),
            (Self::ReadWrite, _) | (Self::ReadOnly, Self::ReadOnly)
        )
    }
}

/// Keyboard key used by a shortcut.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub enum Key {
    /// A printable character, stored uppercase.
    Character(char),
    /// Function key F1..F24.
    Function(u8),
    /// Escape.
    Escape,
    /// Tab.
    Tab,
    /// Space.
    Space,
    /// Enter or Return.
    Enter,
}

impl Key {
    /// Parse one key token.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        let upper = token.trim().to_ascii_uppercase();
        if let Some(rest) = upper.strip_prefix('F') {
            if let Ok(number) = rest.parse::<u8>() {
                if (1..=24).contains(&number) {
                    return Some(Self::Function(number));
                }
            }
        }
        match upper.as_str() {
            "ESC" | "ESCAPE" => Some(Self::Escape),
            "TAB" => Some(Self::Tab),
            "SPACE" => Some(Self::Space),
            "ENTER" | "RETURN" => Some(Self::Enter),
            _ => {
                let mut chars = upper.chars();
                let first = chars.next()?;
                if chars.next().is_none() && first.is_ascii_alphanumeric() {
                    Some(Self::Character(first))
                } else {
                    None
                }
            }
        }
    }
}

/// Modifier state for a shortcut.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize, Debug,
)]
pub struct Modifiers {
    /// Control.
    pub ctrl: bool,
    /// Alt.
    pub alt: bool,
    /// Shift.
    pub shift: bool,
    /// Meta/Windows/Super.
    pub meta: bool,
}

/// A normalized keyboard shortcut.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Shortcut {
    /// Modifier state.
    pub modifiers: Modifiers,
    /// Non-modifier key.
    pub key: Key,
}

impl Shortcut {
    /// Parse a case-insensitive form such as "Ctrl+Alt+F12" or "Shift+H".
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut modifiers = Modifiers::default();
        let mut key = None;
        for token in text
            .split('+')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            match token.to_ascii_lowercase().as_str() {
                "ctrl" | "control" => modifiers.ctrl = true,
                "alt" => modifiers.alt = true,
                "shift" => modifiers.shift = true,
                "meta" | "super" | "win" => modifiers.meta = true,
                _ => {
                    if key.is_some() {
                        return None;
                    }
                    key = Some(Key::parse(token)?);
                }
            }
        }
        Some(Self {
            modifiers,
            key: key?,
        })
    }

    /// Exact match against a pressed shortcut.
    #[must_use]
    pub const fn matches(self, pressed: Self) -> bool {
        self.modifiers.ctrl == pressed.modifiers.ctrl
            && self.modifiers.alt == pressed.modifiers.alt
            && self.modifiers.shift == pressed.modifiers.shift
            && self.modifiers.meta == pressed.modifiers.meta
            && match (self.key, pressed.key) {
                (Key::Character(expected), Key::Character(actual)) => expected == actual,
                (Key::Function(expected), Key::Function(actual)) => expected == actual,
                (Key::Escape, Key::Escape)
                | (Key::Tab, Key::Tab)
                | (Key::Space, Key::Space)
                | (Key::Enter, Key::Enter) => true,
                _ => false,
            }
    }
}

/// Rectangle in screen coordinates.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug)]
pub struct Rect {
    /// Left.
    pub x: i32,
    /// Top.
    pub y: i32,
    /// Width.
    pub width: i32,
    /// Height.
    pub height: i32,
}

impl Rect {
    /// True when the point is inside, including the top/left edges.
    #[must_use]
    pub const fn contains(self, x: i32, y: i32) -> bool {
        x >= self.x && y >= self.y && x < self.x + self.width && y < self.y + self.height
    }
}

/// Toolbar geometry and row metrics.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct OverlayConfig {
    /// Distance from the top-left screen corner.
    pub margin: i32,
    /// Width while collapsed.
    pub collapsed_width: i32,
    /// Height while collapsed.
    pub collapsed_height: i32,
    /// Width while expanded.
    pub expanded_width: i32,
    /// Height of the title strip.
    pub title_height: i32,
    /// Height of one action row.
    pub row_height: i32,
    /// Inner padding.
    pub padding: i32,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            margin: 8,
            collapsed_width: 180,
            collapsed_height: 36,
            expanded_width: 280,
            title_height: 32,
            row_height: 32,
            padding: 8,
        }
    }
}

/// One action exposed by the host to the toolbar.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ActionSpec {
    /// Stable opaque id interpreted by the host.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Optional keyboard shortcut.
    pub shortcut: Option<Shortcut>,
    /// Capability required to run it.
    pub capability: Capability,
    /// False disables the row and shortcut without removing it.
    pub enabled: bool,
}

impl ActionSpec {
    /// Start a read-only, enabled action.
    #[must_use]
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            shortcut: None,
            capability: Capability::ReadOnly,
            enabled: true,
        }
    }

    /// Attach a shortcut.
    #[must_use]
    pub fn with_shortcut(mut self, shortcut: Shortcut) -> Self {
        self.shortcut = Some(shortcut);
        self
    }

    /// Require write capability.
    #[must_use]
    pub fn requiring_write(mut self) -> Self {
        self.capability = Capability::ReadWrite;
        self
    }

    /// Disable the action.
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// Complete shell input: config, action list and initial capability.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OverlaySetup {
    /// Geometry and row metrics.
    pub config: OverlayConfig,
    /// Actions in render order.
    pub actions: Vec<ActionSpec>,
    /// Initial capability; hosts normally start read-only.
    pub capability: Capability,
}

/// A request to run one host action.
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub struct ActionRequest {
    /// Opaque action id.
    pub id: String,
}

/// Result of capability/enabled checks; the host still performs the action.
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub enum ActionOutcome {
    /// The host may execute the action.
    Allowed,
    /// The id is not registered.
    Unknown,
    /// The action is disabled.
    Disabled,
    /// The host has not granted the required capability.
    Denied {
        /// Required capability.
        required: Capability,
        /// Currently granted capability.
        granted: Capability,
    },
}

/// A rendered row for shells.
#[derive(Clone, Serialize, Debug)]
pub struct RowSnapshot {
    /// Action id.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Whether the row is enabled.
    pub enabled: bool,
    /// Row rectangle.
    pub rect: Rect,
}

/// Everything a Tauri or egui shell needs to draw one frame.
#[derive(Clone, Serialize, Debug)]
pub struct OverlaySnapshot {
    /// Expanded state.
    pub expanded: bool,
    /// Pointer is inside the window.
    pub hovered: bool,
    /// Currently granted capability.
    pub capability: Capability,
    /// Window rectangle (collapsed or expanded).
    pub window_rect: Rect,
    /// Action rows in deterministic order.
    pub rows: Vec<RowSnapshot>,
}

/// Model construction error.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OverlayError(pub String);

impl fmt::Display for OverlayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OverlayError {}

/// Hover-toolbar state machine.
#[derive(Clone, Debug)]
pub struct OverlayModel {
    config: OverlayConfig,
    actions: Vec<ActionSpec>,
    capability: Capability,
    expanded: bool,
    hovered: bool,
}

impl OverlayModel {
    /// Build a model, rejecting duplicate ids and duplicate shortcuts.
    ///
    /// # Errors
    /// Returns [OverlayError] when ids or shortcuts collide.
    pub fn new(
        config: OverlayConfig,
        actions: Vec<ActionSpec>,
        capability: Capability,
    ) -> Result<Self, OverlayError> {
        let mut ids = BTreeSet::new();
        let mut shortcuts = BTreeSet::new();
        for action in &actions {
            if action.id.is_empty() {
                return Err(OverlayError("action id must not be empty".to_string()));
            }
            if !ids.insert(action.id.clone()) {
                return Err(OverlayError(format!("duplicate action id: {}", action.id)));
            }
            if let Some(shortcut) = action.shortcut {
                if !shortcuts.insert(shortcut) {
                    return Err(OverlayError(format!("duplicate shortcut: {}", action.id)));
                }
            }
        }
        Ok(Self {
            config,
            actions,
            capability,
            expanded: false,
            hovered: false,
        })
    }

    /// Build a model from a deserialized setup.
    ///
    /// # Errors
    /// Returns [OverlayError] when ids or shortcuts collide.
    pub fn from_setup(setup: OverlaySetup) -> Result<Self, OverlayError> {
        Self::new(setup.config, setup.actions, setup.capability)
    }

    /// Current action list.
    #[must_use]
    pub fn actions(&self) -> &[ActionSpec] {
        &self.actions
    }

    /// Granted capability.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// Explicitly grant write access.
    pub fn grant_write(&mut self) {
        self.capability = Capability::ReadWrite;
    }

    /// Return to read-only.
    pub fn revoke_write(&mut self) {
        self.capability = Capability::ReadOnly;
    }

    /// Height of the expanded window for the current action count.
    #[must_use]
    pub fn expanded_height(&self) -> i32 {
        self.config.title_height
            + self.config.padding * 2
            + self.config.row_height * i32::try_from(self.actions.len()).unwrap_or(i32::MAX)
    }

    /// Current window rectangle.
    #[must_use]
    pub fn window_rect(&self) -> Rect {
        Rect {
            x: self.config.margin,
            y: self.config.margin,
            width: if self.expanded {
                self.config.expanded_width
            } else {
                self.config.collapsed_width
            },
            height: if self.expanded {
                self.expanded_height()
            } else {
                self.config.collapsed_height
            },
        }
    }

    /// Feed a pointer move. Returns true when the expanded state changed.
    pub fn pointer_moved(&mut self, x: i32, y: i32) -> bool {
        let inside = self.window_rect().contains(x, y);
        if inside == self.hovered {
            return false;
        }
        self.hovered = inside;
        self.expanded = inside;
        true
    }

    /// Expand programmatically (keyboard/accessibility or a capture harness).
    pub fn expand(&mut self) {
        self.expanded = true;
        self.hovered = false;
    }

    /// Collapse programmatically.
    pub fn collapse(&mut self) {
        self.expanded = false;
        self.hovered = false;
    }

    /// Feed a pointer leave. Returns true when the state changed.
    pub fn pointer_left(&mut self) -> bool {
        if !self.hovered {
            return false;
        }
        self.hovered = false;
        self.expanded = false;
        true
    }

    /// Row rectangle by index, or None when collapsed/out of range.
    #[must_use]
    pub fn row_rect(&self, index: usize) -> Option<Rect> {
        if !self.expanded || index >= self.actions.len() {
            return None;
        }
        let row = i32::try_from(index).ok()?;
        Some(Rect {
            x: self.config.margin + self.config.padding,
            y: self.config.margin
                + self.config.title_height
                + self.config.padding
                + self.config.row_height * row,
            width: self.config.expanded_width - self.config.padding * 2,
            height: self.config.row_height,
        })
    }

    fn hit_index(&self, x: i32, y: i32) -> Option<usize> {
        (0..self.actions.len()).find(|index| {
            self.row_rect(*index)
                .is_some_and(|rect| rect.contains(x, y))
        })
    }

    /// Click at a screen point; returns the requested action id.
    #[must_use]
    pub fn click(&self, x: i32, y: i32) -> Option<ActionRequest> {
        let index = self.hit_index(x, y)?;
        Some(ActionRequest {
            id: self.actions[index].id.clone(),
        })
    }

    /// Match a pressed shortcut to an action.
    #[must_use]
    pub fn shortcut(&self, pressed: Shortcut) -> Option<ActionRequest> {
        self.actions
            .iter()
            .find(|action| {
                action
                    .shortcut
                    .is_some_and(|shortcut| shortcut.matches(pressed))
            })
            .map(|action| ActionRequest {
                id: action.id.clone(),
            })
    }

    /// Check enabled/capability constraints before the host runs an action.
    #[must_use]
    pub fn authorize(&self, request: &ActionRequest) -> ActionOutcome {
        let Some(action) = self.actions.iter().find(|action| action.id == request.id) else {
            return ActionOutcome::Unknown;
        };
        if !action.enabled {
            return ActionOutcome::Disabled;
        }
        if !self.capability.allows(action.capability) {
            return ActionOutcome::Denied {
                required: action.capability,
                granted: self.capability,
            };
        }
        ActionOutcome::Allowed
    }

    /// Snapshot for a shell frame.
    #[must_use]
    pub fn snapshot(&self) -> OverlaySnapshot {
        let rows = if self.expanded {
            self.actions
                .iter()
                .enumerate()
                .filter_map(|(index, action)| {
                    Some(RowSnapshot {
                        id: action.id.clone(),
                        label: action.label.clone(),
                        enabled: action.enabled,
                        rect: self.row_rect(index)?,
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        OverlaySnapshot {
            expanded: self.expanded,
            hovered: self.hovered,
            capability: self.capability,
            window_rect: self.window_rect(),
            rows,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OverlayConfig {
        OverlayConfig::default()
    }

    fn model() -> OverlayModel {
        OverlayModel::new(
            config(),
            vec![
                ActionSpec::new("sun", "Sun +1000").requiring_write(),
                ActionSpec::new("cooldown", "Reset cooldowns")
                    .requiring_write()
                    .with_shortcut(Shortcut::parse("Ctrl+Alt+F12").unwrap()),
                ActionSpec::new("read", "Inspect"),
            ],
            Capability::ReadOnly,
        )
        .unwrap()
    }

    #[test]
    fn hover_expands_and_leave_collapses() {
        let mut model = model();
        assert!(!model.snapshot().expanded);
        assert_eq!(model.window_rect().width, config().collapsed_width);
        assert!(model.pointer_moved(10, 10));
        assert!(model.snapshot().expanded);
        assert!(model.window_rect().height > config().collapsed_height);
        assert!(!model.pointer_moved(20, 20));
        assert!(model.pointer_moved(2000, 2000));
        assert!(!model.snapshot().expanded);
        assert!(!model.pointer_left());
    }

    #[test]
    fn rows_only_click_when_expanded_and_map_to_ids() {
        let mut model = model();
        assert!(model.click(20, 50).is_none());
        model.pointer_moved(10, 10);
        let row = model.row_rect(0).unwrap();
        assert_eq!(model.click(row.x + 2, row.y + 2).unwrap().id, "sun");
        assert!(model.click(row.x, row.y - 1).is_none());
    }

    #[test]
    fn shortcuts_and_capability_gate() {
        let mut model = model();
        let request = model
            .shortcut(Shortcut::parse("ctrl+alt+f12").unwrap())
            .unwrap();
        assert_eq!(request.id, "cooldown");
        assert_eq!(
            model.authorize(&request),
            ActionOutcome::Denied {
                required: Capability::ReadWrite,
                granted: Capability::ReadOnly,
            }
        );
        model.grant_write();
        assert_eq!(model.authorize(&request), ActionOutcome::Allowed);
        assert_eq!(
            model.authorize(&ActionRequest {
                id: "missing".to_string()
            }),
            ActionOutcome::Unknown
        );
        assert_eq!(
            model.authorize(&ActionRequest {
                id: "read".to_string()
            }),
            ActionOutcome::Allowed
        );
    }

    #[test]
    fn disabled_and_duplicate_actions_are_reported() {
        let mut model = model();
        model.actions[2].enabled = false;
        assert_eq!(
            model.authorize(&ActionRequest {
                id: "read".to_string()
            }),
            ActionOutcome::Disabled
        );
        let duplicate_id = OverlayModel::new(
            config(),
            vec![ActionSpec::new("same", "A"), ActionSpec::new("same", "B")],
            Capability::ReadOnly,
        );
        assert!(duplicate_id.is_err());
        let duplicate_shortcut = OverlayModel::new(
            config(),
            vec![
                ActionSpec::new("a", "A").with_shortcut(Shortcut::parse("Shift+H").unwrap()),
                ActionSpec::new("b", "B").with_shortcut(Shortcut::parse("Shift+H").unwrap()),
            ],
            Capability::ReadOnly,
        );
        assert!(duplicate_shortcut.is_err());
    }

    #[test]
    fn setup_json_round_trips_and_builds_a_model() {
        let json = r#"{
            "config": {
                "margin": 8,
                "collapsed_width": 180,
                "collapsed_height": 36,
                "expanded_width": 280,
                "title_height": 32,
                "row_height": 32,
                "padding": 8
            },
            "actions": [
                {
                    "id": "demo.read",
                    "label": "Inspect",
                    "shortcut": null,
                    "capability": "ReadOnly",
                    "enabled": true
                },
                {
                    "id": "demo.write",
                    "label": "Write",
                    "shortcut": { "modifiers": { "ctrl": true, "alt": false, "shift": false, "meta": false }, "key": { "Character": "W" } },
                    "capability": "ReadWrite",
                    "enabled": true
                }
            ],
            "capability": "ReadOnly"
        }"#;
        let setup: OverlaySetup = serde_json::from_str(json).unwrap();
        let model = OverlayModel::from_setup(setup).unwrap();
        assert_eq!(model.actions().len(), 2);
        assert_eq!(
            model.authorize(&ActionRequest {
                id: "demo.write".to_string()
            }),
            ActionOutcome::Denied {
                required: Capability::ReadWrite,
                granted: Capability::ReadOnly,
            }
        );
        assert_eq!(
            model
                .shortcut(Shortcut::parse("Ctrl+W").unwrap())
                .unwrap()
                .id,
            "demo.write"
        );
    }

    #[test]
    fn snapshots_are_serializable_and_deterministic() {
        let mut model = model();
        model.pointer_moved(10, 10);
        let first = serde_json::to_string(&model.snapshot()).unwrap();
        let second = serde_json::to_string(&model.snapshot()).unwrap();
        assert_eq!(first, second);
        assert!(first.contains("\"expanded\":true"));
        assert!(first.contains("\"rows\":["));
    }
}
