//! Minimal Tauri 2 shell for the shared kotama-overlay model.
//!
//! Hikari Vue draws snapshots and forwards pointer/key events. Action ids are
//! returned to the frontend and printed to stdout; no target is touched.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;

use kotama_overlay::{
    ActionOutcome, ActionRequest, Key, Modifiers, OverlayModel, OverlaySetup, OverlaySnapshot,
    Shortcut,
};
use serde::Serialize;
use tauri::{LogicalSize, Manager, State, WebviewWindow};

const SETUP_JSON: &str = include_str!("../../../demo-actions.json");

struct Session {
    model: OverlayModel,
    origin: (i32, i32),
}

type Shared = Mutex<Session>;

#[derive(Serialize)]
struct Invoked {
    id: Option<String>,
    outcome: ActionOutcome,
}

#[tauri::command]
fn snapshot_view(
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<OverlaySnapshot, String> {
    let snapshot = state
        .lock()
        .map_err(|error| error.to_string())?
        .model
        .snapshot();
    resize(&window, &snapshot)?;
    Ok(snapshot)
}

#[tauri::command]
fn pointer_moved(
    window: WebviewWindow,
    state: State<'_, Shared>,
    x: i32,
    y: i32,
) -> Result<OverlaySnapshot, String> {
    let mut session = state.lock().map_err(|error| error.to_string())?;
    let origin = session.origin;
    let changed = session.model.pointer_moved(x + origin.0, y + origin.1);
    let snapshot = session.model.snapshot();
    drop(session);
    if changed {
        resize(&window, &snapshot)?;
    }
    Ok(snapshot)
}

#[tauri::command]
fn pointer_left(
    window: WebviewWindow,
    state: State<'_, Shared>,
) -> Result<OverlaySnapshot, String> {
    let mut session = state.lock().map_err(|error| error.to_string())?;
    let changed = session.model.pointer_left();
    let snapshot = session.model.snapshot();
    drop(session);
    if changed {
        resize(&window, &snapshot)?;
    }
    Ok(snapshot)
}

#[tauri::command]
fn click(state: State<'_, Shared>, x: i32, y: i32) -> Result<Invoked, String> {
    let session = state.lock().map_err(|error| error.to_string())?;
    let request = session
        .model
        .click(x + session.origin.0, y + session.origin.1);
    Ok(invoke(&session.model, request))
}

#[tauri::command]
fn press_shortcut(
    state: State<'_, Shared>,
    ctrl: bool,
    alt: bool,
    shift: bool,
    meta: bool,
    key: String,
) -> Result<Invoked, String> {
    let Some(key) = Key::parse(&key) else {
        return Ok(Invoked {
            id: None,
            outcome: ActionOutcome::Unknown,
        });
    };
    let shortcut = Shortcut {
        modifiers: Modifiers {
            ctrl,
            alt,
            shift,
            meta,
        },
        key,
    };
    let session = state.lock().map_err(|error| error.to_string())?;
    Ok(invoke(&session.model, session.model.shortcut(shortcut)))
}

#[tauri::command]
fn grant_write(state: State<'_, Shared>) -> Result<OverlaySnapshot, String> {
    let mut session = state.lock().map_err(|error| error.to_string())?;
    session.model.grant_write();
    Ok(session.model.snapshot())
}

fn invoke(model: &OverlayModel, request: Option<ActionRequest>) -> Invoked {
    let Some(request) = request else {
        return Invoked {
            id: None,
            outcome: ActionOutcome::Unknown,
        };
    };
    let outcome = model.authorize(&request);
    if outcome == ActionOutcome::Allowed {
        println!("action={}", request.id);
    }
    Invoked {
        id: Some(request.id),
        outcome,
    }
}

fn resize(window: &WebviewWindow, snapshot: &OverlaySnapshot) -> Result<(), String> {
    window
        .set_size(LogicalSize::new(
            f64::from(snapshot.window_rect.width),
            f64::from(snapshot.window_rect.height),
        ))
        .map_err(|error| error.to_string())
}

fn main() {
    let setup: OverlaySetup = serde_json::from_str(SETUP_JSON).expect("embedded setup must parse");
    let mut model = OverlayModel::from_setup(setup).expect("embedded setup must be valid");
    let expanded = std::env::var("KOTAMA_OVERLAY_EXPANDED").is_ok();
    if expanded {
        model.expand();
    }
    let initial_size = model.window_rect();
    let origin = (initial_size.x, initial_size.y);
    tauri::Builder::default()
        .manage(Shared::new(Session { model, origin }))
        .invoke_handler(tauri::generate_handler![
            snapshot_view,
            pointer_moved,
            pointer_left,
            click,
            press_shortcut,
            grant_write
        ])
        .setup(move |app| {
            if let Some(window) = app.get_webview_window("toolbar") {
                let _ = window.set_always_on_top(true);
                if expanded {
                    let _ = window.set_size(LogicalSize::new(
                        f64::from(initial_size.width),
                        f64::from(initial_size.height),
                    ));
                }
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
