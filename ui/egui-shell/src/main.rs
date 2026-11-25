//! Minimal egui shell for the shared kotama-overlay model.
//!
//! The shell only draws snapshots and forwards pointer/click events. Action ids
//! are printed to stdout; this demo never touches a target process.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use eframe::egui;
use kotama_overlay::{
    ActionOutcome, ActionRequest, ActionSpec, Capability, OverlayModel, OverlaySetup, Rect,
};

struct Shell {
    model: OverlayModel,
    message: String,
    deadline: Option<Instant>,
    screenshot: Option<PathBuf>,
    screenshot_requested: bool,
    adapter: Vec<String>,
    initial_action: Option<String>,
}

impl Shell {
    fn new(model: OverlayModel, seconds: Option<u64>) -> Self {
        Self {
            model,
            message: "hover to expand; click a row".to_string(),
            deadline: seconds.map(|seconds| Instant::now() + Duration::from_secs(seconds)),
            screenshot: None,
            screenshot_requested: false,
            adapter: Vec::new(),
            initial_action: None,
        }
    }

    fn run_adapter(&self, action: &str) {
        let Some(program) = self.adapter.first() else {
            return;
        };
        match Command::new(program)
            .args(&self.adapter[1..])
            .arg(action)
            .status()
        {
            Ok(status) if status.success() => println!("adapter={action} ok"),
            Ok(status) => eprintln!("adapter={action} failed: {status}"),
            Err(error) => eprintln!("adapter={action} spawn failed: {error}"),
        }
    }

    fn apply(&mut self, request: ActionRequest) {
        match self.model.authorize(&request) {
            ActionOutcome::Allowed => {
                self.message = format!("invoked {}", request.id);
                println!("action={}", request.id);
                self.run_adapter(&request.id);
            }
            ActionOutcome::Denied { required, granted } => {
                self.message = format!("denied {} ({required:?} > {granted:?})", request.id);
            }
            ActionOutcome::Disabled => {
                self.message = format!("disabled {}", request.id);
            }
            ActionOutcome::Unknown => {
                self.message = format!("unknown {}", request.id);
            }
        }
    }

    fn resize(&self, ctx: &egui::Context) {
        let rect = self.model.window_rect();
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(
            rect.width as f32,
            rect.height as f32,
        )));
    }
}

impl eframe::App for Shell {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if let Some(id) = self.initial_action.take() {
            self.apply(ActionRequest { id });
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        let before = self.model.window_rect();
        let pointer = ctx.input(|input| input.pointer.hover_pos());
        let changed = if let Some(position) = pointer {
            self.model.pointer_moved(
                position.x.round() as i32 + before.x,
                position.y.round() as i32 + before.y,
            )
        } else {
            self.model.pointer_left()
        };
        if changed {
            self.resize(&ctx);
        }
        if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        let clicked = ctx.input(|input| {
            input
                .pointer
                .primary_clicked()
                .then(|| input.pointer.interact_pos())
                .flatten()
        });
        if let Some(position) = clicked {
            let rect = self.model.window_rect();
            if let Some(request) = self.model.click(
                position.x.round() as i32 + rect.x,
                position.y.round() as i32 + rect.y,
            ) {
                self.apply(request);
            }
        }

        let snapshot = self.model.snapshot();
        let local = Rect {
            x: 0,
            y: 0,
            width: snapshot.window_rect.width,
            height: snapshot.window_rect.height,
        };
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE)
            .show(ui, |ui| {
                let origin = ui.max_rect().min;
                let painter = ui.painter();
                let full = egui::Rect::from_min_size(
                    origin,
                    egui::vec2(local.width as f32, local.height as f32),
                );
                painter.rect_filled(full, 8.0, egui::Color32::from_rgb(24, 28, 36));
                painter.text(
                    origin + egui::vec2(12.0, 8.0),
                    egui::Align2::LEFT_TOP,
                    format!("kotama overlay  {:?}", snapshot.capability),
                    egui::FontId::proportional(13.0),
                    egui::Color32::from_rgb(236, 240, 248),
                );
                if snapshot.expanded {
                    for row in &snapshot.rows {
                        let row_rect = egui::Rect::from_min_size(
                            origin
                                + egui::vec2(
                                    (row.rect.x - snapshot.window_rect.x) as f32,
                                    (row.rect.y - snapshot.window_rect.y) as f32,
                                ),
                            egui::vec2(row.rect.width as f32, row.rect.height as f32),
                        );
                        let fill = if row.enabled {
                            egui::Color32::from_rgb(44, 52, 68)
                        } else {
                            egui::Color32::from_rgb(32, 36, 44)
                        };
                        painter.rect_filled(row_rect, 4.0, fill);
                        painter.text(
                            row_rect.left_center() + egui::vec2(8.0, 0.0),
                            egui::Align2::LEFT_CENTER,
                            &row.label,
                            egui::FontId::proportional(13.0),
                            if row.enabled {
                                egui::Color32::from_rgb(220, 228, 240)
                            } else {
                                egui::Color32::from_rgb(120, 128, 140)
                            },
                        );
                    }
                }
            });
        if !self.screenshot_requested {
            if let Some(path) = self.screenshot.clone() {
                self.screenshot_requested = true;
                ctx.request_screenshot(move |image| {
                    let [width, height] = image.size;
                    let mut rgba = Vec::with_capacity(width * height * 4);
                    for pixel in &image.pixels {
                        let [r, g, b, a] = pixel.to_array();
                        let alpha = u16::from(a);
                        let blend = |channel: u8| -> u8 {
                            ((u16::from(channel) * alpha + 32 * (255 - alpha)) / 255) as u8
                        };
                        rgba.extend_from_slice(&[blend(r), blend(g), blend(b), 255]);
                    }
                    if let Err(error) = image::save_buffer(
                        &path,
                        &rgba,
                        width as u32,
                        height as u32,
                        image::ColorType::Rgba8,
                    ) {
                        eprintln!("screenshot {}: {error}", path.display());
                    }
                });
            }
        }
    }
}

fn load_setup(path: &PathBuf) -> Result<OverlaySetup, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn fallback_setup() -> OverlaySetup {
    OverlaySetup {
        config: Default::default(),
        actions: vec![
            ActionSpec::new("demo.inspect", "Inspect"),
            ActionSpec::new("demo.write", "Example write").requiring_write(),
            ActionSpec::new("demo.disabled", "Disabled example").disabled(),
        ],
        capability: Capability::ReadOnly,
    }
}

fn main() -> eframe::Result {
    let mut setup_path: Option<PathBuf> = None;
    let mut seconds: Option<u64> = None;
    let mut expanded = false;
    let mut screenshot: Option<PathBuf> = None;
    let mut adapter: Vec<String> = Vec::new();
    let mut invoke: Option<String> = None;
    let mut grant_write = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--setup" => setup_path = args.next().map(PathBuf::from),
            "--seconds" => seconds = args.next().and_then(|value| value.parse().ok()),
            "--expanded" => expanded = true,
            "--screenshot" => screenshot = args.next().map(PathBuf::from),
            "--adapter" => {
                if let Some(program) = args.next() {
                    adapter.push(program);
                }
            }
            "--adapter-arg" => {
                if let Some(argument) = args.next() {
                    adapter.push(argument);
                }
            }
            "--invoke" => invoke = args.next(),
            "--grant-write" => grant_write = true,
            "--help" => {
                println!(
                    "usage: kotama-overlay-egui [--setup actions.json] [--seconds N] [--expanded] [--screenshot path] [--adapter program] [--adapter-arg arg]... [--invoke action-id] [--grant-write]"
                );
                return Ok(());
            }
            _ => {}
        }
    }
    let setup = match setup_path.as_ref() {
        Some(path) => match load_setup(path) {
            Ok(setup) => setup,
            Err(error) => {
                eprintln!("kotama-overlay-egui: {error}");
                return Ok(());
            }
        },
        None => fallback_setup(),
    };
    let mut model = match OverlayModel::from_setup(setup) {
        Ok(model) => model,
        Err(error) => {
            eprintln!("kotama-overlay-egui: {error}");
            return Ok(());
        }
    };
    if expanded {
        model.expand();
    }
    if grant_write {
        model.grant_write();
    }
    let size = model.window_rect();
    if let Ok(path) = std::env::var("KOTAMA_UI_DEBUG") {
        let _ = std::fs::write(
            path,
            format!("expanded={expanded} size={}x{}", size.width, size.height),
        );
    }
    let options = eframe::NativeOptions {
        persist_window: false,
        viewport: egui::ViewportBuilder::default()
            .with_title("kotama overlay (egui)")
            .with_inner_size([size.width as f32, size.height as f32])
            .with_position([8.0, 8.0])
            .with_decorations(false)
            .with_resizable(false)
            .with_transparent(true)
            .with_always_on_top(),
        ..Default::default()
    };
    eframe::run_native(
        "kotama-overlay-egui",
        options,
        Box::new(move |_cc| {
            let mut shell = Shell::new(model, seconds);
            shell.screenshot = screenshot;
            shell.adapter = adapter;
            shell.initial_action = invoke;
            Ok(Box::new(shell))
        }),
    )
}
