mod commands;
mod gpg;

use tauri::Manager;

/// `tauri dev` runs a bare executable, so macOS shows a generic Dock icon.
/// Bundled builds get the icon from the `.icns`, so this is debug-only.
#[cfg(all(target_os = "macos", debug_assertions))]
fn set_dev_dock_icon() {
    use objc2::{AnyThread, MainThreadMarker};
    use objc2_app_kit::{NSApplication, NSImage};
    use objc2_foundation::NSData;

    let Some(mtm) = MainThreadMarker::new() else { return };
    let data = NSData::with_bytes(include_bytes!("../icons/icon.png"));
    if let Some(image) = NSImage::initWithData(NSImage::alloc(), &data) {
        // SAFETY: called on the main thread with a valid, owned NSImage.
        unsafe { NSApplication::sharedApplication(mtm).setApplicationIconImage(Some(&image)) };
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            #[cfg(all(target_os = "macos", debug_assertions))]
            set_dev_dock_icon();
            let dir = app.path().app_data_dir()?.join("keyring");
            app.manage(gpg::teams::TeamStore::open(dir.clone()));
            app.manage(gpg::store::KeyStore::open(dir)?);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_keys,
            commands::generate_key,
            commands::import_key,
            commands::import_key_file,
            commands::export_key,
            commands::export_key_to_file,
            commands::delete_key,
            commands::encrypt_file,
            commands::decrypt_file,
            commands::encrypt_text,
            commands::decrypt_text,
            commands::key_detail,
            commands::set_ownertrust,
            commands::trust_graph,
            commands::certify_key,
            commands::lookup_wkd,
            commands::lookup_keyserver,
            commands::upload_key,
            commands::refresh_keys,
            commands::qr_code,
            commands::qr_png,
            commands::save_qr,
            commands::import_from_uri,
            commands::list_teams,
            commands::save_team,
            commands::delete_team,
        ])
        .run(tauri::generate_context!())
        .expect("error while running AegisGPG");
}
