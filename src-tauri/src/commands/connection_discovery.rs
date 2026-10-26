//! Read saved connection files only from known application configuration roots.
use base64::Engine;
use serde::Serialize;
use std::path::{Path, PathBuf};
use tauri::Manager;

#[path = "navicat_wine.rs"]
mod navicat_wine;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredConnectionSource {
    source: String,
    label: String,
    path: String,
    content: String,
}

fn read_text(path: &Path) -> Option<String> {
    String::from_utf8(read_bytes(path)?).ok()
}

fn read_bytes(path: &Path) -> Option<Vec<u8>> {
    // Bound memory use and skip directories, links, and unexpectedly large files.
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > 8 * 1024 * 1024 {
        return None;
    }
    std::fs::read(path).ok()
}

fn collect(root: &Path, depth: usize, output: &mut Vec<DiscoveredConnectionSource>, remaining: &mut usize) {
    if *remaining == 0
        || output.len() >= 100
        || std::fs::symlink_metadata(root).map_or(true, |m| m.file_type().is_symlink())
    {
        return;
    }
    *remaining -= 1;
    let Ok(entries) = std::fs::read_dir(root) else { return };
    let mut entries: Vec<_> = entries.flatten().take(500).collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if output.len() >= 100 {
            break;
        }
        let path = entry.path();
        let Ok(kind) = entry.file_type() else { continue };
        if kind.is_dir() && depth > 0 {
            collect(&path, depth - 1, output, remaining);
        } else if kind.is_file() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let (source, label, content) = match name.as_ref() {
                "data-sources.json" => {
                    let Some(data) = read_text(&path) else { continue };
                    let credentials = read_bytes(&root.join("credentials-config.json"))
                        .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
                        .unwrap_or_default();
                    (
                        "dbeaver",
                        "DBeaver",
                        serde_json::json!({"format": "dbeaver-import", "dataSources": data, "credentialsBase64": credentials}).to_string(),
                    )
                }
                "dataSources.xml" => {
                    let Some(data) = read_text(&path) else { continue };
                    (
                        "datagrip",
                        "DataGrip",
                        serde_json::json!({
                            "format": "datagrip-import", "dataSources": data,
                            "dataSourcesLocal": read_text(&root.join("dataSources.local.xml")).unwrap_or_default(),
                            "dbForestConfig": read_text(&root.join("db-forest-config.xml")).unwrap_or_default()
                        })
                        .to_string(),
                    )
                }
                "connections.json" => {
                    let Some(data) = read_text(&path) else { continue };
                    (
                        "rdm",
                        "Redis Desktop Manager",
                        serde_json::json!({"format": "rdm-import", "content": data}).to_string(),
                    )
                }
                _ => continue,
            };
            if !output.iter().any(|item| item.path == path.to_string_lossy()) {
                output.push(DiscoveredConnectionSource {
                    source: source.into(),
                    label: label.into(),
                    path: path.to_string_lossy().into_owned(),
                    content,
                });
            }
        }
    }
}

fn discover(home: &Path, config: &Path, data: &Path) -> Vec<DiscoveredConnectionSource> {
    let mut output = Vec::new();
    let roots: Vec<(PathBuf, usize)> = vec![
        (data.join("DBeaverData"), 6),
        (home.join(".local/share/DBeaverData"), 6),
        (home.join("Library/DBeaverData"), 6),
        (home.join(".dbeaver4"), 4),
        (home.join("snap/dbeaver-ce/current/.local/share/DBeaverData"), 6),
        (home.join(".var/app/io.dbeaver.DBeaverCommunity/data/DBeaverData"), 6),
        (config.join("JetBrains"), 4),
        (home.join("Library/Application Support/JetBrains"), 4),
        (home.join("DataGripProjects"), 5),
        (home.join(".rdm"), 1),
        (config.join("rdm"), 1),
        (config.join("RedisDesktopManager"), 2),
    ];
    let mut remaining = 2000;
    for (root, depth) in roots {
        collect(&root, depth, &mut output, &mut remaining);
    }
    // Native Linux store documented by Navicat; also find NCX files saved
    // inside its configuration folders. These are distinct from RDM JSON.
    for root in [config.join("navicat"), home.join(".config/navicat"), home.join(".navicat"), home.join(".navicat64")] {
        collect_navicat(&root, 5, &mut output, &mut remaining);
    }
    collect_navicat_wine(home, data, &mut output);
    output
}

fn collect_navicat_wine(home: &Path, data: &Path, output: &mut Vec<DiscoveredConnectionSource>) {
    let mut prefixes = vec![home.join(".wine")];
    if let Some(prefix) = std::env::var_os("WINEPREFIX") {
        prefixes.push(PathBuf::from(prefix));
    }
    if let Ok(entries) = std::fs::read_dir(home) {
        prefixes.extend(
            entries
                .flatten()
                .take(1000)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with(".wine"))
                .map(|entry| entry.path()),
        );
    }
    for root in [
        data.join("bottles/bottles"),
        home.join(".local/share/bottles/bottles"),
        home.join(".var/app/com.usebottles.bottles/data/bottles/bottles"),
        home.join(".PlayOnLinux/wineprefix"),
    ] {
        if let Ok(entries) = std::fs::read_dir(root) {
            prefixes.extend(entries.flatten().take(100).map(|entry| entry.path()));
        }
    }
    let mut seen = std::collections::HashSet::new();
    for prefix in prefixes {
        if output.len() >= 100 {
            break;
        }
        let Ok(path) = std::fs::canonicalize(prefix.join("user.reg")) else { continue };
        if !seen.insert(path.clone()) {
            continue;
        }
        let Some(registry) = read_text(&path) else { continue };
        let connections = navicat_wine::parse(&registry);
        if !connections.is_empty() {
            output.push(DiscoveredConnectionSource {
                source: "navicat".into(),
                label: "Navicat (Wine)".into(),
                path: path.to_string_lossy().into_owned(),
                content: serde_json::json!({"format": "navicat-wine-import", "connections": connections}).to_string(),
            });
        }
    }
}

fn collect_navicat(root: &Path, depth: usize, output: &mut Vec<DiscoveredConnectionSource>, remaining: &mut usize) {
    if *remaining == 0
        || output.len() >= 100
        || std::fs::symlink_metadata(root).map_or(true, |m| m.file_type().is_symlink())
    {
        return;
    }
    *remaining -= 1;
    let Ok(entries) = std::fs::read_dir(root) else { return };
    let mut entries: Vec<_> = entries.flatten().take(500).collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if output.len() >= 100 {
            break;
        }
        let path = entry.path();
        let Ok(kind) = entry.file_type() else { continue };
        if kind.is_dir() && depth > 0 {
            collect_navicat(&path, depth - 1, output, remaining);
        } else if kind.is_file()
            && (entry.file_name() == "connections.json"
                || path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("ncx")))
        {
            let Some(content) = read_text(&path) else { continue };
            if !output.iter().any(|item| item.path == path.to_string_lossy()) {
                output.push(DiscoveredConnectionSource {
                    source: "navicat".into(),
                    label: "Navicat".into(),
                    path: path.to_string_lossy().into_owned(),
                    content,
                });
            }
        }
    }
}

#[tauri::command]
pub async fn discover_connection_sources(app: tauri::AppHandle) -> Result<Vec<DiscoveredConnectionSource>, String> {
    let home = app.path().home_dir().map_err(|e| e.to_string())?;
    let config = app.path().config_dir().map_err(|e| e.to_string())?;
    let data = app.path().data_dir().map_err(|e| e.to_string())?;
    tauri::async_runtime::spawn_blocking(move || discover(&home, &config, &data)).await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_known_sources_and_companion_files_without_duplicates() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        let dbeaver = home.join(".local/share/DBeaverData/workspace6/General/.dbeaver");
        let datagrip = home.join("config/JetBrains/DataGrip2026/options");
        std::fs::create_dir_all(&dbeaver).unwrap();
        std::fs::create_dir_all(&datagrip).unwrap();
        std::fs::write(dbeaver.join("data-sources.json"), "{\"connections\":{}}").unwrap();
        std::fs::write(dbeaver.join("credentials-config.json"), [1, 2, 3]).unwrap();
        std::fs::write(datagrip.join("dataSources.xml"), "<project/>").unwrap();
        std::fs::write(datagrip.join("dataSources.local.xml"), "<local/>").unwrap();
        let sources = discover(home, &home.join("config"), &home.join(".local/share"));
        assert_eq!(sources.len(), 2);
        let grip = sources.iter().find(|s| s.source == "datagrip").unwrap();
        let payload: serde_json::Value = serde_json::from_str(&grip.content).unwrap();
        assert_eq!(payload["dataSourcesLocal"], "<local/>");
        let beaver = sources.iter().find(|s| s.source == "dbeaver").unwrap();
        let payload: serde_json::Value = serde_json::from_str(&beaver.content).unwrap();
        assert_eq!(payload["credentialsBase64"], "AQID");
    }

    #[test]
    fn missing_roots_are_empty() {
        let temp = tempfile::tempdir().unwrap();
        assert!(discover(temp.path(), temp.path(), temp.path()).is_empty());
    }

    #[test]
    fn navicat_json_is_discovered_once_and_never_classified_as_redis() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join(".config/navicat/Common");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("connections.json"), "{\"connections\":[]}").unwrap();
        std::fs::write(directory.join("export.ncx"), "<Connections/>").unwrap();
        let sources = discover(temp.path(), &temp.path().join(".config"), &temp.path().join(".local/share"));
        assert_eq!(sources.len(), 2);
        assert!(sources.iter().all(|source| source.source == "navicat"));
    }

    #[test]
    fn wine_registry_connections_are_discovered_without_unrelated_registry_values() {
        let temp = tempfile::tempdir().unwrap();
        let prefix = temp.path().join(".wine");
        std::fs::create_dir_all(&prefix).unwrap();
        std::fs::write(
            prefix.join("user.reg"),
            r#"[Software\\PremiumSoft\\Navicat\\Servers\\Demo] 1
"Host"="mysql.example"
"Port"=dword:00000cea
"Pwd_2"="private-blob"
"#,
        )
        .unwrap();
        let sources = discover(temp.path(), temp.path(), temp.path());
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].label, "Navicat (Wine)");
        assert!(!sources[0].content.contains("private-blob"));
        let payload: serde_json::Value = serde_json::from_str(&sources[0].content).unwrap();
        assert_eq!(payload["connections"][0]["Name"], "Demo");
    }
}
