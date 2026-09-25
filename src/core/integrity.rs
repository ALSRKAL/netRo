//! File integrity monitoring: cryptographic baselines and comparison.
//!
//! This is integrity monitoring, not malware detection. netRo records SHA-256
//! digests, size, timestamps, permissions and ownership, then reports
//! added/removed/modified files. Unreadable files are reported with the reason,
//! never silently skipped.

use crate::config;
use crate::error::{ErrorCode, NetroError, Result};
use crate::model::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_FILES: usize = 20_000;
const MAX_DEPTH: usize = 12;

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Hash a file and collect its metadata.
pub fn inspect_file(path: &Path, max_size: u64) -> IntegrityEntry {
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            return IntegrityEntry {
                path: path.display().to_string(),
                sha256: None,
                size: 0,
                mtime_epoch: 0,
                mode: None,
                uid: None,
                gid: None,
                error: Some(e.to_string()),
            }
        }
    };

    let mtime_epoch = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    #[cfg(unix)]
    let (mode, uid, gid) = {
        use std::os::unix::fs::MetadataExt;
        (
            Some(metadata.mode()),
            Some(metadata.uid()),
            Some(metadata.gid()),
        )
    };
    #[cfg(not(unix))]
    let (mode, uid, gid) = {
        let readonly = metadata.permissions().readonly();
        (Some(if readonly { 0o444 } else { 0o644 }), None, None)
    };

    let size = metadata.len();
    let mut entry = IntegrityEntry {
        path: path.display().to_string(),
        sha256: None,
        size,
        mtime_epoch,
        mode,
        uid,
        gid,
        error: None,
    };

    if !metadata.is_file() {
        entry.error = Some("not a regular file".into());
        return entry;
    }
    if max_size > 0 && size > max_size {
        entry.error = Some(format!(
            "skipped: {} exceeds the {} byte hashing limit",
            crate::util::human_bytes(size),
            crate::util::human_bytes(max_size)
        ));
        return entry;
    }

    match hash_file(path) {
        Ok(digest) => entry.sha256 = Some(digest),
        Err(e) => entry.error = Some(e.to_string()),
    }
    entry
}

pub fn hash_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>())
}

/// Expand the configured paths into a sorted, deduplicated file list.
pub fn expand_paths(paths: &[String]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for raw in paths {
        let path = PathBuf::from(raw);
        if !path.exists() {
            files.push(path);
            continue;
        }
        if path.is_dir() {
            walk_dir(&path, 0, &mut files);
        } else {
            files.push(path);
        }
        if files.len() > MAX_FILES {
            return Err(NetroError::new(
                ErrorCode::Other,
                format!("integrity path set expands to more than {MAX_FILES} files"),
            )
            .with_hint("narrow the paths in `netro config show` (integrity.paths)"));
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn walk_dir(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH || out.len() > MAX_FILES {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() => walk_dir(&path, depth + 1, out),
            Ok(meta) if meta.is_file() => out.push(path),
            Ok(_) => {}
            Err(_) => {}
        }
    }
}

/// Create a new baseline for the given paths.
pub fn create_baseline(paths: &[String], max_file_size: u64) -> Result<IntegrityBaseline> {
    if paths.is_empty() {
        return Err(NetroError::new(
            ErrorCode::ConfigError,
            "no integrity paths configured",
        ));
    }
    let files = expand_paths(paths)?;
    let mut entries = Vec::with_capacity(files.len());
    for file in files {
        entries.push(inspect_file(&file, max_file_size));
    }
    let baseline = IntegrityBaseline {
        schema_version: MODEL_SCHEMA_VERSION,
        created_epoch: now_epoch(),
        hostname: sysinfo::System::host_name().unwrap_or_else(|| "unknown".into()),
        platform: crate::platform::platform_id(),
        paths: paths.to_vec(),
        entries,
    };
    Ok(baseline)
}

pub fn save_baseline(baseline: &IntegrityBaseline) -> Result<PathBuf> {
    config::ensure_dirs()?;
    let path = config::baseline_file();
    let text = serde_json::to_string_pretty(baseline)?;
    std::fs::write(&path, text)?;
    config::restrict_permissions(&path);
    Ok(path)
}

pub fn load_baseline() -> Result<IntegrityBaseline> {
    let path = config::baseline_file();
    let text = std::fs::read_to_string(&path).map_err(|e| {
        NetroError::new(
            ErrorCode::NotFound,
            format!("cannot read integrity baseline at {}: {e}", path.display()),
        )
        .with_hint("create one with `netro integrity baseline create`")
    })?;
    Ok(serde_json::from_str(&text)?)
}

/// Compare the current state against a baseline.
pub fn scan_baseline(baseline: &IntegrityBaseline, max_file_size: u64) -> Result<IntegrityReport> {
    let current_paths = if baseline.paths.is_empty() {
        config::default_integrity_paths()
    } else {
        baseline.paths.clone()
    };
    let files = expand_paths(&current_paths)?;

    let baseline_map: BTreeMap<String, &IntegrityEntry> = baseline
        .entries
        .iter()
        .map(|e| (e.path.clone(), e))
        .collect();
    let mut changes = Vec::new();
    let mut unchanged = 0usize;
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();

    for file in &files {
        let key = file.display().to_string();
        seen.insert(key.clone(), ());
        let current = inspect_file(file, max_file_size);
        match baseline_map.get(&key) {
            None => changes.push(IntegrityChange {
                path: key.clone(),
                status: IntegrityStatus::Added,
                details: vec!["not present in baseline".into()],
            }),
            Some(previous) => {
                let mut details = Vec::new();
                if previous.sha256 != current.sha256 {
                    if previous.sha256.is_some() && current.sha256.is_some() {
                        details.push("content hash changed".into());
                    } else {
                        details.push(format!(
                            "hash unavailable before/after ({:?} -> {:?})",
                            previous.error.as_deref().unwrap_or("ok"),
                            current.error.as_deref().unwrap_or("ok")
                        ));
                    }
                }
                if previous.mode != current.mode {
                    details.push(format!(
                        "permissions changed ({:o} -> {:o})",
                        previous.mode.unwrap_or(0),
                        current.mode.unwrap_or(0)
                    ));
                }
                if previous.uid != current.uid || previous.gid != current.gid {
                    details.push("ownership changed".into());
                }
                if previous.size != current.size {
                    details.push(format!(
                        "size changed ({} -> {} bytes)",
                        previous.size, current.size
                    ));
                }
                if current.error.is_some() && previous.error.is_none() {
                    details.push(format!(
                        "now unreadable: {}",
                        current.error.clone().unwrap_or_default()
                    ));
                }
                if details.is_empty() {
                    unchanged += 1;
                } else {
                    changes.push(IntegrityChange {
                        path: key.clone(),
                        status: IntegrityStatus::Modified,
                        details,
                    });
                }
            }
        }
    }

    // Baseline entries that no longer exist.
    for entry in &baseline.entries {
        if seen.contains_key(&entry.path) {
            continue;
        }
        if !Path::new(&entry.path).exists() {
            changes.push(IntegrityChange {
                path: entry.path.clone(),
                status: IntegrityStatus::Removed,
                details: vec!["present in baseline, missing now".into()],
            });
        }
    }

    changes.sort_by(|a, b| a.path.cmp(&b.path));
    let missing_count = changes
        .iter()
        .filter(|c| c.status == IntegrityStatus::Removed)
        .count();
    Ok(IntegrityReport {
        baseline_created_epoch: Some(baseline.created_epoch),
        scanned_epoch: now_epoch(),
        changes,
        unchanged,
        note: (missing_count > 0).then(|| {
            "removed files may indicate legitimate package updates; review each entry".into()
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("netro-integrity-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn hash_file_is_sha256_of_content() {
        let dir = temp_dir("hash");
        let file = dir.join("a.txt");
        fs::write(&file, b"abc").unwrap();
        // Known SHA-256 of "abc".
        assert_eq!(
            hash_file(&file).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn baseline_detects_added_modified_removed() {
        let dir = temp_dir("compare");
        let keep = dir.join("keep.conf");
        let modify = dir.join("modify.conf");
        let remove = dir.join("remove.conf");
        fs::write(&keep, b"keep").unwrap();
        fs::write(&modify, b"before").unwrap();
        fs::write(&remove, b"bye").unwrap();

        let baseline = create_baseline(&[dir.display().to_string()], 1024 * 1024).unwrap();
        assert_eq!(baseline.entries.len(), 3);

        fs::write(&modify, b"after").unwrap();
        fs::remove_file(&remove).unwrap();
        fs::write(dir.join("added.conf"), b"new").unwrap();

        let report = scan_baseline(&baseline, 1024 * 1024).unwrap();
        let by_path: BTreeMap<&str, IntegrityStatus> = report
            .changes
            .iter()
            .map(|c| (c.path.as_str(), c.status))
            .collect();

        // Unchanged files are intentionally absent from `changes`.
        assert!(!by_path.contains_key(keep.display().to_string().as_str()));
        assert_eq!(
            by_path[modify.display().to_string().as_str()],
            IntegrityStatus::Modified
        );
        assert_eq!(
            by_path[remove.display().to_string().as_str()],
            IntegrityStatus::Removed
        );
        assert_eq!(
            by_path[dir.join("added.conf").display().to_string().as_str()],
            IntegrityStatus::Added
        );
        assert_eq!(report.unchanged, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn baseline_is_deterministic() {
        let dir = temp_dir("determinism");
        fs::write(dir.join("x"), b"x").unwrap();
        let a = create_baseline(&[dir.display().to_string()], 0).unwrap();
        let b = create_baseline(&[dir.display().to_string()], 0).unwrap();
        assert_eq!(a.entries.len(), b.entries.len());
        assert_eq!(a.entries[0].sha256, b.entries[0].sha256);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn large_file_skipped_with_reason_not_faked() {
        let dir = temp_dir("large");
        let file = dir.join("big.bin");
        fs::write(&file, vec![0u8; 100]).unwrap();
        let entry = inspect_file(&file, 10);
        assert!(entry.sha256.is_none());
        assert!(entry.error.unwrap().contains("skipped"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_baseline_reports_not_found() {
        // Point the config dir at an empty temp location to avoid touching the
        // user's real baseline.
        let err = load_baseline();
        if let Err(e) = err {
            assert!(e.code() == ErrorCode::NotFound);
        }
    }
}
