//! GPU detection on Linux.
//!
//! Sources, in order of preference:
//! 1. `nvidia-smi` (NVIDIA: utilization, VRAM, temperature, power, driver).
//! 2. `rocm-smi --json` (AMD ROCm: VRAM, utilization, temperature, power).
//! 3. sysfs `/sys/class/drm` (vendor/model/VRAM where the driver exports it).
//!
//! Metrics that a driver does not expose are reported as absent, never
//! invented. Intel iGPUs generally expose no utilization through sysfs; that is
//! reported in the `note` field.

use crate::model::GpuInfo;
use crate::util::{self, which};
use std::path::Path;
use std::time::Duration;

const CMD_TIMEOUT: Duration = Duration::from_secs(10);

pub fn gpus() -> Vec<GpuInfo> {
    let mut out = Vec::new();
    if let Some(nvidia) = nvidia_gpus() {
        out.extend(nvidia);
    }
    if let Some(amd) = rocm_gpus() {
        out.extend(amd);
    }
    if out.is_empty() {
        out.extend(sysfs_gpus());
    } else {
        // Vendor tools already reported their GPUs; add sysfs entries only for
        // vendors that are not represented, so a machine with an NVIDIA dGPU
        // and an Intel iGPU lists each device exactly once.
        let covered_vendors: Vec<String> = out
            .iter()
            .filter_map(|g| g.vendor.clone())
            .map(|v| v.to_lowercase())
            .collect();
        for gpu in sysfs_gpus() {
            let vendor = gpu.vendor.clone().unwrap_or_default().to_lowercase();
            if !covered_vendors
                .iter()
                .any(|v| !v.is_empty() && *v == vendor)
            {
                out.push(gpu);
            }
        }
    }
    out
}

fn nvidia_gpus() -> Option<Vec<GpuInfo>> {
    let path = which("nvidia-smi")?;
    let args = [
        "--query-gpu=name,memory.total,utilization.gpu,temperature.gpu,power.draw,driver_version",
        "--format=csv,noheader,nounits",
    ];
    let out = util::run_command(&path.to_string_lossy(), &args, CMD_TIMEOUT).ok()?;
    if !out.success() {
        return None;
    }
    let mut gpus = Vec::new();
    for line in out.stdout.lines() {
        let cols: Vec<&str> = line.split(',').map(|c| c.trim()).collect();
        if cols.len() < 6 {
            continue;
        }
        let parse_num = |s: &str| -> Option<f64> { s.parse::<f64>().ok().filter(|v| *v >= 0.0) };
        gpus.push(GpuInfo {
            vendor: Some("NVIDIA".into()),
            model: Some(cols[0].to_string()),
            vram_bytes: parse_num(cols[1]).map(|mb| (mb * 1024.0 * 1024.0) as u64),
            driver: Some(cols[5].to_string()),
            utilization_percent: parse_num(cols[2]).map(|v| v as f32),
            temperature_c: parse_num(cols[3]).map(|v| v as f32),
            power_watts: parse_num(cols[4]).map(|v| v as f32),
            compute_backend: Some("CUDA".into()),
            source: "nvidia-smi".into(),
            note: None,
        });
    }
    if gpus.is_empty() {
        None
    } else {
        Some(gpus)
    }
}

fn rocm_gpus() -> Option<Vec<GpuInfo>> {
    let path = which("rocm-smi")?;
    let args = [
        "--showproductname",
        "--showmeminfo",
        "vram",
        "--showuse",
        "--showtemp",
        "--showpower",
        "--json",
    ];
    let out = util::run_command(&path.to_string_lossy(), &args, CMD_TIMEOUT).ok()?;
    if !out.success() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(out.stdout.trim()).ok()?;
    let obj = value.as_object()?;
    let mut gpus = Vec::new();
    for (card, info) in obj {
        if !card.starts_with("card") {
            continue;
        }
        let info = match info.as_object() {
            Some(o) => o,
            None => continue,
        };
        let get = |key: &str| -> Option<String> {
            info.iter()
                .find(|(k, _)| k.to_ascii_lowercase().contains(key))
                .and_then(|(_, v)| v.as_str().map(|s| s.to_string()))
        };
        let num = |key: &str| -> Option<f64> {
            get(key).and_then(|s| s.trim().trim_end_matches('%').trim().parse::<f64>().ok())
        };
        gpus.push(GpuInfo {
            vendor: Some("AMD".into()),
            model: get("card series")
                .or_else(|| get("product name"))
                .or_else(|| get("card model")),
            vram_bytes: num("vram total").map(|mb| (mb * 1024.0 * 1024.0) as u64),
            driver: get("driver version"),
            utilization_percent: num("gpu use").or_else(|| num("use")).map(|v| v as f32),
            temperature_c: num("temperature").map(|v| v as f32),
            power_watts: num("average power")
                .or_else(|| num("power"))
                .map(|v| v as f32),
            compute_backend: Some("ROCm".into()),
            source: "rocm-smi".into(),
            note: None,
        });
    }
    if gpus.is_empty() {
        None
    } else {
        Some(gpus)
    }
}

fn sysfs_gpus() -> Vec<GpuInfo> {
    let mut out = Vec::new();
    let drm = Path::new("/sys/class/drm");
    let entries = match std::fs::read_dir(drm) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_card_entry(&name) {
            continue;
        }
        let device = entry.path().join("device");
        if !device.exists() {
            continue;
        }
        let vendor_id = read_trim(&device.join("vendor")).unwrap_or_default();
        let device_id = read_trim(&device.join("device")).unwrap_or_default();
        let vendor = match vendor_id.as_str() {
            "0x10de" => Some("NVIDIA".to_string()),
            "0x1002" | "0x1022" => Some("AMD".to_string()),
            "0x8086" => Some("Intel".to_string()),
            "0x1af4" => Some("Red Hat (virtio)".to_string()),
            _ => None,
        };
        let driver = std::fs::read_link(device.join("driver"))
            .ok()
            .and_then(|p| p.file_name().map(|f| f.to_string_lossy().to_string()));
        let vram = read_trim(&device.join("mem_info_vram_total"))
            .and_then(|s| s.parse::<u64>().ok())
            .or_else(|| {
                read_trim(&device.join("mem_info_vram_used")).and_then(|s| s.parse::<u64>().ok())
            });
        let pci_id = if device_id.is_empty() {
            None
        } else {
            Some(format!("{vendor_id}:{device_id}"))
        };
        out.push(GpuInfo {
            vendor,
            model: model_name_for(&vendor_id, &device_id).or(pci_id),
            vram_bytes: vram,
            driver,
            utilization_percent: None,
            temperature_c: None,
            power_watts: None,
            compute_backend: None,
            source: "sysfs /sys/class/drm".into(),
            note: Some(
                "vendor driver does not expose live utilization via sysfs; install nvidia-smi or rocm-smi for live metrics"
                    .into(),
            ),
        });
    }
    out
}

fn is_card_entry(name: &str) -> bool {
    // card0, card1, ... but not card0-DP-1 connectors
    name.starts_with("card") && !name.contains('-')
}

fn read_trim(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Resolve a PCI vendor/device pair to a name via `lspci` when available.
fn model_name_for(vendor_id: &str, device_id: &str) -> Option<String> {
    let lspci = which("lspci")?;
    let out = util::run_command(
        &lspci.to_string_lossy(),
        &["-nn", "-mm"],
        Duration::from_secs(5),
    )
    .ok()?;
    let needle = format!(
        "{}:{}",
        vendor_id.trim_start_matches("0x"),
        device_id.trim_start_matches("0x")
    )
    .to_lowercase();
    for line in out.stdout.lines() {
        if line.to_lowercase().contains(&needle) {
            let quoted: Vec<&str> = line.split('"').collect();
            // lspci -mm output: slot "class" "vendor" "device" ...
            if quoted.len() >= 6 {
                return Some(format!("{} {}", quoted[3], quoted[5]));
            }
            return Some(line.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_entry_filter() {
        assert!(is_card_entry("card0"));
        assert!(is_card_entry("card12"));
        assert!(!is_card_entry("card0-DP-1"));
        assert!(!is_card_entry("renderD128"));
    }

    #[test]
    fn gpu_detection_never_panics() {
        // Must return real data or nothing; must not fabricate entries.
        let gpus = gpus();
        for gpu in &gpus {
            assert!(!gpu.source.is_empty());
        }
    }
}
