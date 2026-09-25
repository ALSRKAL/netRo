//! MAC OUI (vendor) lookup.
//!
//! A bundled table covers common vendors; unknown prefixes stay `None` rather
//! than being guessed. A full IEEE OUI database can be supplied via
//! `integrations.oui_file` in the config (either IEEE `oui.txt` or a CSV with
//! `prefix,vendor`).

use std::collections::HashMap;
use std::path::Path;

/// Bundled OUI prefixes (first three bytes).
const BUNDLED: &[(&str, &str)] = &[
    ("000C29", "VMware"),
    ("000569", "VMware"),
    ("001C14", "VMware"),
    ("005056", "VMware"),
    ("080027", "VirtualBox"),
    ("0A0027", "VirtualBox"),
    ("525400", "QEMU/KVM"),
    ("00163E", "Xen"),
    ("020054", "Xen"),
    ("00155D", "Microsoft Hyper-V"),
    ("000D3A", "Microsoft"),
    ("0017FA", "Microsoft"),
    ("001DD8", "Microsoft"),
    ("281878", "Microsoft"),
    ("3C8375", "Microsoft"),
    ("7C1E52", "Microsoft"),
    ("C83F26", "Microsoft"),
    ("DCB4C4", "Microsoft"),
    ("F01DBC", "Microsoft"),
    ("0050F2", "Microsoft"),
    ("001B63", "Apple"),
    ("002332", "Apple"),
    ("00236C", "Apple"),
    ("002500", "Apple"),
    ("0026BB", "Apple"),
    ("003EE1", "Apple"),
    ("0050E4", "Apple"),
    ("04F13E", "Apple"),
    ("0C4DE9", "Apple"),
    ("1093E9", "Apple"),
    ("18AF61", "Apple"),
    ("28CFE9", "Apple"),
    ("3451C9", "Apple"),
    ("3C0754", "Apple"),
    ("40D32D", "Apple"),
    ("48437C", "Apple"),
    ("5C95AE", "Apple"),
    ("64B9E8", "Apple"),
    ("6C709F", "Apple"),
    ("78CA39", "Apple"),
    ("7CD1C3", "Apple"),
    ("8863DF", "Apple"),
    ("8C8590", "Apple"),
    ("9801A7", "Apple"),
    ("A45E60", "Apple"),
    ("AC87A3", "Apple"),
    ("B065BD", "Apple"),
    ("D02598", "Apple"),
    ("D89E3F", "Apple"),
    ("DC2B2A", "Apple"),
    ("E0B9BA", "Apple"),
    ("F0DBF8", "Apple"),
    ("F4F15A", "Apple"),
    ("001AA0", "Dell"),
    ("002219", "Dell"),
    ("0024E8", "Dell"),
    ("14B31F", "Dell"),
    ("1866DA", "Dell"),
    ("18DBF2", "Dell"),
    ("3417EB", "Dell"),
    ("44A842", "Dell"),
    ("509A4C", "Dell"),
    ("5CF9DD", "Dell"),
    ("782BCB", "Dell"),
    ("847BEB", "Dell"),
    ("B083FE", "Dell"),
    ("BC305B", "Dell"),
    ("D4AE52", "Dell"),
    ("F04DA2", "Dell"),
    ("F8BC12", "Dell"),
    ("F8B156", "Dell"),
    ("001B21", "Intel"),
    ("001E67", "Intel"),
    ("0021 6A", "Intel"),
    ("0024D7", "Intel"),
    ("34E6D7", "Intel"),
    ("3C9509", "Intel"),
    ("44 85 00", "Intel"),
    ("4C3488", "Intel"),
    ("5C5F67", "Intel"),
    ("7CB27D", "Intel"),
    ("8086F2", "Intel"),
    ("94C691", "Intel"),
    ("A0369F", "Intel"),
    ("A4BF01", "Intel"),
    ("B49691", "Intel"),
    ("D8FC93", "Intel"),
    ("E4A471", "Intel"),
    ("F8633F", "Intel"),
    ("001A2B", "Ayecom"),
    ("001CB3", "Apple"),
    ("001E58", "D-Link"),
    ("001F5B", "Apple"),
    ("0021CC", "Flextronics"),
    ("0022B0", "D-Link"),
    ("002454", "Samsung"),
    ("0025D3", "AzureWave"),
    ("0026F2", "Netgear"),
    ("002722", "Ubiquiti"),
    ("002A6A", "Cisco"),
    ("003048", "Cisco"),
    ("00408C", "Axis"),
    ("0050C2", "IEEE Registration Authority"),
    ("0050E8", "Nomadix"),
    ("0050FC", "Edimax"),
    ("0060B0", "HP"),
    ("006440", "Cisco"),
    ("0090A9", "Western Digital"),
    ("00A0C9", "Intel"),
    ("00C0B7", "American Power Conversion"),
    ("00D0B7", "Intel"),
    ("00E04C", "Realtek"),
    ("00E0FC", "Huawei"),
    ("00E18C", "Intel"),
    ("00FEC8", "Cisco"),
    ("0418D6", "Ubiquiti"),
    ("04A151", "Netgear"),
    ("04BF6D", "Cisco"),
    ("04D4C4", "Asus"),
    ("04E676", "Amazon"),
    ("08 00 27", "VirtualBox"),
    ("080086", "Xerox"),
    ("081196", "Intel"),
    ("08606E", "Asus"),
    ("0C47C9", "Amazon"),
    ("0CBF74", "Sagemcom"),
    ("105172", "Huawei"),
    ("107B44", "Asus"),
    ("10C61F", "Huawei"),
    ("10DA43", "Netgear"),
    ("145AFC", "Liteon"),
    ("14CC20", "TP-Link"),
    ("1840A4", "Shenzhen"),
    ("1C1B0D", "GIGA-BYTE"),
    ("1C5F2B", "D-Link"),
    ("1C7EE5", "D-Link"),
    ("1CBFCE", "Shenzhen"),
    ("200BC7", "Huawei"),
    ("20E52A", "Netgear"),
    ("24050F", "MTN"),
    ("244BFE", "Asus"),
    ("246968", "TP-Link"),
    ("28C68E", "Netgear"),
    ("2C56DC", "Asus"),
    ("2CAB00", "Huawei"),
    ("2CB05D", "Netgear"),
    ("30469A", "Netgear"),
    ("30B5C2", "TP-Link"),
    ("340804", "D-Link"),
    ("34CE00", "Xiaomi"),
    ("3822E2", "HP"),
    ("3C46D8", "TP-Link"),
    ("40167E", "Asus"),
    ("404D8E", "Huawei"),
    ("405D82", "Netgear"),
    ("40B034", "Huawei"),
    ("4494FC", "Netgear"),
    ("44D9E7", "Ubiquiti"),
    ("44FE3B", "Arcadyan"),
    ("485B39", "Asus"),
    ("48EE0C", "D-Link"),
    ("4C60DE", "Netgear"),
    ("4CE676", "Cisco"),
    ("503EAA", "TP-Link"),
    ("504A6E", "Netgear"),
    ("50C7BF", "TP-Link"),
    ("54A703", "TP-Link"),
    ("54C80F", "TP-Link"),
    ("588A5A", "D-Link"),
    ("5C0272", "Huawei"),
    ("5C5015", "Cisco"),
    ("5CD998", "D-Link"),
    ("60A4D0", "Samsung"),
    ("60E327", "TP-Link"),
    ("641666", "Netgear"),
    ("6466B3", "Netgear"),
    ("68 1D EF", "Shenzhen"),
    ("68FF7B", "TP-Link"),
    ("6C5AB0", "TCL"),
    ("6CB0CE", "Netgear"),
    ("704F57", "TP-Link"),
    ("744401", "Netgear"),
    ("74DADA", "Netgear"),
    ("74EA3A", "TP-Link"),
    ("78D294", "Netgear"),
    ("7C8BCA", "TP-Link"),
    ("84 16 F9", "TP-Link"),
    ("84C9B2", "D-Link"),
    ("887F03", "Asus"),
    ("889FFA", "Asus"),
    ("8C3BAD", "Netgear"),
    ("9008D3", "TP-Link"),
    ("90F652", "TP-Link"),
    ("940C6D", "TP-Link"),
    ("94A7B7", "Netgear"),
    ("98DA C4", "TP-Link"),
    ("9C3DCF", "Netgear"),
    ("A0 40 A0", "Netgear"),
    ("A020A6", "Espressif"),
    ("A42B8C", "Netgear"),
    ("A47733", "Netgear"),
    ("A8154D", "TP-Link"),
    ("A84041", "Dragino"),
    ("AC84C6", "TP-Link"),
    ("AC9E17", "Asus"),
    ("B03956", "Netgear"),
    ("B0487A", "TP-Link"),
    ("B0BE76", "TP-Link"),
    ("B0C554", "D-Link"),
    ("B44BD2", "Apple"),
    ("B4B024", "TP-Link"),
    ("B8A386", "D-Link"),
    ("BC 14 85", "Huawei"),
    ("BCA511", "Netgear"),
    ("C025E9", "TP-Link"),
    ("C03F0E", "Netgear"),
    ("C0A5DD", "Shenzhen"),
    ("C46E1F", "TP-Link"),
    ("C4E984", "TP-Link"),
    ("C80E14", "Asus"),
    ("CC32E5", "TP-Link"),
    ("CCB255", "D-Link"),
    ("D017C2", "Asus"),
    ("D03745", "TP-Link"),
    ("D42122", "Sercomm"),
    ("D46E5C", "Huawei"),
    ("D80D17", "TP-Link"),
    ("D8B12A", "TP-Link"),
    ("DC9FDB", "Ubiquiti"),
    ("E0C88D", "Shenzhen"),
    ("E46F13", "D-Link"),
    ("E4C146", "Shenzhen"),
    ("E894F6", "TP-Link"),
    ("E8DE27", "TP-Link"),
    ("EC086B", "TP-Link"),
    ("EC2280", "D-Link"),
    ("ECD68A", "Shenzhen"),
    ("F0 9F C2", "Ubiquiti"),
    ("F077B0", "D-Link"),
    ("F4EC38", "TP-Link"),
    ("F81A67", "TP-Link"),
    ("F8D111", "TP-Link"),
    ("FCD733", "TP-Link"),
];

/// Normalize a MAC or bare OUI prefix to a 6-hex-digit uppercase prefix.
fn normalize_mac(mac: &str) -> Option<String> {
    let cleaned: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    match cleaned.len() {
        6 => Some(cleaned),
        12 => Some(format!(
            "{}{}{}",
            &cleaned[0..2],
            &cleaned[2..4],
            &cleaned[4..6]
        )),
        _ => None,
    }
}

/// Bundled vendor lookup.
pub fn vendor_for_mac(mac: &str) -> Option<&'static str> {
    let prefix = normalize_mac(mac)?;
    BUNDLED
        .iter()
        .find(|(p, _)| p.replace(' ', "") == prefix)
        .map(|(_, vendor)| *vendor)
}

/// Lookup using an optional external OUI file, falling back to the bundle.
pub fn vendor_for_mac_with_file(mac: &str, oui_file: Option<&Path>) -> Option<String> {
    let prefix = normalize_mac(mac)?;
    if let Some(path) = oui_file {
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(path) {
                let table = parse_oui_file(&content);
                if let Some(vendor) = table.get(&prefix) {
                    return Some(vendor.clone());
                }
            }
        }
    }
    vendor_for_mac(mac).map(|s| s.to_string())
}

/// Parse either IEEE `oui.txt` (`AA-BB-CC   (hex)\tVendor`) or CSV
/// (`AABBCC,Vendor`).
pub fn parse_oui_file(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // CSV style
        if let Some((prefix, vendor)) = line.split_once(',') {
            if let Some(normalized) = normalize_mac(prefix) {
                map.insert(normalized, vendor.trim().to_string());
                continue;
            }
        }
        // IEEE style: "00-00-0C   (hex)		Cisco Systems, Inc"
        if let Some(hex_pos) = line.find("(hex)") {
            let prefix = line[..hex_pos].trim();
            let vendor = line[hex_pos + 5..].trim();
            if let Some(normalized) = normalize_mac(prefix) {
                map.insert(normalized, vendor.to_string());
            }
        } else if let Some((prefix, vendor)) = line.split_once(char::is_whitespace) {
            if let Some(normalized) = normalize_mac(prefix) {
                map.insert(normalized, vendor.trim().to_string());
            }
        }
    }
    map
}

/// True when the MAC is a locally-administered/random address rather than a
/// globally unique OUI-based address.
pub fn is_locally_administered(mac: &str) -> bool {
    let cleaned: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() != 12 {
        return false;
    }
    let first = u8::from_str_radix(&cleaned[0..2], 16).unwrap_or(0);
    first & 0x02 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_lookup_works() {
        assert_eq!(vendor_for_mac("00:0C:29:11:22:33"), Some("VMware"));
        assert_eq!(vendor_for_mac("08-00-27-aa-bb-cc"), Some("VirtualBox"));
        assert_eq!(vendor_for_mac("525400123456"), Some("QEMU/KVM"));
        assert_eq!(vendor_for_mac("28:cf:e9:00:00:00"), Some("Apple"));
    }

    #[test]
    fn unknown_prefix_returns_none_not_guess() {
        assert_eq!(vendor_for_mac("02:11:22:33:44:55"), None);
        assert_eq!(vendor_for_mac("not-a-mac"), None);
    }

    #[test]
    fn oui_file_parsing_csv_and_ieee() {
        let csv = "001122,Acme Networks\n# comment\n334455,Other Corp\n";
        let table = parse_oui_file(csv);
        assert_eq!(
            table.get("001122").map(|s| s.as_str()),
            Some("Acme Networks")
        );
        assert_eq!(table.get("334455").map(|s| s.as_str()), Some("Other Corp"));

        let ieee = "00-11-22   (hex)\t\tAcme Networks\n";
        let table = parse_oui_file(ieee);
        assert_eq!(
            table.get("001122").map(|s| s.as_str()),
            Some("Acme Networks")
        );
    }

    #[test]
    fn locally_administered_detection() {
        assert!(is_locally_administered("02:00:00:00:00:01"));
        assert!(is_locally_administered("06:11:22:33:44:55"));
        assert!(!is_locally_administered("00:0c:29:11:22:33"));
    }
}
