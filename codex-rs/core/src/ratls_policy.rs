//! RA-TLS policy conversion and validation utilities.
//!
//! This module provides utilities to convert configuration-level
//! attestation policy to the ratls-core Policy format.

use crate::model_provider_info::RatlsPolicy as ConfigRatlsPolicy;

#[cfg(feature = "ratls")]
use ratls_core::{Policy, TdxTcbPolicy, TeeType};

/// Convert a hex string to bytes.
#[cfg(feature = "ratls")]
fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    // Remove "0x" prefix if present
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    hex::decode(hex).ok()
}

/// Convert config-level RatlsPolicy to ratls-core Policy.
#[cfg(feature = "ratls")]
pub fn to_ratls_policy(config: &ConfigRatlsPolicy) -> Policy {
    let tee_type = config
        .tee_type
        .as_deref()
        .map(|s| match s.to_lowercase().as_str() {
            "tdx" => TeeType::Tdx,
            _ => TeeType::Tdx, // Default to TDX
        })
        .unwrap_or(TeeType::Tdx);

    let allowed_tdx_status = config
        .allowed_tdx_status
        .clone()
        .unwrap_or_else(|| vec!["UpToDate".into()]);

    let min_tdx_tcb = config.min_tdx_tcb.as_ref().map(|tcb| TdxTcbPolicy {
        mrseam: tcb.mrseam.as_ref().and_then(|s| hex_to_bytes(s)),
        mrtmrs: tcb.mrtmrs.as_ref().and_then(|s| hex_to_bytes(s)),
    });

    Policy {
        tee_type,
        allowed_tdx_status,
        min_tdx_tcb,
        pccs_url: config.pccs_url.clone(),
    }
}

/// Create a development-friendly policy with relaxed constraints.
///
/// This policy accepts a wide range of TCB statuses, suitable for
/// development and testing environments.
#[cfg(feature = "ratls")]
pub fn dev_policy() -> Policy {
    Policy::dev_tdx()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_provider_info::{RatlsPolicy, TdxTcbPolicyConfig};

    #[test]
    #[cfg(feature = "ratls")]
    fn test_policy_conversion_defaults() {
        let config = RatlsPolicy::default();
        let policy = to_ratls_policy(&config);

        assert_eq!(policy.tee_type, TeeType::Tdx);
        assert_eq!(policy.allowed_tdx_status, vec!["UpToDate".to_string()]);
        assert!(policy.min_tdx_tcb.is_none());
    }

    #[test]
    #[cfg(feature = "ratls")]
    fn test_policy_conversion_with_status() {
        let config = RatlsPolicy {
            tee_type: Some("Tdx".into()),
            allowed_tdx_status: Some(vec![
                "UpToDate".into(),
                "SWHardeningNeeded".into(),
            ]),
            min_tdx_tcb: None,
            pccs_url: Some("https://custom.pccs.example.com".into()),
        };
        let policy = to_ratls_policy(&config);

        assert_eq!(policy.tee_type, TeeType::Tdx);
        assert_eq!(
            policy.allowed_tdx_status,
            vec!["UpToDate".to_string(), "SWHardeningNeeded".to_string()]
        );
        assert_eq!(
            policy.pccs_url,
            Some("https://custom.pccs.example.com".into())
        );
    }

    #[test]
    #[cfg(feature = "ratls")]
    fn test_hex_to_bytes() {
        assert_eq!(hex_to_bytes("deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(
            hex_to_bytes("0xdeadbeef"),
            Some(vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(hex_to_bytes("invalid"), None);
    }
}
