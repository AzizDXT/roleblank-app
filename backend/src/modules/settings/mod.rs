//! System settings and feature flags.
//!
//! # A feature flag is not an access control
//!
//! Turning a flag off must never be the only thing preventing access. Every route
//! that a flag gates is independently authorised, and the authorisation decision
//! never consults the flag. See the header of `service.rs` for why — in short, a
//! flag is a mutable row behind a deliberately delegable permission, it has no
//! scope, and it is cacheable, so making it load-bearing would create authority
//! that no role review would ever surface.

mod dto;
mod repo;
mod routes;
mod service;

pub use dto::{
    FeatureFlagResponse, SettingResponse, UpdateFeatureFlagRequest, UpdateSettingRequest,
};
pub use routes::router;
/// Exported so the `PathKey` extractor can reject a malformed key using **this**
/// rule rather than a second copy of it. Two copies of a validation grammar drift,
/// and the copy that drifts looser is the one an attacker finds.
pub use service::validate_key;
pub use service::{
    list_feature_flags, list_settings, update_feature_flag, update_setting, REGISTRATION_MODES,
    REGISTRATION_MODE_KEY,
};
