//! Strict loader for the audience-specific Steadholme Experience projections.
//!
//! The canonical Manifest generator emits two disjoint projections: `public` contains only
//! discoverable product surfaces, while `estate` contains only the additional WireGuard
//! management surfaces. Portal loads the pair at startup and converts each projection into its
//! existing render DTO. Route exposure and authorization remain Sluice-owned; these files are
//! presentation inputs, never an authorization source.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use semver::Version;
use serde::Deserialize;
use thiserror::Error;

use crate::catalog::CatalogEntry;

pub const SCHEMA_VERSION: &str = "holdfast.experience-projection.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionAudience {
    Public,
    Estate,
}

impl ProjectionAudience {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Estate => "estate",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionIdentity {
    pub release: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug)]
pub struct LoadedProjection {
    pub identity: ProjectionIdentity,
    pub catalog: Vec<CatalogEntry>,
}

#[derive(Clone, Debug)]
pub struct ProjectionPair {
    pub public: LoadedProjection,
    pub estate: LoadedProjection,
}

#[derive(Debug, Error)]
pub enum ProjectionError {
    #[error("could not read {audience} Experience projection {path}: {source}")]
    Read {
        audience: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid {audience} Experience projection JSON: {source}")]
    Json {
        audience: &'static str,
        source: serde_json::Error,
    },
    #[error("invalid {audience} Experience projection: {message}")]
    Contract {
        audience: &'static str,
        message: String,
    },
    #[error("invalid Experience projection pair: {0}")]
    Pair(String),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectionDocument {
    schema_version: String,
    release: String,
    fingerprint: String,
    audience: String,
    surfaces: Vec<ProjectionSurface>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectionSurface {
    id: String,
    name: String,
    description: String,
    url: String,
    category: String,
    icon: String,
    status_component: String,
    profile: String,
    capabilities: Vec<String>,
    coming_soon: bool,
}

/// Read and validate the two disjoint audience projections. Any IO, schema, audience, content,
/// release, duplicate-id, or duplicate-URL problem fails the whole pair closed.
pub fn load_projection_pair(
    public_path: impl AsRef<Path>,
    estate_path: impl AsRef<Path>,
) -> Result<ProjectionPair, ProjectionError> {
    let public = load_projection(public_path, ProjectionAudience::Public)?;
    let estate = load_projection(estate_path, ProjectionAudience::Estate)?;

    if public.identity.release != estate.identity.release {
        return Err(ProjectionError::Pair(format!(
            "release mismatch: public={} estate={}",
            public.identity.release, estate.identity.release
        )));
    }
    if public.identity.fingerprint == estate.identity.fingerprint {
        return Err(ProjectionError::Pair(
            "public and estate fingerprints must be distinct".to_string(),
        ));
    }

    let public_ids: HashSet<&str> = public
        .catalog
        .iter()
        .map(|entry| entry.id.as_str())
        .collect();
    let public_urls: HashSet<String> = public
        .catalog
        .iter()
        .map(|entry| {
            canonical_url_key("public surface URL", &entry.url)
                .expect("projection URLs were validated before pair validation")
        })
        .collect();
    for entry in &estate.catalog {
        if public_ids.contains(entry.id.as_str()) {
            return Err(ProjectionError::Pair(format!(
                "surface id {:?} occurs in both public and estate projections",
                entry.id
            )));
        }
        let estate_url = canonical_url_key("estate surface URL", &entry.url)
            .expect("projection URLs were validated before pair validation");
        if public_urls.contains(&estate_url) {
            return Err(ProjectionError::Pair(format!(
                "surface URL {:?} occurs in both public and estate projections",
                entry.url
            )));
        }
    }
    reject_public_estate_hosts(&public.identity.release, &public.catalog, &estate.catalog)?;

    Ok(ProjectionPair { public, estate })
}

pub fn load_projection(
    path: impl AsRef<Path>,
    expected: ProjectionAudience,
) -> Result<LoadedProjection, ProjectionError> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path).map_err(|source| ProjectionError::Read {
        audience: expected.as_str(),
        path: path.to_path_buf(),
        source,
    })?;
    parse_projection(&raw, expected)
}

/// Parse one projection. Public for focused contract tests and for tooling that wants the same
/// validation without first writing a file.
pub fn parse_projection(
    raw: &str,
    expected: ProjectionAudience,
) -> Result<LoadedProjection, ProjectionError> {
    let document: ProjectionDocument =
        serde_json::from_str(raw).map_err(|source| ProjectionError::Json {
            audience: expected.as_str(),
            source,
        })?;
    validate_document(document, expected)
}

fn validate_document(
    document: ProjectionDocument,
    expected: ProjectionAudience,
) -> Result<LoadedProjection, ProjectionError> {
    let invalid = |message: String| ProjectionError::Contract {
        audience: expected.as_str(),
        message,
    };

    if document.schema_version != SCHEMA_VERSION {
        return Err(invalid(format!(
            "schemaVersion must be {SCHEMA_VERSION:?}, got {:?}",
            document.schema_version
        )));
    }
    require_nonempty("release", &document.release).map_err(&invalid)?;
    Version::parse(&document.release).map_err(|_| {
        invalid(format!(
            "release {:?} is not strict SemVer",
            document.release
        ))
    })?;
    require_nonempty("fingerprint", &document.fingerprint).map_err(&invalid)?;
    validate_fingerprint(&document.fingerprint).map_err(&invalid)?;
    if document.audience != expected.as_str() {
        return Err(invalid(format!(
            "audience must be {:?}, got {:?}",
            expected.as_str(),
            document.audience
        )));
    }
    if document.surfaces.is_empty() {
        return Err(invalid("surfaces must not be empty".to_string()));
    }

    let mut ids = HashSet::new();
    let mut urls = HashSet::new();
    let mut previous_id: Option<String> = None;
    let mut catalog = Vec::with_capacity(document.surfaces.len());
    for (index, surface) in document.surfaces.into_iter().enumerate() {
        let prefix = format!("surfaces[{index}]");
        for (field, value) in [
            ("id", surface.id.as_str()),
            ("name", surface.name.as_str()),
            ("description", surface.description.as_str()),
            ("url", surface.url.as_str()),
            ("category", surface.category.as_str()),
            ("icon", surface.icon.as_str()),
            ("statusComponent", surface.status_component.as_str()),
            ("profile", surface.profile.as_str()),
        ] {
            require_nonempty(&format!("{prefix}.{field}"), value).map_err(&invalid)?;
        }
        validate_id(&format!("{prefix}.id"), &surface.id).map_err(&invalid)?;
        if !ids.insert(surface.id.clone()) {
            return Err(invalid(format!("duplicate surface id {:?}", surface.id)));
        }
        if previous_id
            .as_deref()
            .is_some_and(|previous| previous >= surface.id.as_str())
        {
            return Err(invalid(format!(
                "surfaces must be strictly sorted by id: {previous_id:?} before {:?}",
                surface.id
            )));
        }
        previous_id = Some(surface.id.clone());
        let canonical_url =
            canonical_url_key(&format!("{prefix}.url"), &surface.url).map_err(&invalid)?;
        validate_category(&format!("{prefix}.category"), &surface.category).map_err(&invalid)?;
        validate_profile(&format!("{prefix}.profile"), &surface.profile).map_err(&invalid)?;
        if !urls.insert(canonical_url) {
            return Err(invalid(format!(
                "duplicate canonical surface URL {:?}; URL is Portal's stable data-app-id",
                surface.url
            )));
        }
        let mut previous_capability: Option<&str> = None;
        for (capability_index, capability) in surface.capabilities.iter().enumerate() {
            let field = format!("{prefix}.capabilities[{capability_index}]");
            require_nonempty(&field, capability).map_err(&invalid)?;
            validate_id(&field, capability).map_err(&invalid)?;
            if previous_capability.is_some_and(|previous| previous >= capability.as_str()) {
                return Err(invalid(format!(
                    "{prefix}.capabilities must be unique and strictly sorted"
                )));
            }
            previous_capability = Some(capability);
        }

        catalog.push(CatalogEntry {
            id: surface.id,
            name: surface.name,
            url: surface.url,
            description: surface.description,
            component: surface.status_component,
            icon: surface.icon,
            category: surface.category,
            profile: surface.profile,
            capabilities: surface.capabilities,
            coming_soon: surface.coming_soon,
        });
    }

    Ok(LoadedProjection {
        identity: ProjectionIdentity {
            release: document.release,
            fingerprint: document.fingerprint,
        },
        catalog,
    })
}

fn require_nonempty(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn canonical_url_key(field: &str, value: &str) -> Result<String, String> {
    if value.chars().any(char::is_whitespace) {
        return Err(format!("{field} must not contain whitespace"));
    }
    let Some(authority_and_path) = value.strip_prefix("https://") else {
        return Err(format!("{field} must use https://"));
    };
    let (host, path) = match authority_and_path.find('/') {
        Some(index) => (
            &authority_and_path[..index],
            Some(&authority_and_path[index..]),
        ),
        None => (authority_and_path, None),
    };
    if !valid_holdfast_host(host) {
        return Err(format!(
            "{field} host must be w33d.xyz or a strict lowercase DNS-label w33d.xyz subdomain"
        ));
    }
    let Some(path) = path else {
        return Ok(format!("https://{host}"));
    };
    if path == "/" {
        return Err(format!("{field} root URL must omit the trailing slash"));
    }
    let decoded_path = canonical_path(field, path)?;
    Ok(format!("https://{host}{decoded_path}"))
}

fn valid_holdfast_host(host: &str) -> bool {
    if host.len() > 253 || (host != "w33d.xyz" && !host.ends_with(".w33d.xyz")) {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn canonical_path(field: &str, path: &str) -> Result<String, String> {
    if !path.is_ascii() || !path.starts_with('/') || path.contains("//") {
        return Err(format!("{field} must use a canonical absolute path"));
    }
    let mut decoded = path.to_string();
    for _ in 0..4 {
        if !decoded.contains('%') {
            break;
        }
        decoded = percent_decode(&decoded)
            .ok_or_else(|| format!("{field} contains a malformed percent escape"))?;
    }
    if decoded.contains('%') {
        return Err(format!("{field} contains excessive percent encoding"));
    }
    if !decoded.is_ascii()
        || decoded.contains("//")
        || decoded.contains('?')
        || decoded.contains('#')
        || decoded.contains('\\')
        || decoded.chars().any(char::is_control)
        || decoded
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(format!("{field} contains a non-canonical or unsafe path"));
    }
    Ok(decoded)
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push(hex_value(high)? * 16 + hex_value(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn reject_public_estate_hosts(
    public_release: &str,
    public: &[CatalogEntry],
    estate: &[CatalogEntry],
) -> Result<(), ProjectionError> {
    let estate_hosts: HashSet<&str> = estate
        .iter()
        .map(|entry| {
            entry
                .url
                .strip_prefix("https://")
                .expect("validated HTTPS URL")
                .split('/')
                .next()
                .expect("validated URL has a host")
        })
        .collect();
    let normalized_release = public_release.to_ascii_lowercase();
    if let Some(host) = estate_hosts
        .iter()
        .find(|host| normalized_release.contains(**host))
    {
        return Err(ProjectionError::Pair(format!(
            "public release leaks estate host {host:?}"
        )));
    }
    for entry in public {
        let text = [
            entry.id.as_str(),
            entry.name.as_str(),
            entry.description.as_str(),
            entry.url.as_str(),
            entry.category.as_str(),
            entry.icon.as_str(),
            entry.component.as_str(),
            entry.profile.as_str(),
        ]
        .into_iter()
        .chain(entry.capabilities.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
        if let Some(host) = estate_hosts.iter().find(|host| text.contains(**host)) {
            return Err(ProjectionError::Pair(format!(
                "public surface {:?} leaks estate host {host:?}",
                entry.id
            )));
        }
    }
    Ok(())
}

fn validate_fingerprint(value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err("fingerprint must use sha256:<64 lowercase hex>".to_string());
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("fingerprint must use sha256:<64 lowercase hex>".to_string());
    }
    Ok(())
}

fn validate_id(field: &str, value: &str) -> Result<(), String> {
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(format!(
            "{field} must start with [a-z] and continue with only [a-z0-9-]"
        ));
    }
    Ok(())
}

fn validate_profile(field: &str, value: &str) -> Result<(), String> {
    if matches!(
        value,
        "ai" | "communication"
            | "content"
            | "control"
            | "data"
            | "developer"
            | "identity"
            | "knowledge"
            | "networking"
            | "observability"
            | "portal"
            | "productivity"
            | "public"
            | "security"
    ) {
        Ok(())
    } else {
        Err(format!("{field} has unknown Odyssey profile {value:?}"))
    }
}

fn validate_category(field: &str, value: &str) -> Result<(), String> {
    if matches!(
        value,
        "communication"
            | "content"
            | "identity"
            | "observability"
            | "ai"
            | "developer"
            | "platform"
    ) {
        Ok(())
    } else {
        Err(format!(
            "{field} has unknown value {value:?}; expected communication, content, identity, observability, ai, developer, or platform"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projection(audience: &str, id: &str, url: &str) -> String {
        let fingerprint = if audience == "public" {
            "a".repeat(64)
        } else {
            "b".repeat(64)
        };
        format!(
            r#"{{
  "schemaVersion":"holdfast.experience-projection.v1",
  "release":"1.0.0",
  "fingerprint":"sha256:{fingerprint}",
  "audience":"{audience}",
  "surfaces":[{{
    "id":"{id}",
    "name":"Example",
    "description":"Example product surface",
    "url":"{url}",
    "category":"platform",
    "icon":"grid",
    "statusComponent":"Example",
    "profile":"control",
    "capabilities":["launch","status"],
    "comingSoon":false
  }}]
}}"#
        )
    }

    #[test]
    fn strict_projection_maps_manifest_surface_to_catalog_dto() {
        let loaded = parse_projection(
            &projection("public", "example-web", "https://example.w33d.xyz"),
            ProjectionAudience::Public,
        )
        .expect("valid projection");
        assert_eq!(loaded.identity.release, "1.0.0");
        assert_eq!(
            loaded.identity.fingerprint,
            format!("sha256:{}", "a".repeat(64))
        );
        assert_eq!(loaded.catalog.len(), 1);
        assert_eq!(loaded.catalog[0].id, "example-web");
        assert_eq!(loaded.catalog[0].url, "https://example.w33d.xyz");
        assert_eq!(loaded.catalog[0].component, "Example");
        assert_eq!(loaded.catalog[0].category, "platform");
        assert_eq!(loaded.catalog[0].profile, "control");
        assert_eq!(loaded.catalog[0].capabilities, ["launch", "status"]);
    }

    #[test]
    fn strict_projection_rejects_unknown_fields_and_audience_mismatch() {
        let unknown = projection("public", "example-web", "https://example.w33d.xyz")
            .replace("\"surfaces\"", "\"unexpected\":true,\"surfaces\"");
        assert!(matches!(
            parse_projection(&unknown, ProjectionAudience::Public),
            Err(ProjectionError::Json { .. })
        ));

        let mismatch = parse_projection(
            &projection("estate", "example-ops", "https://ops.w33d.xyz"),
            ProjectionAudience::Public,
        )
        .unwrap_err()
        .to_string();
        assert!(mismatch.contains("audience must be \"public\""));
    }

    #[test]
    fn strict_projection_requires_semver_release_and_sorted_surface_ids() {
        for release in ["r1", "2026.07.11", "1.0", "01.0.0", "v1.0.0"] {
            let invalid = projection("public", "example-web", "https://example.w33d.xyz").replace(
                "\"release\":\"1.0.0\"",
                &format!("\"release\":\"{release}\""),
            );
            assert!(
                parse_projection(&invalid, ProjectionAudience::Public)
                    .unwrap_err()
                    .to_string()
                    .contains("strict SemVer"),
                "accepted non-SemVer release {release}"
            );
        }

        let unsorted = r#"{
          "schemaVersion":"holdfast.experience-projection.v1",
          "release":"1.0.0","fingerprint":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","audience":"public",
          "surfaces":[
            {"id":"z-last","name":"Z","description":"Z surface","url":"https://z.w33d.xyz","category":"platform","icon":"grid","statusComponent":"Z","profile":"control","capabilities":[],"comingSoon":false},
            {"id":"a-first","name":"A","description":"A surface","url":"https://a.w33d.xyz","category":"platform","icon":"grid","statusComponent":"A","profile":"control","capabilities":[],"comingSoon":false}
          ]
        }"#;
        assert!(parse_projection(unsorted, ProjectionAudience::Public)
            .unwrap_err()
            .to_string()
            .contains("strictly sorted by id"));
    }

    #[test]
    fn strict_projection_rejects_duplicate_ids_non_https_empty_and_unknown_category() {
        let duplicate = r#"{
          "schemaVersion":"holdfast.experience-projection.v1",
          "release":"1.0.0","fingerprint":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","audience":"public",
          "surfaces":[
            {"id":"same","name":"A","description":"A surface","url":"https://a.w33d.xyz","category":"platform","icon":"grid","statusComponent":"A","profile":"control","capabilities":[],"comingSoon":false},
            {"id":"same","name":"B","description":"B surface","url":"https://b.w33d.xyz","category":"platform","icon":"grid","statusComponent":"B","profile":"control","capabilities":[],"comingSoon":false}
          ]
        }"#;
        assert!(parse_projection(duplicate, ProjectionAudience::Public)
            .unwrap_err()
            .to_string()
            .contains("duplicate surface id"));

        let non_https = projection("public", "example-web", "http://example.w33d.xyz");
        assert!(parse_projection(&non_https, ProjectionAudience::Public)
            .unwrap_err()
            .to_string()
            .contains("must use https://"));

        let empty = projection("public", "example-web", "https://example.w33d.xyz")
            .replace("\"name\":\"Example\"", "\"name\":\"  \"");
        assert!(parse_projection(&empty, ProjectionAudience::Public)
            .unwrap_err()
            .to_string()
            .contains("name must not be empty"));

        let category = projection("public", "example-web", "https://example.w33d.xyz")
            .replace("\"category\":\"platform\"", "\"category\":\"misc\"");
        assert!(parse_projection(&category, ProjectionAudience::Public)
            .unwrap_err()
            .to_string()
            .contains("unknown value \"misc\""));
    }

    #[test]
    fn strict_projection_validates_fingerprint_domain_profile_ids_and_capability_order() {
        let base = projection("public", "example-web", "https://example.w33d.xyz");

        let fingerprint = base.replace(&format!("sha256:{}", "a".repeat(64)), "sha256:ABC");
        assert!(parse_projection(&fingerprint, ProjectionAudience::Public)
            .unwrap_err()
            .to_string()
            .contains("64 lowercase hex"));

        let foreign = projection("public", "example-web", "https://example.invalid");
        assert!(parse_projection(&foreign, ProjectionAudience::Public)
            .unwrap_err()
            .to_string()
            .contains("w33d.xyz subdomain"));

        for url in [
            "https://example.w33d.xyz:443",
            "https://example.w33d.xyz/?token=x",
            "https://example.w33d.xyz/#fragment",
            "https://user@example.w33d.xyz",
        ] {
            assert!(
                parse_projection(
                    &projection("public", "example-web", url),
                    ProjectionAudience::Public
                )
                .is_err(),
                "URL should be rejected: {url}"
            );
        }

        let bad_id = projection("public", "example.web", "https://example.w33d.xyz");
        assert!(parse_projection(&bad_id, ProjectionAudience::Public)
            .unwrap_err()
            .to_string()
            .contains("[a-z0-9-]"));

        let profile = base.replace("\"profile\":\"control\"", "\"profile\":\"bespoke\"");
        assert!(parse_projection(&profile, ProjectionAudience::Public)
            .unwrap_err()
            .to_string()
            .contains("unknown Odyssey profile"));

        let unsorted = base.replace(
            "\"capabilities\":[\"launch\",\"status\"]",
            "\"capabilities\":[\"status\",\"launch\"]",
        );
        assert!(parse_projection(&unsorted, ProjectionAudience::Public)
            .unwrap_err()
            .to_string()
            .contains("strictly sorted"));

        let bad_capability = base.replace("\"launch\"", "\"launch.now\"");
        assert!(
            parse_projection(&bad_capability, ProjectionAudience::Public)
                .unwrap_err()
                .to_string()
                .contains("[a-z0-9-]")
        );
    }

    #[test]
    fn strict_projection_rejects_noncanonical_hosts_paths_and_escaped_traversal() {
        for url in [
            "https://.w33d.xyz",
            "https://foo..w33d.xyz",
            "https://-foo.w33d.xyz",
            "https://foo-.w33d.xyz",
            "https://Foo.w33d.xyz",
            "https://example.w33d.xyz/",
            "https://example.w33d.xyz//admin",
            "https://example.w33d.xyz/safe//admin",
            "https://example.w33d.xyz/../secret",
            "https://example.w33d.xyz/./secret",
            "https://example.w33d.xyz/%2e%2e/secret",
            "https://example.w33d.xyz/%252e%252e/secret",
            "https://example.w33d.xyz/%25252e%25252e/secret",
            "https://example.w33d.xyz/%5c..%5csecret",
            "https://example.w33d.xyz/%3fquery",
            "https://example.w33d.xyz/%",
            "https://example.w33d.xyz/%2",
            "https://example.w33d.xyz/%gg",
        ] {
            assert!(
                parse_projection(
                    &projection("public", "example-web", url),
                    ProjectionAudience::Public
                )
                .is_err(),
                "accepted non-canonical URL {url}"
            );
        }

        let raw_backslash = projection(
            "public",
            "example-web",
            "https://example.w33d.xyz/safe\\\\..\\\\secret",
        );
        assert!(parse_projection(&raw_backslash, ProjectionAudience::Public).is_err());
    }

    #[test]
    fn canonical_url_identity_prevents_percent_encoding_duplicate_bypass() {
        let duplicate = r#"{
          "schemaVersion":"holdfast.experience-projection.v1",
          "release":"1.0.0","fingerprint":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","audience":"public",
          "surfaces":[
            {"id":"a-plain","name":"A","description":"A surface","url":"https://same.w33d.xyz/x","category":"platform","icon":"grid","statusComponent":"A","profile":"control","capabilities":[],"comingSoon":false},
            {"id":"b-escaped","name":"B","description":"B surface","url":"https://same.w33d.xyz/%78","category":"platform","icon":"grid","statusComponent":"B","profile":"control","capabilities":[],"comingSoon":false}
          ]
        }"#;
        assert!(parse_projection(duplicate, ProjectionAudience::Public)
            .unwrap_err()
            .to_string()
            .contains("duplicate canonical surface URL"));
    }

    #[test]
    fn public_metadata_must_not_contain_an_estate_host() {
        let mut public = parse_projection(
            &projection("public", "mail-web", "https://mail.w33d.xyz"),
            ProjectionAudience::Public,
        )
        .unwrap();
        let estate = parse_projection(
            &projection("estate", "vault-ops", "https://vault.w33d.xyz"),
            ProjectionAudience::Estate,
        )
        .unwrap();
        public.catalog[0].description = "Escalate through VAULT.W33D.XYZ".to_string();
        assert!(
            reject_public_estate_hosts("1.0.0", &public.catalog, &estate.catalog)
                .unwrap_err()
                .to_string()
                .contains("leaks estate host")
        );

        assert!(reject_public_estate_hosts(
            "1.0.0+vault.w33d.xyz",
            &parse_projection(
                &projection("public", "mail-web", "https://mail.w33d.xyz"),
                ProjectionAudience::Public,
            )
            .unwrap()
            .catalog,
            &estate.catalog,
        )
        .unwrap_err()
        .to_string()
        .contains("public release leaks estate host"));
    }
}
