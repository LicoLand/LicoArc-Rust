use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{
    Deserialize,
    de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;

use crate::{
    error::{Error, ErrorCode, Stage},
    provider::{DigestProvider, fixed_sha256},
};

const MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SOURCES: usize = 256;
const MAX_SOURCE_BYTES: usize = 4_194_304;
const MAX_JSON_DEPTH: usize = 16;
const MAX_INTEGER: u64 = 9_007_199_254_740_991;
const FOUNDATION_JSON_LIMITS: JsonLimits = JsonLimits {
    max_bytes: 1_048_576,
    max_depth: MAX_JSON_DEPTH,
    max_array_items: 64,
    max_object_members: 64,
    max_string_bytes: 4_096,
};
const SECURITY_BINDINGS_JSON_LIMITS: JsonLimits = JsonLimits {
    max_array_items: 256,
    ..FOUNDATION_JSON_LIMITS
};
const CONFORMANCE_JSON_LIMITS: JsonLimits = JsonLimits {
    max_bytes: MAX_SOURCE_BYTES,
    max_depth: MAX_JSON_DEPTH,
    max_array_items: 512,
    max_object_members: 256,
    max_string_bytes: 1_048_576,
};
const EXPECTED_BUNDLE_DIGEST: &str =
    "b6ceacb359568cb09800317a8d4668442f55a1a66bba04f13c3e865a6cd2f8e0";
const EXPECTED_LINE_ID: &str = "c0b64d71865ce972a944db3d31a18cb03395300f3ed006c21e64429178c23a08";
const EXPECTED_PROFILE_ID: &str =
    "4b7d575f397862f9031e44b716921e86c410b5facf379bde21955922b0d58a17";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SnapshotDigest([u8; 32]);

impl SnapshotDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Explicit, read-only, content-addressed authority input.
pub struct AuthorityBundle<'a> {
    bytes: &'a [u8],
}

impl<'a> AuthorityBundle<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn admit(self) -> Result<VerifiedProtocolLine, Error> {
        if self.bytes.is_empty() || self.bytes.len() > MAX_BUNDLE_BYTES {
            return Err(admission(ErrorCode::BoundExceeded));
        }
        let bundle = parse_bundle(self.bytes)?;
        bundle.verify()
    }
}

/// Immutable proof that the exact reviewed stable-core Protocol Line was admitted.
///
/// The token has no public constructor. Callers can obtain it only by admitting
/// the complete, explicitly supplied, content-addressed authority bundle.
#[derive(Clone)]
pub struct VerifiedProtocolLine {
    snapshot_digest: SnapshotDigest,
    wire_id: String,
    generation: u64,
    capability_ids: Vec<String>,
    protocol_line_id: [u8; 32],
    protection_profile_id: [u8; 32],
    case_count: usize,
    operation_ids: Vec<String>,
    protection_bounds: BTreeMap<String, u64>,
    sources: Arc<BTreeMap<String, Value>>,
}

impl std::fmt::Debug for VerifiedProtocolLine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedProtocolLine([REDACTED])")
    }
}

impl VerifiedProtocolLine {
    #[must_use]
    pub const fn snapshot_digest(&self) -> SnapshotDigest {
        self.snapshot_digest
    }

    #[must_use]
    pub fn wire_id(&self) -> &str {
        &self.wire_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn capability_ids(&self) -> &[String] {
        &self.capability_ids
    }

    #[must_use]
    pub const fn protocol_line_id(&self) -> &[u8; 32] {
        &self.protocol_line_id
    }

    #[must_use]
    pub const fn protection_profile_id(&self) -> &[u8; 32] {
        &self.protection_profile_id
    }

    #[must_use]
    pub const fn conformance_case_count(&self) -> usize {
        self.case_count
    }

    #[must_use]
    pub fn operation_ids(&self) -> &[String] {
        &self.operation_ids
    }

    #[must_use]
    pub fn protection_bound(&self, name: &str) -> Option<u64> {
        self.protection_bounds.get(name).copied()
    }

    pub(crate) fn source(&self, path: &str) -> Result<&Value, Error> {
        self.sources
            .get(path)
            .ok_or_else(|| admission(ErrorCode::SourceClosureMismatch))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Bundle {
    artifact_version: String,
    wire_id: String,
    generation: u64,
    lifecycle: String,
    definition_status: String,
    session_eligible: bool,
    publication_eligible: bool,
    digest_algorithm: String,
    sources: BTreeMap<String, Value>,
    digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LineManifest {
    #[serde(rename = "$schema")]
    schema: String,
    manifest_version: String,
    wire_id: String,
    generation: u64,
    lifecycle: String,
    definition_status: String,
    session_eligible: bool,
    publication_eligible: bool,
    protocol_line_catalog: String,
    protection_profile_catalog: String,
    protocol_line_id: String,
    protection_profile_ids: Vec<String>,
    capabilities: Vec<Component>,
    missing_mandatory_capabilities: Vec<String>,
    open_definitions: Vec<Value>,
    blockers: Vec<String>,
    source_closure: AggregateClosure,
    handshake_binding: String,
    session_lock: bool,
    translation_policy: String,
    stable_claim_ids: Vec<String>,
    field_registry: FieldRegistry,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FieldRegistry {
    authority: String,
    path: String,
    source_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Component {
    capability_id: String,
    version: u64,
    definition_status: String,
    source_manifest_path: Option<String>,
    source_roots: Vec<String>,
    source_paths: Vec<String>,
    source_digest: String,
    semantic_identity: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AggregateClosure {
    roots: Vec<String>,
    additional_sources: Vec<String>,
    undeclared_files: String,
    symlinks: String,
    encoding: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SourceManifest {
    #[serde(rename = "$schema")]
    schema: String,
    #[serde(rename = "$id")]
    id: String,
    manifest_version: String,
    #[serde(default)]
    artifact_version: Option<String>,
    #[serde(default)]
    contract_version: Option<String>,
    lifecycle: String,
    #[serde(default)]
    definition_status: Option<String>,
    #[serde(default)]
    session_eligible: Option<bool>,
    #[serde(default)]
    representation: Option<String>,
    #[serde(default)]
    digest_algorithm: Option<String>,
    #[serde(default)]
    sorted: Option<bool>,
    #[serde(default)]
    source_roots: Vec<String>,
    sources: Vec<String>,
    #[serde(default)]
    additional_sources: Vec<String>,
    #[serde(default)]
    undeclared_files: Option<String>,
    #[serde(default)]
    symlinks: Option<String>,
    #[serde(default)]
    aggregate_admission_pending: Option<bool>,
    #[serde(default)]
    semantic_sources_complete: Option<bool>,
    #[serde(default)]
    dependency_manifests: Vec<String>,
}

impl Bundle {
    fn verify(self) -> Result<VerifiedProtocolLine, Error> {
        if self.artifact_version != "licoarc.bundle.v1"
            || self.wire_id != "licoarc.protocol-line.v1"
            || self.generation != 1
            || self.digest_algorithm != "sha256"
            || self.lifecycle != "Candidate"
            || self.definition_status != "COMPLETE"
            || !self.session_eligible
            || self.publication_eligible
            || self.sources.len() > MAX_SOURCES
        {
            return Err(admission(ErrorCode::UnsupportedDefinition));
        }
        for path in self.sources.keys() {
            validate_path(path)?;
        }
        for (path, source) in &self.sources {
            if path.ends_with(".json") {
                let limits = source_json_limits(path);
                validate_json_source(source, 0, limits)?;
                canonical_json_bounded(source, limits.max_bytes)?;
            } else {
                let text = source
                    .as_str()
                    .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
                if text.len() > MAX_SOURCE_BYTES {
                    return Err(admission(ErrorCode::BoundExceeded));
                }
            }
        }
        if self.digest != EXPECTED_BUNDLE_DIGEST {
            return Err(admission(ErrorCode::DigestMismatch));
        }

        let mut canonical_body = canonical_bundle_body(&self)?;
        push_bounded(&mut canonical_body, "\n", MAX_BUNDLE_BYTES)?;
        let snapshot = digest(canonical_body.as_bytes());
        if hex(&snapshot) != self.digest || hex(&snapshot) != EXPECTED_BUNDLE_DIGEST {
            return Err(admission(ErrorCode::DigestMismatch));
        }

        let manifest_value = self
            .sources
            .get("spec/v1/manifest.json")
            .ok_or_else(|| admission(ErrorCode::SourceClosureMismatch))?;
        let manifest: LineManifest = serde_json::from_value(manifest_value.clone())
            .map_err(|_| admission(ErrorCode::InvalidAuthorityInput))?;
        if manifest.schema != "https://json-schema.org/draft/2020-12/schema"
            || manifest.manifest_version != "licoarc.protocol-line-manifest.v1"
            || manifest.wire_id != self.wire_id
            || manifest.generation != self.generation
            || manifest.lifecycle != self.lifecycle
            || manifest.definition_status != self.definition_status
            || manifest.session_eligible != self.session_eligible
            || manifest.publication_eligible != self.publication_eligible
            || manifest.protocol_line_catalog != "spec/protocol-lines.json"
            || manifest.protection_profile_catalog != "spec/protection-profiles.json"
            || manifest.protocol_line_id != EXPECTED_LINE_ID
            || manifest.protection_profile_ids != [EXPECTED_PROFILE_ID]
            || !manifest.missing_mandatory_capabilities.is_empty()
            || !manifest.open_definitions.is_empty()
            || !manifest.blockers.is_empty()
            || manifest.source_closure.roots != ["conformance/v1", "spec/schemas", "spec/v1"]
            || manifest.source_closure.undeclared_files != "reject"
            || manifest.source_closure.symlinks != "reject"
            || manifest.source_closure.encoding
                != "restricted-jcs-json-plus-canonical-utf8-cddl-and-markdown"
            || manifest.handshake_binding != "protocol-line-and-profile-identities-transcript-bound"
            || !manifest.session_lock
            || manifest.translation_policy != "forbidden"
            || manifest.stable_claim_ids.is_empty()
            || manifest.field_registry.authority != "canonical-field-registry"
            || manifest.field_registry.path != "spec/FIELD-REGISTRY.md"
        {
            return Err(admission(ErrorCode::SourceClosureMismatch));
        }
        ensure_sorted_unique(&manifest.stable_claim_ids)?;
        ensure_sorted_unique(&manifest.source_closure.additional_sources)?;

        let mut expected = BTreeSet::from([
            "spec/v1/manifest.json".to_owned(),
            "conformance/v1/manifest.json".to_owned(),
        ]);
        expected.extend(manifest.source_closure.additional_sources.iter().cloned());
        let mut capability_ids = Vec::with_capacity(manifest.capabilities.len());
        let mut capability_semantic_ids = Vec::with_capacity(manifest.capabilities.len());
        if manifest.capabilities.is_empty() {
            return Err(admission(ErrorCode::UnsupportedDefinition));
        }
        for component in &manifest.capabilities {
            if component.definition_status != "COMPLETE" {
                return Err(admission(ErrorCode::UnsupportedDefinition));
            }
            capability_ids.push(component.capability_id.clone());
            validate_digest_text(&component.semantic_identity)?;
            capability_semantic_ids.push(component.semantic_identity.clone());
            let paths = component_paths(component, &self.sources)?;
            verify_component_digest(&paths, &component.source_digest, &self.sources)?;
            expected.extend(paths);
        }
        ensure_sorted_unique(&capability_ids)?;

        let aggregate = source_object(&self.sources, "conformance/v1/manifest.json")?;
        let definition_corpora = aggregate
            .get("definitionCorpora")
            .and_then(Value::as_array)
            .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
        if definition_corpora.len() != 1 {
            return Err(admission(ErrorCode::SourceClosureMismatch));
        }
        let security_corpus = definition_corpora[0]
            .as_object()
            .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
        if required_string(security_corpus, "definitionId")? != "security-accounting" {
            return Err(admission(ErrorCode::SourceClosureMismatch));
        }
        let security_paths =
            source_manifest_paths("spec/v1/security/source-manifest.json", &self.sources)?;
        verify_component_digest(
            &security_paths,
            required_string(security_corpus, "sourceDigest")?,
            &self.sources,
        )?;
        expected.extend(security_paths);
        if expected != self.sources.keys().cloned().collect() {
            return Err(admission(ErrorCode::SourceClosureMismatch));
        }

        let field_registry = self
            .sources
            .get(&manifest.field_registry.path)
            .and_then(Value::as_str)
            .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
        if hex(&digest(field_registry.as_bytes())) != manifest.field_registry.source_digest {
            return Err(admission(ErrorCode::DigestMismatch));
        }

        let admission_facts = verify_current_stable_sources(
            &self.sources,
            &manifest,
            &capability_ids,
            &capability_semantic_ids,
        )?;
        Ok(VerifiedProtocolLine {
            snapshot_digest: SnapshotDigest(snapshot),
            wire_id: self.wire_id,
            generation: self.generation,
            capability_ids,
            protocol_line_id: decode_digest(EXPECTED_LINE_ID)?,
            protection_profile_id: decode_digest(EXPECTED_PROFILE_ID)?,
            case_count: admission_facts.case_count,
            operation_ids: admission_facts.operation_ids,
            protection_bounds: admission_facts.protection_bounds,
            sources: Arc::new(self.sources),
        })
    }
}

fn canonical_bundle_body(bundle: &Bundle) -> Result<String, Error> {
    let mut output = String::new();
    push_bounded(&mut output, "{\"artifactVersion\":", MAX_BUNDLE_BYTES)?;
    append_json_string(&bundle.artifact_version, &mut output, MAX_BUNDLE_BYTES)?;
    push_bounded(&mut output, ",\"definitionStatus\":", MAX_BUNDLE_BYTES)?;
    append_json_string(&bundle.definition_status, &mut output, MAX_BUNDLE_BYTES)?;
    push_bounded(&mut output, ",\"digestAlgorithm\":", MAX_BUNDLE_BYTES)?;
    append_json_string(&bundle.digest_algorithm, &mut output, MAX_BUNDLE_BYTES)?;
    push_bounded(&mut output, ",\"generation\":", MAX_BUNDLE_BYTES)?;
    push_bounded(
        &mut output,
        &bundle.generation.to_string(),
        MAX_BUNDLE_BYTES,
    )?;
    push_bounded(&mut output, ",\"lifecycle\":", MAX_BUNDLE_BYTES)?;
    append_json_string(&bundle.lifecycle, &mut output, MAX_BUNDLE_BYTES)?;
    push_bounded(&mut output, ",\"publicationEligible\":", MAX_BUNDLE_BYTES)?;
    push_bounded(
        &mut output,
        if bundle.publication_eligible {
            "true"
        } else {
            "false"
        },
        MAX_BUNDLE_BYTES,
    )?;
    push_bounded(&mut output, ",\"sessionEligible\":", MAX_BUNDLE_BYTES)?;
    push_bounded(
        &mut output,
        if bundle.session_eligible {
            "true"
        } else {
            "false"
        },
        MAX_BUNDLE_BYTES,
    )?;
    push_bounded(&mut output, ",\"sources\":{", MAX_BUNDLE_BYTES)?;
    for (index, (path, source)) in bundle.sources.iter().enumerate() {
        if index != 0 {
            push_bounded(&mut output, ",", MAX_BUNDLE_BYTES)?;
        }
        append_json_string(path, &mut output, MAX_BUNDLE_BYTES)?;
        push_bounded(&mut output, ":", MAX_BUNDLE_BYTES)?;
        append_canonical_json(source, &mut output, MAX_BUNDLE_BYTES)?;
    }
    push_bounded(&mut output, "},\"wireId\":", MAX_BUNDLE_BYTES)?;
    append_json_string(&bundle.wire_id, &mut output, MAX_BUNDLE_BYTES)?;
    push_bounded(&mut output, "}", MAX_BUNDLE_BYTES)?;
    Ok(output)
}

fn append_json_string(value: &str, output: &mut String, maximum: usize) -> Result<(), Error> {
    let encoded =
        serde_json::to_string(value).map_err(|_| admission(ErrorCode::InvalidRepresentation))?;
    push_bounded(output, &encoded, maximum)
}

fn component_paths(
    component: &Component,
    sources: &BTreeMap<String, Value>,
) -> Result<Vec<String>, Error> {
    if component.version != 1 {
        return Err(admission(ErrorCode::UnsupportedDefinition));
    }
    ensure_sorted_unique(&component.source_roots)?;
    component
        .source_roots
        .iter()
        .try_for_each(|root| validate_root(root))?;
    if let Some(path) = &component.source_manifest_path {
        if !component.source_paths.is_empty() || !component.source_roots.is_empty() {
            return Err(admission(ErrorCode::SourceClosureMismatch));
        }
        source_manifest_paths(path, sources)
    } else {
        if component.source_roots.is_empty() {
            return Err(admission(ErrorCode::SourceClosureMismatch));
        }
        ensure_sorted_unique(&component.source_paths)?;
        if component.source_paths.iter().any(|path| {
            !component
                .source_roots
                .iter()
                .any(|root| path_is_within(path, root))
        }) {
            return Err(admission(ErrorCode::SourceClosureMismatch));
        }
        Ok(component.source_paths.clone())
    }
}

fn source_manifest_paths(
    path: &str,
    sources: &BTreeMap<String, Value>,
) -> Result<Vec<String>, Error> {
    validate_path(path)?;
    let source_manifest: SourceManifest = serde_json::from_value(
        sources
            .get(path)
            .ok_or_else(|| admission(ErrorCode::SourceClosureMismatch))?
            .clone(),
    )
    .map_err(|_| admission(ErrorCode::InvalidAuthorityInput))?;
    let expected_id = if path == "spec/v1/foundation/source-manifest.json" {
        "https://licoarc.com/spec/v1/schemas/source-manifest.schema.json".to_owned()
    } else {
        format!("https://licoarc.com/{path}")
    };
    if source_manifest.schema != "https://json-schema.org/draft/2020-12/schema"
        || source_manifest.id != expected_id
        || !source_manifest.manifest_version.starts_with("licoarc.")
        || source_manifest.lifecycle != "Candidate"
        || source_manifest
            .artifact_version
            .as_deref()
            .is_some_and(str::is_empty)
        || source_manifest
            .contract_version
            .as_deref()
            .is_some_and(str::is_empty)
        || source_manifest
            .definition_status
            .as_deref()
            .is_some_and(|value| value != "COMPLETE")
        || source_manifest.session_eligible == Some(true)
        || source_manifest
            .representation
            .as_deref()
            .is_some_and(str::is_empty)
        || source_manifest
            .digest_algorithm
            .as_deref()
            .is_some_and(|value| value != "sha256")
        || source_manifest.sorted == Some(false)
        || source_manifest
            .undeclared_files
            .as_deref()
            .is_some_and(|v| v != "reject")
        || source_manifest
            .symlinks
            .as_deref()
            .is_some_and(|v| v != "reject")
        || source_manifest.aggregate_admission_pending == Some(false)
        || source_manifest.semantic_sources_complete == Some(false)
    {
        return Err(admission(ErrorCode::SourceClosureMismatch));
    }
    ensure_sorted_unique(&source_manifest.source_roots)?;
    source_manifest
        .source_roots
        .iter()
        .try_for_each(|root| validate_root(root))?;
    ensure_sorted_unique(&source_manifest.sources)?;
    ensure_sorted_unique(&source_manifest.additional_sources)?;
    ensure_sorted_unique(&source_manifest.dependency_manifests)?;
    if source_manifest
        .dependency_manifests
        .iter()
        .any(|path| !sources.contains_key(path))
    {
        return Err(admission(ErrorCode::SourceClosureMismatch));
    }
    let source_set: BTreeSet<_> = source_manifest.sources.iter().collect();
    if source_manifest
        .additional_sources
        .iter()
        .any(|source| source_set.contains(source))
    {
        return Err(admission(ErrorCode::SourceClosureMismatch));
    }
    if !source_manifest.source_roots.is_empty()
        && source_manifest.sources.iter().any(|path| {
            !source_manifest
                .source_roots
                .iter()
                .any(|root| path_is_within(path, root))
        })
    {
        return Err(admission(ErrorCode::SourceClosureMismatch));
    }
    let mut paths = BTreeSet::from([path.to_owned()]);
    paths.extend(source_manifest.sources);
    paths.extend(source_manifest.additional_sources);
    Ok(paths.into_iter().collect())
}

fn verify_component_digest(
    paths: &[String],
    expected: &str,
    sources: &BTreeMap<String, Value>,
) -> Result<(), Error> {
    let content: Vec<Value> = paths
        .iter()
        .map(|path| {
            let source = sources
                .get(path)
                .ok_or_else(|| admission(ErrorCode::SourceClosureMismatch))?;
            Ok(serde_json::json!({"path": path, "source": source}))
        })
        .collect::<Result<_, Error>>()?;
    let actual = hex(&digest(canonical_json(&Value::Array(content))?.as_bytes()));
    if actual != expected {
        return Err(admission(ErrorCode::DigestMismatch));
    }
    Ok(())
}

struct AdmissionFacts {
    case_count: usize,
    operation_ids: Vec<String>,
    protection_bounds: BTreeMap<String, u64>,
}

fn verify_current_stable_sources(
    sources: &BTreeMap<String, Value>,
    manifest: &LineManifest,
    capability_ids: &[String],
    capability_semantic_ids: &[String],
) -> Result<AdmissionFacts, Error> {
    let lines = source_object(sources, "spec/protocol-lines.json")?;
    let profiles = source_object(sources, "spec/protection-profiles.json")?;
    let claims = source_object(sources, "spec/v1/security/claims.json")?;
    let bindings = source_object(sources, "spec/v1/security/formal-bindings.json")?;
    let line_records = lines
        .get("lines")
        .and_then(Value::as_array)
        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
    let mut matching_lines = line_records.iter().filter(|value| {
        value.get("wireId").and_then(Value::as_str) == Some("licoarc.protocol-line.v1")
            && value.get("generation").and_then(Value::as_u64) == Some(1)
    });
    let line = matching_lines
        .next()
        .and_then(Value::as_object)
        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
    if line_records.len() != 1 || matching_lines.next().is_some() {
        return Err(admission(ErrorCode::UnsupportedDefinition));
    }
    let line_capabilities = string_array(line.get("mandatoryCapabilities"))?;
    let line_defined = string_array(line.get("definedCapabilities"))?;
    let line_profiles = string_array(line.get("protectionProfileIds"))?;
    let line_claims = string_array(line.get("stableClaimIds"))?;
    if line.get("protocolLineId").and_then(Value::as_str) != Some(EXPECTED_LINE_ID)
        || line.get("definitionStatus").and_then(Value::as_str) != Some("COMPLETE")
        || line.get("lifecycle").and_then(Value::as_str) != Some("Candidate")
        || line.get("sessionEligible").and_then(Value::as_bool) != Some(true)
        || line.get("publicationEligible").and_then(Value::as_bool) != Some(false)
        || line
            .get("blockers")
            .and_then(Value::as_array)
            .is_none_or(|v| !v.is_empty())
        || line_capabilities != capability_ids
        || line_defined != capability_ids
        || line_profiles != [EXPECTED_PROFILE_ID]
        || line_claims != manifest.stable_claim_ids
    {
        return Err(admission(ErrorCode::UnsupportedDefinition));
    }

    let profile_records = profiles
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
    let active_ids = string_array(profiles.get("activeProfileIds"))?;
    if profile_records.len() != 1 || active_ids != [EXPECTED_PROFILE_ID] {
        return Err(admission(ErrorCode::UnknownProfile));
    }
    let profile = profile_records[0]
        .as_object()
        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
    let required_claims = string_array(profile.get("requiredClaimIds"))?;
    let stable_non_claims = string_array(profile.get("stableNonClaimIds"))?;
    if profile.get("profileId").and_then(Value::as_str) != Some(EXPECTED_PROFILE_ID)
        || profile.get("profileLocator").and_then(Value::as_str) != Some("stable-core")
        || profile.get("generation").and_then(Value::as_u64) != Some(1)
        || profile.get("definitionStatus").and_then(Value::as_str) != Some("COMPLETE")
        || profile.get("lifecycle").and_then(Value::as_str) != Some("Candidate")
        || profile.get("sessionEligible").and_then(Value::as_bool) != Some(true)
        || profile.get("publicationEligible").and_then(Value::as_bool) != Some(false)
        || profile
            .get("blockers")
            .and_then(Value::as_array)
            .is_none_or(|v| !v.is_empty())
        || required_claims.is_empty()
        || stable_non_claims.is_empty()
    {
        return Err(admission(ErrorCode::LineNotEligible));
    }

    verify_security(
        claims,
        bindings,
        &manifest.stable_claim_ids,
        &required_claims,
        sources,
    )?;
    verify_profile_identity(sources, &required_claims, &stable_non_claims)?;
    verify_line_identity(manifest, capability_semantic_ids, &line_claims)?;
    let protection_bounds = verify_protection_bounds(sources)?;
    let (case_count, operation_ids) = verify_conformance(sources, manifest, capability_ids)?;
    Ok(AdmissionFacts {
        case_count,
        operation_ids,
        protection_bounds,
    })
}

fn verify_security(
    claims: &serde_json::Map<String, Value>,
    bindings: &serde_json::Map<String, Value>,
    stable_claims: &[String],
    required_claims: &[String],
    sources: &BTreeMap<String, Value>,
) -> Result<(), Error> {
    let claim_values = claims
        .get("claims")
        .and_then(Value::as_array)
        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
    let mut claim_ids = Vec::with_capacity(claim_values.len());
    for claim in claim_values {
        let claim = claim
            .as_object()
            .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
        if claim.get("status").and_then(Value::as_str) != Some("proved")
            || claim.get("proofModel").and_then(Value::as_str).is_none()
            || claim.get("proofLemma").and_then(Value::as_str).is_none()
            || claim.get("counterexampleStatus").and_then(Value::as_str)
                != Some("no-counterexample-found")
        {
            return Err(admission(ErrorCode::SecurityClaimUnproved));
        }
        claim_ids.push(
            claim
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?
                .to_owned(),
        );
    }
    ensure_sorted_unique(&claim_ids)?;
    if claim_ids != stable_claims || required_claims.iter().any(|id| !claim_ids.contains(id)) {
        return Err(admission(ErrorCode::SecurityClaimUnproved));
    }
    let binding_values = bindings
        .get("bindings")
        .and_then(Value::as_array)
        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
    if bindings.get("status").and_then(Value::as_str) != Some("complete")
        || binding_values.is_empty()
    {
        return Err(admission(ErrorCode::SecurityClaimUnproved));
    }
    let required_kinds = string_array(bindings.get("requiredKinds"))?;
    let mut binding_ids = BTreeSet::new();
    let mut bound_claims = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    for binding in binding_values {
        let binding = binding
            .as_object()
            .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
        let binding_id = required_string(binding, "bindingId")?;
        let claim_id = required_string(binding, "claimId")?;
        let kind = required_string(binding, "kind")?;
        let authority_path = required_string(binding, "authorityPath")?;
        let authority_digest = required_string(binding, "authorityDigest")?;
        if !binding_ids.insert(binding_id)
            || !claim_ids.iter().any(|id| id == claim_id)
            || !sources.contains_key(authority_path)
        {
            return Err(admission(ErrorCode::SecurityClaimUnproved));
        }
        validate_digest_text(authority_digest)?;
        bound_claims.insert(claim_id);
        kinds.insert(kind);
    }
    if bound_claims.len() != claim_ids.len()
        || kinds != required_kinds.iter().map(String::as_str).collect()
    {
        return Err(admission(ErrorCode::SecurityClaimUnproved));
    }
    Ok(())
}

fn verify_profile_identity(
    sources: &BTreeMap<String, Value>,
    stable_claims: &[String],
    stable_non_claims: &[String],
) -> Result<(), Error> {
    let descriptor = source_object(sources, "spec/v1/protection/profile.json")?;
    let semantic_source_paths = descriptor
        .get("semanticSources")
        .and_then(Value::as_object)
        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
    let mut semantic_sources = serde_json::Map::new();
    for (role, path) in semantic_source_paths {
        let path = path
            .as_str()
            .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
        let source = sources
            .get(path)
            .ok_or_else(|| admission(ErrorCode::SourceClosureMismatch))?;
        semantic_sources.insert(role.clone(), source.clone());
    }
    let actual = compute_profile_content_identity(
        descriptor,
        &semantic_sources,
        stable_claims,
        stable_non_claims,
        &crate::provider::RustCryptoProvider,
    )?;
    if hex(&actual) != EXPECTED_PROFILE_ID
        || descriptor.get("contentIdentity").and_then(Value::as_str) != Some(EXPECTED_PROFILE_ID)
    {
        return Err(admission(ErrorCode::ContentIdentityMismatch));
    }
    Ok(())
}

pub(crate) fn compute_profile_content_identity(
    descriptor: &serde_json::Map<String, Value>,
    semantic_sources: &serde_json::Map<String, Value>,
    stable_claims: &[String],
    stable_non_claims: &[String],
    provider: &dyn DigestProvider,
) -> Result<[u8; 32], Error> {
    let mut roles: Vec<_> = semantic_sources
        .iter()
        .filter(|(role, _)| role.as_str() != "authorityVectors")
        .collect();
    roles.sort_by_key(|(role, _)| role.as_str());
    if roles.is_empty()
        || roles.len() > 32
        || stable_claims.is_empty()
        || stable_non_claims.is_empty()
        || stable_claims.windows(2).any(|pair| pair[0] >= pair[1])
        || stable_non_claims.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(admission(ErrorCode::ContentIdentityMismatch));
    }
    let mut encoded_sources = Vec::with_capacity(roles.len());
    for (role, source) in roles {
        let bytes = if let Some(text) = source.as_str() {
            text.strip_prefix("base64:").map_or_else(
                || {
                    text.ends_with('\n')
                        .then(|| text.as_bytes().to_vec())
                        .filter(|_| !text.contains('\r') && !text.contains('\0'))
                        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))
                },
                |_| Err(admission(ErrorCode::InvalidAuthorityInput)),
            )?
        } else {
            canonical_json(source)?.into_bytes()
        };
        encoded_sources.push(SemanticCbor::Array(vec![
            SemanticCbor::Text(role.clone()),
            SemanticCbor::Bytes(bytes),
        ]));
    }
    let projection = SemanticCbor::Array(vec![
        SemanticCbor::Text("ProtectionProfileSemanticProjectionV1".to_owned()),
        SemanticCbor::Text(required_string(descriptor, "profileSemanticVersion")?.to_owned()),
        SemanticCbor::Bool(
            descriptor
                .get("indivisible")
                .and_then(Value::as_bool)
                .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?,
        ),
        SemanticCbor::Bool(
            descriptor
                .get("componentNegotiation")
                .and_then(Value::as_bool)
                .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?,
        ),
        SemanticCbor::Text(required_string(descriptor, "fallback")?.to_owned()),
        SemanticCbor::Array(encoded_sources),
        text_array(stable_claims),
        text_array(stable_non_claims),
    ]);
    let bytes = semantic_bytes(b"LICOARC/PROFILE-CONTENT-IDENTITY/V1\0", &projection);
    Ok(provider.sha256(&bytes))
}

fn verify_line_identity(
    manifest: &LineManifest,
    capability_semantic_ids: &[String],
    stable_claims: &[String],
) -> Result<(), Error> {
    let session_rules = serde_json::json!({
        "handshakeBinding": manifest.handshake_binding,
        "sessionLock": manifest.session_lock,
        "translationPolicy": manifest.translation_policy,
    });
    let mut capabilities = capability_semantic_ids.to_vec();
    capabilities.sort();
    let projection = SemanticCbor::Array(vec![
        SemanticCbor::Text("ProtocolLineSemanticProjectionV1".to_owned()),
        SemanticCbor::Unsigned(manifest.generation),
        text_array(&capabilities),
        text_array(&[EXPECTED_PROFILE_ID.to_owned()]),
        text_array(stable_claims),
        SemanticCbor::Bytes(canonical_json(&session_rules)?.into_bytes()),
    ]);
    let actual = semantic_digest(b"LICOARC/PROTOCOL-LINE-CONTENT-IDENTITY/V1\0", &projection);
    if hex(&actual) != EXPECTED_LINE_ID {
        return Err(admission(ErrorCode::ContentIdentityMismatch));
    }
    Ok(())
}

fn verify_protection_bounds(
    sources: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, u64>, Error> {
    let bounds_source = source_object(sources, "spec/v1/protection/bounds.json")?;
    let bounds = bounds_source
        .get("bounds")
        .and_then(Value::as_object)
        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
    let admitted: BTreeMap<_, _> = bounds
        .iter()
        .map(|(name, value)| {
            value
                .as_u64()
                .map(|value| (name.clone(), value))
                .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))
        })
        .collect::<Result<_, Error>>()?;
    if admitted
        .get("MAX_PLAINTEXT_BYTES")
        .and_then(|value| value.checked_add(64))
        != Some(admitted["MAX_PROTECTED_PACKET_BYTES"])
        || admitted["MAX_FIRST_PACKET_BYTES"] > admitted["MAX_HANDSHAKE_BYTES"]
        || admitted.get("MAX_SESSION_ACCEPT_BYTES").copied()
            != Some(crate::protection::MAX_SESSION_ACCEPT_BYTES as u64)
        || !admitted.contains_key("MAX_RECORD_AAD_BYTES")
        || !admitted.contains_key("MAX_RATCHET_HEADER_BYTES")
        || 22_u64
            .checked_add(32)
            .and_then(|v| v.checked_add(admitted["MAX_RATCHET_HEADER_BYTES"]))
            != Some(admitted["MAX_RECORD_AAD_BYTES"])
        || admitted["MAX_SKIP_PER_RECORD"] > admitted["MAX_SKIPPED_KEYS"]
        || admitted["MAX_COMMITTED_HANDSHAKE_REPLAY_BINDINGS"] != admitted["MAX_ACTIVE_SESSIONS"]
        || admitted["MAX_PREKEY_PAIR_SEQUENCE"] > admitted["MAX_STATE_GENERATION"]
    {
        return Err(admission(ErrorCode::BoundExceeded));
    }
    Ok(admitted)
}

fn verify_conformance(
    sources: &BTreeMap<String, Value>,
    manifest: &LineManifest,
    capability_ids: &[String],
) -> Result<(usize, Vec<String>), Error> {
    let aggregate = source_object(sources, "conformance/v1/manifest.json")?;
    let capability_corpora = aggregate
        .get("capabilityCorpora")
        .and_then(Value::as_array)
        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
    let definition_corpora = aggregate
        .get("definitionCorpora")
        .and_then(Value::as_array)
        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
    if aggregate.get("definitionStatus").and_then(Value::as_str) != Some("COMPLETE")
        || aggregate.get("generation").and_then(Value::as_u64) != Some(1)
        || aggregate.get("protocolLineId").and_then(Value::as_str) != Some(EXPECTED_LINE_ID)
        || aggregate
            .get("absentCorpora")
            .and_then(Value::as_array)
            .is_none_or(|v| !v.is_empty())
        || capability_corpora.len() != capability_ids.len()
        || definition_corpora.len() != 1
    {
        return Err(admission(ErrorCode::UnsupportedConformanceCase));
    }
    let mut owners = Vec::new();
    let mut corpus_paths = Vec::new();
    for corpus in capability_corpora {
        let corpus = corpus
            .as_object()
            .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
        if corpus.get("complete").and_then(Value::as_bool) != Some(true)
            || corpus.get("definitionStatus").and_then(Value::as_str) != Some("COMPLETE")
        {
            return Err(admission(ErrorCode::UnsupportedConformanceCase));
        }
        owners.push(required_string(corpus, "capabilityId")?.to_owned());
        corpus_paths.push(required_string(corpus, "manifestPath")?.to_owned());
    }
    if owners != capability_ids {
        return Err(admission(ErrorCode::UnsupportedConformanceCase));
    }
    let security = definition_corpora[0]
        .as_object()
        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
    if required_string(security, "definitionId")? != "security-accounting"
        || security.get("complete").and_then(Value::as_bool) != Some(true)
        || security.get("definitionStatus").and_then(Value::as_str) != Some("COMPLETE")
    {
        return Err(admission(ErrorCode::UnsupportedConformanceCase));
    }
    corpus_paths.push(required_string(security, "manifestPath")?.to_owned());

    let mut total = 0_usize;
    let mut operations = BTreeSet::new();
    for corpus_path in corpus_paths {
        let corpus = source_object(sources, &corpus_path)?;
        let count = corpus
            .get("caseCount")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
        total = total
            .checked_add(count)
            .ok_or_else(|| admission(ErrorCode::BoundExceeded))?;
        for operation in string_array(corpus.get("operationIds"))? {
            operations.insert(operation);
        }
        let envelope_paths = string_array(corpus.get("envelopePaths"))?;
        if envelope_paths.len() != 1 {
            return Err(admission(ErrorCode::UnsupportedConformanceCase));
        }
        let envelope = source_object(sources, &envelope_paths[0])?;
        let cases = envelope
            .get("cases")
            .and_then(Value::as_array)
            .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?;
        let mut ids = BTreeSet::new();
        if cases.len() != count
            || cases.iter().any(|case| {
                case.get("id")
                    .and_then(Value::as_str)
                    .is_none_or(|id| !ids.insert(id))
            })
        {
            return Err(admission(ErrorCode::ConformanceMismatch));
        }
    }
    let operation_ids: Vec<_> = operations.into_iter().collect();
    if total == 0 || operation_ids.is_empty() {
        return Err(admission(ErrorCode::ConformanceMismatch));
    }
    if manifest.protection_profile_ids != [EXPECTED_PROFILE_ID] {
        return Err(admission(ErrorCode::UnknownProfile));
    }
    Ok((total, operation_ids))
}

enum SemanticCbor {
    Unsigned(u64),
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
    Array(Vec<SemanticCbor>),
}

fn semantic_digest(domain: &[u8], value: &SemanticCbor) -> [u8; 32] {
    digest(&semantic_bytes(domain, value))
}

fn semantic_bytes(domain: &[u8], value: &SemanticCbor) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(domain);
    encode_semantic_cbor(value, &mut bytes);
    bytes
}

fn encode_semantic_cbor(value: &SemanticCbor, output: &mut Vec<u8>) {
    match value {
        SemanticCbor::Unsigned(value) => cbor_head(0, *value, output),
        SemanticCbor::Bytes(value) => {
            cbor_head(2, value.len() as u64, output);
            output.extend_from_slice(value);
        }
        SemanticCbor::Text(value) => {
            cbor_head(3, value.len() as u64, output);
            output.extend_from_slice(value.as_bytes());
        }
        SemanticCbor::Bool(value) => output.push(if *value { 0xf5 } else { 0xf4 }),
        SemanticCbor::Array(values) => {
            cbor_head(4, values.len() as u64, output);
            for value in values {
                encode_semantic_cbor(value, output);
            }
        }
    }
}

fn cbor_head(major: u8, value: u64, output: &mut Vec<u8>) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | value as u8),
        24..=0xff => output.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            output.push(prefix | 25);
            output.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 26);
            output.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn text_array(values: &[String]) -> SemanticCbor {
    SemanticCbor::Array(values.iter().cloned().map(SemanticCbor::Text).collect())
}

fn string_array(value: Option<&Value>) -> Result<Vec<String>, Error> {
    value
        .and_then(Value::as_array)
        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))
        })
        .collect()
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, Error> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))
}

fn validate_digest_text(value: &str) -> Result<(), Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(admission(ErrorCode::InvalidAuthorityInput));
    }
    Ok(())
}

fn decode_digest(value: &str) -> Result<[u8; 32], Error> {
    validate_digest_text(value)?;
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(bytes)
}

fn hex_nibble(value: u8) -> Result<u8, Error> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(admission(ErrorCode::InvalidAuthorityInput)),
    }
}

fn source_object<'a>(
    sources: &'a BTreeMap<String, Value>,
    path: &str,
) -> Result<&'a serde_json::Map<String, Value>, Error> {
    sources
        .get(path)
        .and_then(Value::as_object)
        .ok_or_else(|| admission(ErrorCode::InvalidAuthorityInput))
}

fn validate_path(path: &str) -> Result<(), Error> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || !(path.ends_with(".json") || path.ends_with(".cddl") || path.ends_with(".md"))
    {
        return Err(admission(ErrorCode::InvalidAuthorityInput));
    }
    Ok(())
}

fn validate_root(root: &str) -> Result<(), Error> {
    if root.is_empty()
        || root.starts_with('/')
        || root.contains('\\')
        || root
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(admission(ErrorCode::InvalidAuthorityInput));
    }
    Ok(())
}

fn path_is_within(path: &str, root: &str) -> bool {
    path.strip_prefix(root)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn ensure_sorted_unique<T: Ord>(values: &[T]) -> Result<(), Error> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(admission(ErrorCode::SourceClosureMismatch));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct JsonLimits {
    max_bytes: usize,
    max_depth: usize,
    max_array_items: usize,
    max_object_members: usize,
    max_string_bytes: usize,
}

fn source_json_limits(path: &str) -> JsonLimits {
    if path.ends_with("/cases.json") {
        CONFORMANCE_JSON_LIMITS
    } else if path == "spec/v1/security/formal-bindings.json" {
        SECURITY_BINDINGS_JSON_LIMITS
    } else {
        FOUNDATION_JSON_LIMITS
    }
}

fn parse_bundle(bytes: &[u8]) -> Result<Bundle, Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let bundle = BundleSeed
        .deserialize(&mut deserializer)
        .map_err(restricted_json_error)?;
    deserializer
        .end()
        .map_err(|_| admission(ErrorCode::InvalidAuthorityInput))?;
    Ok(bundle)
}

#[cfg(test)]
pub(crate) fn parse_restricted_json(bytes: &[u8]) -> Result<Value, Error> {
    parse_restricted_json_detailed(bytes).map_err(RestrictedJsonFailure::into_error)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestrictedJsonFailure {
    BoundExceeded,
    DuplicateMember,
    TrailingBytes,
    Invalid,
}

#[cfg(test)]
impl RestrictedJsonFailure {
    const fn into_error(self) -> Error {
        match self {
            Self::BoundExceeded => admission(ErrorCode::BoundExceeded),
            Self::DuplicateMember | Self::TrailingBytes | Self::Invalid => {
                admission(ErrorCode::InvalidAuthorityInput)
            }
        }
    }
}

pub(crate) fn parse_restricted_json_detailed(bytes: &[u8]) -> Result<Value, RestrictedJsonFailure> {
    parse_restricted_json_with_limits_detailed(bytes, FOUNDATION_JSON_LIMITS)
}

#[cfg(test)]
fn parse_restricted_json_with_limits(bytes: &[u8], limits: JsonLimits) -> Result<Value, Error> {
    parse_restricted_json_with_limits_detailed(bytes, limits)
        .map_err(RestrictedJsonFailure::into_error)
}

fn parse_restricted_json_with_limits_detailed(
    bytes: &[u8],
    limits: JsonLimits,
) -> Result<Value, RestrictedJsonFailure> {
    if bytes.len() > limits.max_bytes {
        return Err(RestrictedJsonFailure::BoundExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = RestrictedValueSeed { depth: 0, limits }
        .deserialize(&mut deserializer)
        .map_err(classify_restricted_json_error)?;
    deserializer
        .end()
        .map_err(|_| RestrictedJsonFailure::TrailingBytes)?;
    Ok(value)
}

fn classify_restricted_json_error(error: serde_json::Error) -> RestrictedJsonFailure {
    let message = error.to_string();
    if message.contains("bound exceeded") {
        RestrictedJsonFailure::BoundExceeded
    } else if message.contains("duplicate member") {
        RestrictedJsonFailure::DuplicateMember
    } else {
        RestrictedJsonFailure::Invalid
    }
}

fn restricted_json_error(error: serde_json::Error) -> Error {
    if error.to_string().contains("bound exceeded") {
        admission(ErrorCode::BoundExceeded)
    } else {
        admission(ErrorCode::InvalidAuthorityInput)
    }
}

pub(crate) fn canonical_json(value: &Value) -> Result<String, Error> {
    canonical_json_bounded(value, MAX_SOURCE_BYTES)
}

fn canonical_json_bounded(value: &Value, maximum: usize) -> Result<String, Error> {
    let mut output = String::new();
    append_canonical_json(value, &mut output, maximum)?;
    Ok(output)
}

fn append_canonical_json(value: &Value, output: &mut String, maximum: usize) -> Result<(), Error> {
    match value {
        Value::Null => push_bounded(output, "null", maximum),
        Value::Bool(value) => push_bounded(output, if *value { "true" } else { "false" }, maximum),
        Value::Number(value) => {
            let number = if value.is_i64() {
                value
                    .as_i64()
                    .filter(|value| value.unsigned_abs() <= MAX_INTEGER)
                    .map(|value| value.to_string())
            } else if value.is_u64() {
                value
                    .as_u64()
                    .filter(|value| *value <= MAX_INTEGER)
                    .map(|value| value.to_string())
            } else {
                value.as_f64().and_then(|value| {
                    (value.is_finite()
                        && (value.fract() != 0.0 || value.abs() <= MAX_INTEGER as f64))
                        .then(|| {
                            if value == 0.0 {
                                "0".to_owned()
                            } else {
                                ryu_js::Buffer::new().format_finite(value).to_owned()
                            }
                        })
                })
            }
            .ok_or_else(|| admission(ErrorCode::InvalidRepresentation))?;
            push_bounded(output, &number, maximum)
        }
        Value::String(value) => {
            let encoded = serde_json::to_string(value)
                .map_err(|_| admission(ErrorCode::InvalidRepresentation))?;
            push_bounded(output, &encoded, maximum)
        }
        Value::Array(values) => {
            push_bounded(output, "[", maximum)?;
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    push_bounded(output, ",", maximum)?;
                }
                append_canonical_json(value, output, maximum)?;
            }
            push_bounded(output, "]", maximum)
        }
        Value::Object(values) => {
            push_bounded(output, "{", maximum)?;
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    push_bounded(output, ",", maximum)?;
                }
                let encoded_key = serde_json::to_string(key)
                    .map_err(|_| admission(ErrorCode::InvalidRepresentation))?;
                push_bounded(output, &encoded_key, maximum)?;
                push_bounded(output, ":", maximum)?;
                append_canonical_json(value, output, maximum)?;
            }
            push_bounded(output, "}", maximum)
        }
    }
}

fn push_bounded(output: &mut String, value: &str, maximum: usize) -> Result<(), Error> {
    let next = output
        .len()
        .checked_add(value.len())
        .filter(|length| *length <= maximum)
        .ok_or_else(|| admission(ErrorCode::BoundExceeded))?;
    output
        .try_reserve(next - output.len())
        .map_err(|_| admission(ErrorCode::BoundExceeded))?;
    output.push_str(value);
    Ok(())
}

fn validate_json_source(value: &Value, depth: usize, limits: JsonLimits) -> Result<(), Error> {
    if depth > limits.max_depth {
        return Err(admission(ErrorCode::BoundExceeded));
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
        Value::String(value) if value.len() <= limits.max_string_bytes => Ok(()),
        Value::String(_) => Err(admission(ErrorCode::BoundExceeded)),
        Value::Array(values) if values.len() <= limits.max_array_items => values
            .iter()
            .try_for_each(|value| validate_json_source(value, depth + 1, limits)),
        Value::Array(_) => Err(admission(ErrorCode::BoundExceeded)),
        Value::Object(values)
            if values.len() <= limits.max_object_members
                && values
                    .keys()
                    .all(|key| key.len() <= limits.max_string_bytes) =>
        {
            values
                .values()
                .try_for_each(|value| validate_json_source(value, depth + 1, limits))
        }
        Value::Object(_) => Err(admission(ErrorCode::BoundExceeded)),
    }
}

pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    fixed_sha256(bytes)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

const fn admission(code: ErrorCode) -> Error {
    Error::terminal(code, Stage::Admission)
}

struct BundleSeed;

impl<'de> DeserializeSeed<'de> for BundleSeed {
    type Value = Bundle;

    fn deserialize<D>(self, deserializer: D) -> Result<Bundle, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(BundleVisitor)
    }
}

struct BundleVisitor;

impl<'de> Visitor<'de> for BundleVisitor {
    type Value = Bundle;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the closed LicoArc authority bundle envelope")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Bundle, A::Error> {
        let mut artifact_version = None;
        let mut wire_id = None;
        let mut generation = None;
        let mut lifecycle = None;
        let mut definition_status = None;
        let mut session_eligible = None;
        let mut publication_eligible = None;
        let mut digest_algorithm = None;
        let mut sources = None;
        let mut digest = None;

        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 64 {
                return Err(serde::de::Error::custom(
                    "bundle member name bound exceeded",
                ));
            }
            match key.as_str() {
                "artifactVersion" => set_once(
                    &mut artifact_version,
                    map.next_value_seed(BoundedStringSeed { maximum: 128 })?,
                )?,
                "wireId" => set_once(
                    &mut wire_id,
                    map.next_value_seed(BoundedStringSeed { maximum: 128 })?,
                )?,
                "generation" => set_once(&mut generation, map.next_value()?)?,
                "lifecycle" => set_once(
                    &mut lifecycle,
                    map.next_value_seed(BoundedStringSeed { maximum: 32 })?,
                )?,
                "definitionStatus" => set_once(
                    &mut definition_status,
                    map.next_value_seed(BoundedStringSeed { maximum: 32 })?,
                )?,
                "sessionEligible" => set_once(&mut session_eligible, map.next_value()?)?,
                "publicationEligible" => set_once(&mut publication_eligible, map.next_value()?)?,
                "digestAlgorithm" => set_once(
                    &mut digest_algorithm,
                    map.next_value_seed(BoundedStringSeed { maximum: 32 })?,
                )?,
                "sources" => set_once(&mut sources, map.next_value_seed(SourcesSeed)?)?,
                "digest" => set_once(
                    &mut digest,
                    map.next_value_seed(BoundedStringSeed { maximum: 64 })?,
                )?,
                _ => return Err(serde::de::Error::unknown_field(&key, BUNDLE_FIELDS)),
            }
        }

        Ok(Bundle {
            artifact_version: artifact_version
                .ok_or_else(|| serde::de::Error::missing_field("artifactVersion"))?,
            wire_id: wire_id.ok_or_else(|| serde::de::Error::missing_field("wireId"))?,
            generation: generation.ok_or_else(|| serde::de::Error::missing_field("generation"))?,
            lifecycle: lifecycle.ok_or_else(|| serde::de::Error::missing_field("lifecycle"))?,
            definition_status: definition_status
                .ok_or_else(|| serde::de::Error::missing_field("definitionStatus"))?,
            session_eligible: session_eligible
                .ok_or_else(|| serde::de::Error::missing_field("sessionEligible"))?,
            publication_eligible: publication_eligible
                .ok_or_else(|| serde::de::Error::missing_field("publicationEligible"))?,
            digest_algorithm: digest_algorithm
                .ok_or_else(|| serde::de::Error::missing_field("digestAlgorithm"))?,
            sources: sources.ok_or_else(|| serde::de::Error::missing_field("sources"))?,
            digest: digest.ok_or_else(|| serde::de::Error::missing_field("digest"))?,
        })
    }
}

const BUNDLE_FIELDS: &[&str] = &[
    "artifactVersion",
    "wireId",
    "generation",
    "lifecycle",
    "definitionStatus",
    "sessionEligible",
    "publicationEligible",
    "digestAlgorithm",
    "sources",
    "digest",
];

fn set_once<T, E: serde::de::Error>(slot: &mut Option<T>, value: T) -> Result<(), E> {
    if slot.replace(value).is_some() {
        return Err(E::custom("duplicate member"));
    }
    Ok(())
}

struct BoundedStringSeed {
    maximum: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedStringSeed {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<String, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_string(BoundedStringVisitor {
            maximum: self.maximum,
        })
    }
}

struct BoundedStringVisitor {
    maximum: usize,
}

impl Visitor<'_> for BoundedStringVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded UTF-8 string")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<String, E> {
        if value.len() > self.maximum {
            return Err(E::custom("string bound exceeded"));
        }
        Ok(value.to_owned())
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<String, E> {
        if value.len() > self.maximum {
            return Err(E::custom("string bound exceeded"));
        }
        Ok(value)
    }
}

struct SourcesSeed;

impl<'de> DeserializeSeed<'de> for SourcesSeed {
    type Value = BTreeMap<String, Value>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(SourcesVisitor)
    }
}

struct SourcesVisitor;

impl<'de> Visitor<'de> for SourcesVisitor {
    type Value = BTreeMap<String, Value>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded source map")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        if map.size_hint().is_some_and(|size| size > MAX_SOURCES) {
            return Err(serde::de::Error::custom("source count bound exceeded"));
        }
        let mut sources = BTreeMap::new();
        loop {
            if sources.len() == MAX_SOURCES {
                if map.next_key::<IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("source count bound exceeded"));
                }
                break;
            }
            let Some(path) = map.next_key::<String>()? else {
                break;
            };
            if validate_path(&path).is_err() || sources.contains_key(&path) {
                return Err(serde::de::Error::custom("invalid or duplicate source path"));
            }
            let value = if path.ends_with(".json") {
                map.next_value_seed(RestrictedValueSeed {
                    depth: 0,
                    limits: source_json_limits(&path),
                })?
            } else {
                Value::String(map.next_value_seed(BoundedStringSeed {
                    maximum: MAX_SOURCE_BYTES,
                })?)
            };
            sources.insert(path, value);
        }
        Ok(sources)
    }
}

#[derive(Clone, Copy)]
struct RestrictedValueSeed {
    depth: usize,
    limits: JsonLimits,
}

impl<'de> DeserializeSeed<'de> for RestrictedValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > self.limits.max_depth {
            return Err(serde::de::Error::custom("JSON nesting bound exceeded"));
        }
        deserializer.deserialize_any(RestrictedVisitor {
            depth: self.depth,
            limits: self.limits,
        })
    }
}

struct RestrictedVisitor {
    depth: usize,
    limits: JsonLimits,
}

impl<'de> Visitor<'de> for RestrictedVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded restricted JSON without duplicate members")
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        if value.unsigned_abs() > MAX_INTEGER {
            return Err(E::custom("unsafe integral number"));
        }
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        if value > MAX_INTEGER {
            return Err(E::custom("unsafe integral number"));
        }
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
        if value.fract() == 0.0 && value.abs() > MAX_INTEGER as f64 {
            return Err(E::custom("unsafe integral number"));
        }
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite numbers are forbidden"))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        if value.len() > self.limits.max_string_bytes {
            return Err(E::custom("string bound exceeded"));
        }
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        if value.len() > self.limits.max_string_bytes {
            return Err(E::custom("string bound exceeded"));
        }
        Ok(Value::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        if sequence
            .size_hint()
            .is_some_and(|size| size > self.limits.max_array_items)
        {
            return Err(serde::de::Error::custom("array bound exceeded"));
        }
        let mut values = Vec::with_capacity(
            sequence
                .size_hint()
                .unwrap_or_default()
                .min(self.limits.max_array_items),
        );
        let seed = RestrictedValueSeed {
            depth: self.depth + 1,
            limits: self.limits,
        };
        loop {
            if values.len() == self.limits.max_array_items {
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("array bound exceeded"));
                }
                break;
            }
            let Some(value) = sequence.next_element_seed(seed)? else {
                break;
            };
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if map
            .size_hint()
            .is_some_and(|size| size > self.limits.max_object_members)
        {
            return Err(serde::de::Error::custom("object bound exceeded"));
        }
        let mut values = serde_json::Map::new();
        loop {
            if values.len() == self.limits.max_object_members {
                if map.next_key::<IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("object bound exceeded"));
                }
                break;
            }
            let Some(key) = map.next_key::<String>()? else {
                break;
            };
            if key.len() > self.limits.max_string_bytes {
                return Err(serde::de::Error::custom(
                    "object member name bound exceeded",
                ));
            }
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate member"));
            }
            let value = map.next_value_seed(RestrictedValueSeed {
                depth: self.depth + 1,
                limits: self.limits,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use serde_json::Value;

    use super::{
        CONFORMANCE_JSON_LIMITS, FOUNDATION_JSON_LIMITS, SECURITY_BINDINGS_JSON_LIMITS,
        SnapshotDigest, VerifiedProtocolLine, canonical_json, parse_restricted_json,
        parse_restricted_json_with_limits, validate_json_source,
    };

    #[test]
    fn restricted_json_is_duplicate_safe_and_jcs_ordered() {
        assert!(parse_restricted_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse_restricted_json(br#"{"a":1} false"#).is_err());

        let value =
            parse_restricted_json("{\"\u{e000}\":1,\"\u{10000}\":2,\"number\":1e-6}".as_bytes())
                .unwrap();
        assert_eq!(
            canonical_json(&value).unwrap(),
            "{\"number\":0.000001,\"𐀀\":2,\"\":1}"
        );

        let numbers = parse_restricted_json(
            b"[-0.0,5e-324,1e-27,9.999999999999997e-7,1e-6,333333333.3333333,-0.0000033333333333333333,1424953923781206.25]",
        )
        .unwrap();
        assert_eq!(
            numbers[3].as_f64().unwrap().to_bits(),
            0x3eb0_c6f7_a0b5_ed8c
        );
        assert_eq!(
            canonical_json(&numbers).unwrap(),
            "[0,5e-324,1e-27,9.999999999999997e-7,0.000001,333333333.3333333,-0.0000033333333333333333,1424953923781206.2]"
        );
        assert!(parse_restricted_json(b"9007199254740992").is_err());
        assert!(parse_restricted_json(b"-9007199254740992").is_err());
    }

    #[test]
    fn restricted_json_source_bounds_are_closed() {
        let validate = |value: &Value, limits| validate_json_source(value, 0, limits);
        assert!(validate(&Value::Array(vec![Value::Null; 64]), FOUNDATION_JSON_LIMITS).is_ok());
        assert!(validate(&Value::Array(vec![Value::Null; 65]), FOUNDATION_JSON_LIMITS).is_err());
        assert!(
            validate(
                &Value::Object(
                    (0..64)
                        .map(|index| (index.to_string(), Value::Null))
                        .collect(),
                ),
                FOUNDATION_JSON_LIMITS,
            )
            .is_ok()
        );
        assert!(
            validate(
                &Value::Object(
                    (0..65)
                        .map(|index| (index.to_string(), Value::Null))
                        .collect(),
                ),
                FOUNDATION_JSON_LIMITS,
            )
            .is_err()
        );
        assert!(validate(&Value::String("x".repeat(4_096)), FOUNDATION_JSON_LIMITS,).is_ok());
        assert!(validate(&Value::String("x".repeat(4_097)), FOUNDATION_JSON_LIMITS,).is_err());
        assert!(validate(&Value::String("界".repeat(1_365)), FOUNDATION_JSON_LIMITS,).is_ok());
        assert!(validate(&Value::String("界".repeat(1_366)), FOUNDATION_JSON_LIMITS,).is_err());

        assert!(
            validate(
                &Value::Array(vec![Value::Null; 256]),
                SECURITY_BINDINGS_JSON_LIMITS,
            )
            .is_ok()
        );
        assert!(
            validate(
                &Value::Array(vec![Value::Null; 257]),
                SECURITY_BINDINGS_JSON_LIMITS,
            )
            .is_err()
        );
        assert!(
            validate(
                &Value::Array(vec![Value::Null; 512]),
                CONFORMANCE_JSON_LIMITS,
            )
            .is_ok()
        );
        assert!(
            validate(
                &Value::Array(vec![Value::Null; 513]),
                CONFORMANCE_JSON_LIMITS,
            )
            .is_err()
        );
        assert!(
            validate(
                &Value::String("x".repeat(1_048_576)),
                CONFORMANCE_JSON_LIMITS,
            )
            .is_ok()
        );
        assert!(
            validate(
                &Value::String("x".repeat(1_048_577)),
                CONFORMANCE_JSON_LIMITS,
            )
            .is_err()
        );

        let mut nested = Value::Null;
        for _ in 0..16 {
            nested = Value::Array(vec![nested]);
        }
        assert!(validate(&nested, FOUNDATION_JSON_LIMITS).is_ok());
        nested = Value::Array(vec![nested]);
        assert!(validate(&nested, FOUNDATION_JSON_LIMITS).is_err());

        let exact = format!("[{}]", vec!["null"; 64].join(","));
        assert!(parse_restricted_json(exact.as_bytes()).is_ok());
        let over = format!("[{}]", vec!["null"; 65].join(","));
        assert!(parse_restricted_json(over.as_bytes()).is_err());

        let conformance_object = Value::Object(
            (0..256)
                .map(|index| (index.to_string(), Value::Null))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        );
        let encoded = serde_json::to_vec(&conformance_object).unwrap();
        assert!(parse_restricted_json_with_limits(&encoded, CONFORMANCE_JSON_LIMITS).is_ok());
        let mut over_object = conformance_object.as_object().unwrap().clone();
        over_object.insert("extra".to_owned(), Value::Null);
        let encoded = serde_json::to_vec(&Value::Object(over_object)).unwrap();
        assert!(parse_restricted_json_with_limits(&encoded, CONFORMANCE_JSON_LIMITS).is_err());
    }

    #[test]
    fn verified_line_debug_never_renders_retained_sources() {
        let canary = "authority-source-canary";
        let line = VerifiedProtocolLine {
            snapshot_digest: SnapshotDigest([1; 32]),
            wire_id: canary.to_owned(),
            generation: 1,
            capability_ids: vec![canary.to_owned()],
            protocol_line_id: [2; 32],
            protection_profile_id: [3; 32],
            case_count: 1,
            operation_ids: vec![canary.to_owned()],
            protection_bounds: BTreeMap::new(),
            sources: Arc::new(BTreeMap::from([(
                "spec/source.json".to_owned(),
                Value::String(canary.to_owned()),
            )])),
        };
        let rendered = format!("{line:?}");
        assert!(!rendered.contains(canary));
    }
}
