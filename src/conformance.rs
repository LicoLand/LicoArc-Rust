use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;

use crate::{
    SnapshotDigest, VerifiedProtocolLine,
    error::{Error, ErrorCode, Stage},
    provider::{Provider, fixed_provider},
};

mod executor;

#[derive(Clone)]
pub struct ConformanceCase {
    pub id: String,
    pub corpus_id: String,
    pub operation_id: String,
    input: Value,
    context: Value,
    expected: Expected,
}

impl std::fmt::Debug for ConformanceCase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConformanceCase")
            .field("id", &self.id)
            .field("corpus_id", &self.corpus_id)
            .field("operation_id", &self.operation_id)
            .field("input", &"[REDACTED]")
            .field("context", &"[REDACTED]")
            .field("expected", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
enum Expected {
    Result(Value),
    Error(ExpectedError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ExpectedError {
    code: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionSummary {
    pub declared: usize,
    pub visited: usize,
    pub executed: usize,
    pub passed: usize,
    pub capability_coverage: usize,
    pub operation_coverage: usize,
    pub blocked: usize,
    pub skipped: usize,
    pub source_only: usize,
    pub unmapped: usize,
    pub duplicate: usize,
    pub absent: usize,
    pub surplus: usize,
    pub case_set_digest: [u8; 32],
}

impl ExecutionSummary {
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.declared > 0
            && self.visited == self.declared
            && self.executed == self.declared
            && self.passed == self.declared
            && self.capability_coverage > 0
            && self.operation_coverage > 0
            && self.blocked == 0
            && self.skipped == 0
            && self.source_only == 0
            && self.unmapped == 0
            && self.duplicate == 0
            && self.absent == 0
            && self.surplus == 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceReport {
    pub summary: ExecutionSummary,
}

pub struct ConformanceRegistry {
    cases: Vec<ConformanceCase>,
    snapshot_digest: SnapshotDigest,
    capability_coverage: usize,
    operation_ids: BTreeSet<String>,
}

impl ConformanceRegistry {
    pub fn from_protocol_line(line: &VerifiedProtocolLine) -> Result<Self, Error> {
        let aggregate: Aggregate = value_as(line.source("conformance/v1/manifest.json")?)?;
        if aggregate.schema != "https://licoarc.com/spec/schemas/conformance-manifest.schema.json"
            || aggregate.manifest_version != "licoarc.conformance-manifest.v1"
            || aggregate.wire_id != line.wire_id()
            || aggregate.generation != line.generation()
            || aggregate.protocol_line_id != hex(line.protocol_line_id())
            || aggregate.lifecycle != "Candidate"
            || aggregate.definition_status != "COMPLETE"
            || aggregate.source_closure != "declared-component-source-closures"
            || !aggregate.absent_corpora.is_empty()
            || aggregate.capability_corpora.len() != line.capability_ids().len()
            || aggregate.definition_corpora.len() != 1
        {
            return Err(conformance(ErrorCode::SourceClosureMismatch));
        }

        let mut declared = BTreeMap::new();
        for corpus in aggregate.capability_corpora {
            corpus.validate()?;
            declared.insert(corpus.capability_id, corpus.manifest_path);
        }
        for corpus in aggregate.definition_corpora {
            corpus.validate()?;
            declared.insert(corpus.definition_id, corpus.manifest_path);
        }
        let capability_ids = line
            .capability_ids()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let declared_capabilities = declared
            .keys()
            .filter(|id| id.as_str() != "security-accounting")
            .cloned()
            .collect::<BTreeSet<_>>();
        if declared_capabilities != capability_ids || !declared.contains_key("security-accounting")
        {
            return Err(conformance(ErrorCode::SourceClosureMismatch));
        }

        let mut cases = Vec::new();
        let mut case_ids = BTreeSet::new();
        let mut operation_ids = BTreeSet::new();
        let mut source_bindings = BTreeMap::new();
        for manifest_path in declared.values() {
            load_corpus(
                line,
                manifest_path,
                &mut cases,
                &mut case_ids,
                &mut operation_ids,
                &mut source_bindings,
            )?;
        }
        let admitted_operations = line
            .operation_ids()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if cases.len() != line.conformance_case_count()
            || admitted_operations != operation_ids
            || operation_ids.iter().any(|id| !executor::supports(id))
        {
            return Err(conformance(ErrorCode::SourceClosureMismatch));
        }
        cases
            .sort_by(|left, right| (&left.corpus_id, &left.id).cmp(&(&right.corpus_id, &right.id)));
        Ok(Self {
            cases,
            snapshot_digest: line.snapshot_digest(),
            capability_coverage: line.capability_ids().len(),
            operation_ids,
        })
    }

    #[must_use]
    pub fn cases(&self) -> &[ConformanceCase] {
        &self.cases
    }

    pub fn execute_all(&self, line: &VerifiedProtocolLine) -> Result<ConformanceReport, Error> {
        self.execute_all_with_provider(line, &fixed_provider())
    }

    pub fn execute_all_with_provider(
        &self,
        line: &VerifiedProtocolLine,
        provider: &impl Provider,
    ) -> Result<ConformanceReport, Error> {
        if line.snapshot_digest() != self.snapshot_digest {
            return Err(conformance(ErrorCode::DigestMismatch));
        }
        let declared = self.cases.len();
        let mut visited = 0;
        let mut executed = 0;
        let mut passed = 0;
        let mut visited_operations = BTreeSet::new();
        let mut case_set = Vec::new();
        for case in &self.cases {
            visited += 1;
            // The execution boundary intentionally receives no expected value.
            let actual = executor::execute(
                &case.operation_id,
                &case.input,
                &case.context,
                line,
                provider,
            )?;
            executed += 1;
            if actual != case.expected {
                return Err(conformance(ErrorCode::ConformanceMismatch));
            }
            passed += 1;
            visited_operations.insert(case.operation_id.as_str());
            case_set.extend_from_slice(case.corpus_id.as_bytes());
            case_set.push(0);
            case_set.extend_from_slice(case.id.as_bytes());
            case_set.push(0);
            case_set.extend_from_slice(case.operation_id.as_bytes());
            case_set.push(0xff);
        }
        let summary = ExecutionSummary {
            declared,
            visited,
            executed,
            passed,
            capability_coverage: self.capability_coverage,
            operation_coverage: visited_operations.len(),
            blocked: 0,
            skipped: 0,
            source_only: 0,
            unmapped: 0,
            duplicate: 0,
            absent: declared.saturating_sub(visited),
            surplus: visited.saturating_sub(declared)
                + self
                    .operation_ids
                    .len()
                    .saturating_sub(visited_operations.len()),
            case_set_digest: provider.sha256(&case_set),
        };
        if !summary.complete() {
            return Err(conformance(ErrorCode::ConformanceMismatch));
        }
        Ok(ConformanceReport { summary })
    }
}

fn load_corpus(
    line: &VerifiedProtocolLine,
    manifest_path: &str,
    cases: &mut Vec<ConformanceCase>,
    case_ids: &mut BTreeSet<String>,
    operation_ids: &mut BTreeSet<String>,
    source_bindings: &mut BTreeMap<String, String>,
) -> Result<(), Error> {
    let manifest: CorpusManifest = value_as(line.source(manifest_path)?)?;
    if manifest.schema != "https://licoarc.com/spec/schemas/conformance-corpus-manifest.schema.json"
        || manifest.manifest_version != "licoarc.conformance-corpus-manifest.v1"
        || manifest.envelope_paths.len() != 1
        || manifest.case_count == 0
        || manifest.operation_ids.is_empty()
    {
        return Err(conformance(ErrorCode::InvalidAuthorityInput));
    }
    let directory = manifest_path.rsplit_once('/').ok_or_else(invalid)?.0;
    if manifest.envelope_paths[0] != format!("{directory}/cases.json") {
        return Err(conformance(ErrorCode::SourceClosureMismatch));
    }
    let envelope: Envelope = value_as(line.source(&manifest.envelope_paths[0])?)?;
    if envelope.schema != "https://licoarc.com/spec/schemas/conformance-envelope.schema.json"
        || envelope.envelope_version != "licoarc.conformance-envelope.v1"
        || envelope.corpus_id != manifest.corpus_id
        || envelope.cases.len() != manifest.case_count
    {
        return Err(conformance(ErrorCode::SourceClosureMismatch));
    }
    let declared = manifest.operation_ids.into_iter().collect::<BTreeSet<_>>();
    if declared.is_empty() || declared.iter().any(|id| !executor::supports(id)) {
        return Err(conformance(ErrorCode::UnsupportedConformanceCase));
    }
    let mut observed = BTreeSet::new();
    for case in envelope.cases {
        if case.schema != "https://licoarc.com/spec/schemas/conformance-case.schema.json"
            || case.case_version != "licoarc.conformance-case.v1"
            || !case_ids.insert(case.id.clone())
            || !declared.contains(&case.target.operation_id)
        {
            return Err(conformance(ErrorCode::SourceClosureMismatch));
        }
        validate_context(&case.context, line, source_bindings)?;
        observed.insert(case.target.operation_id.clone());
        cases.push(ConformanceCase {
            id: case.id,
            corpus_id: envelope.corpus_id.clone(),
            operation_id: case.target.operation_id,
            input: case.input,
            context: case.context,
            expected: case.expected,
        });
    }
    if observed != declared {
        return Err(conformance(ErrorCode::SourceClosureMismatch));
    }
    operation_ids.extend(observed);
    Ok(())
}

fn validate_context(
    context: &Value,
    line: &VerifiedProtocolLine,
    source_bindings: &mut BTreeMap<String, String>,
) -> Result<(), Error> {
    let object = context.as_object().ok_or_else(invalid)?;
    let bindings = object
        .get("sourceBindings")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    if bindings.is_empty() {
        return Err(conformance(ErrorCode::SourceClosureMismatch));
    }
    for binding in bindings {
        let binding = binding.as_object().ok_or_else(invalid)?;
        if binding.len() != 2 {
            return Err(conformance(ErrorCode::InvalidAuthorityInput));
        }
        let path = binding
            .get("sourcePath")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        let digest = binding
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(conformance(ErrorCode::InvalidAuthorityInput));
        }
        line.source(path)?;
        if source_bindings
            .insert(path.to_owned(), digest.to_owned())
            .is_some_and(|previous| previous != digest)
        {
            return Err(conformance(ErrorCode::SourceClosureMismatch));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Aggregate {
    #[serde(rename = "$schema")]
    schema: String,
    manifest_version: String,
    wire_id: String,
    generation: u64,
    protocol_line_id: String,
    lifecycle: String,
    definition_status: String,
    capability_corpora: Vec<AggregateCorpus>,
    definition_corpora: Vec<AggregateDefinitionCorpus>,
    absent_corpora: Vec<Value>,
    source_closure: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AggregateCorpus {
    capability_id: String,
    definition_status: String,
    manifest_path: String,
    source_digest: String,
    protection_profile_ids: Vec<String>,
    complete: bool,
}

impl AggregateCorpus {
    fn validate(&self) -> Result<(), Error> {
        if self.definition_status != "COMPLETE"
            || !self.complete
            || self.source_digest.len() != 64
            || (self.capability_id == "licoarc.pairwise-protection.v1")
                != (self.protection_profile_ids.len() == 1)
        {
            return Err(conformance(ErrorCode::SourceClosureMismatch));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AggregateDefinitionCorpus {
    definition_id: String,
    definition_status: String,
    manifest_path: String,
    source_digest: String,
    complete: bool,
}

impl AggregateDefinitionCorpus {
    fn validate(&self) -> Result<(), Error> {
        if self.definition_status != "COMPLETE" || !self.complete || self.source_digest.len() != 64
        {
            return Err(conformance(ErrorCode::SourceClosureMismatch));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CorpusManifest {
    #[serde(rename = "$schema")]
    schema: String,
    manifest_version: String,
    corpus_id: String,
    case_count: usize,
    operation_ids: Vec<String>,
    envelope_paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Envelope {
    #[serde(rename = "$schema")]
    schema: String,
    envelope_version: String,
    corpus_id: String,
    cases: Vec<CaseEnvelope>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CaseEnvelope {
    #[serde(rename = "$schema")]
    schema: String,
    case_version: String,
    id: String,
    target: Target,
    context: Value,
    input: Value,
    expected: Expected,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Target {
    operation_id: String,
}

fn value_as<T: for<'de> Deserialize<'de>>(value: &Value) -> Result<T, Error> {
    serde_json::from_value(value.clone()).map_err(|_| conformance(ErrorCode::InvalidAuthorityInput))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const fn invalid() -> Error {
    conformance(ErrorCode::InvalidAuthorityInput)
}

const fn conformance(code: ErrorCode) -> Error {
    Error::terminal(code, Stage::Validation)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ConformanceCase, Expected};

    #[test]
    fn case_debug_redacts_input_context_and_expected_values() {
        let canary = "case-content-canary";
        let case = ConformanceCase {
            id: "safe-case-id".to_owned(),
            corpus_id: "safe-corpus-id".to_owned(),
            operation_id: "safe-operation-id".to_owned(),
            input: json!({ "value": canary }),
            context: json!({ "value": canary }),
            expected: Expected::Result(json!({ "value": canary })),
        };
        let rendered = format!("{case:?}");
        assert!(!rendered.contains(canary));
        assert!(rendered.contains("safe-case-id"));
    }
}

#[cfg(test)]
mod fixed_v1_handshake_tests {
    use super::*;
    use crate::{
        AuthorityBundle,
        encoding::{self, CborValue},
        endpoint::{decode_first_packet, encode_first_packet},
        provider::RustCryptoProvider,
    };

    #[test]
    fn fixed_v1_handshake_vectors_and_maximum_wire() {
        let path = std::env::var_os("LICOARC_AUTHORITY_BUNDLE")
            .expect("explicit authority bundle required");
        let bytes = std::fs::read(path).expect("authority bundle must be readable");
        let line = AuthorityBundle::new(&bytes)
            .admit()
            .expect("authority must verify");
        let registry = ConformanceRegistry::from_protocol_line(&line).unwrap();
        let cases: Vec<_> = registry
            .cases
            .iter()
            .filter(|case| {
                case.operation_id == "licoarc.protection.verify-handshake-authentication.v1"
            })
            .collect();
        assert_eq!(cases.len(), 5);
        for case in cases {
            let actual = executor::execute(
                &case.operation_id,
                &case.input,
                &case.context,
                &line,
                &RustCryptoProvider,
            )
            .unwrap();
            assert!(actual == case.expected, "fixed V1 handshake vector failed");
            if case.id != "fixed-v1-handshake-accept" {
                continue;
            }
            let hex = case.input["firstPacketCanonicalHex"].as_str().unwrap();
            let wire: Vec<_> = hex
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            assert_eq!(wire.len(), crate::protection::MAX_FIRST_PACKET_BYTES);
            let packet = decode_first_packet(&wire).unwrap();
            assert!(encode_first_packet(&packet).unwrap() == wire);
            assert!(decode_first_packet(&wire[..wire.len() - 1]).is_err());
            let mut surplus = wire.clone();
            surplus.push(0);
            assert!(decode_first_packet(&surplus).is_err());
            let CborValue::Map(mut map) = encoding::decode(&wire).unwrap() else {
                panic!("map required")
            };
            map.remove(&14);
            assert!(
                decode_first_packet(&encoding::encode(&CborValue::Map(map.clone())).unwrap())
                    .is_err()
            );
            map.insert(15, CborValue::Bytes(vec![0; 16]));
            assert!(decode_first_packet(&encoding::encode(&CborValue::Map(map)).unwrap()).is_err());
        }
    }
}
