use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::{
    VerifiedProtocolLine,
    error::{Error, ErrorCode, Stage},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityAccounting {
    claim_ids: Vec<String>,
    non_claim_count: usize,
}

impl SecurityAccounting {
    pub fn from_protocol_line(line: &VerifiedProtocolLine) -> Result<Self, Error> {
        let claims: Claims =
            serde_json::from_value(line.source("spec/v1/security/claims.json")?.clone())
                .map_err(|_| accounting(ErrorCode::InvalidAuthorityInput))?;
        let bindings: Bindings = serde_json::from_value(
            line.source("spec/v1/security/formal-bindings.json")?
                .clone(),
        )
        .map_err(|_| accounting(ErrorCode::InvalidAuthorityInput))?;
        let manifest: Manifest =
            serde_json::from_value(line.source("spec/v1/manifest.json")?.clone())
                .map_err(|_| accounting(ErrorCode::InvalidAuthorityInput))?;

        if claims.schema != "https://licoarc.com/spec/schemas/security-claims.schema.json"
            || claims.id != "https://licoarc.com/spec/v1/security/claims.json"
            || claims.registry_version != "licoarc.security-claims.v1"
            || claims.lifecycle != "Candidate"
            || claims.claim_status_values != ["unproved", "proved", "explicit-nonclaim"]
            || claims.claims.is_empty()
            || claims.claims.len() > 128
            || claims.non_claims.is_empty()
            || claims.non_claims.len() > 128
            || claims.claims.iter().any(|claim| !claim.is_valid())
            || !unique(&claims.non_claims)
            || claims
                .non_claims
                .iter()
                .any(|value| !lower_token(value, 128))
            || bindings.schema
                != "https://licoarc.com/spec/schemas/security-formal-bindings.schema.json"
            || bindings.id != "https://licoarc.com/spec/v1/security/formal-bindings.json"
            || bindings.registry_version != "licoarc.formal-bindings.v1"
            || bindings.lifecycle != "Candidate"
            || bindings.status != "complete"
            || bindings.required_kinds
                != [
                    "protocol-line-id",
                    "profile-id",
                    "algorithm-id",
                    "domain-separator",
                    "field-label",
                    "bound",
                    "failure-enum",
                ]
            || bindings.authority != "generated-only-from-decided-specified-normative-sources"
            || bindings.missing_binding_policy != "claim-remains-unproved-and-line-ineligible"
            || bindings.model_authority != "never-a-second-protocol"
            || !hex_digest(&bindings.semantic_source_digest)
            || bindings.semantic_sources.is_empty()
            || bindings.semantic_sources.len() > 128
            || !sorted_unique(&bindings.semantic_sources)
            || bindings.bindings.is_empty()
            || bindings.bindings.len() > 512
            || manifest.stable_claim_ids.is_empty()
            || manifest.stable_claim_ids.len() > 128
            || !sorted_unique(&manifest.stable_claim_ids)
        {
            return Err(accounting(ErrorCode::InvalidAuthorityInput));
        }

        let mut claim_ids: Vec<_> = claims.claims.iter().map(|claim| claim.id.clone()).collect();
        claim_ids.sort();
        let claim_proofs: BTreeMap<_, _> = claims
            .claims
            .iter()
            .map(|claim| {
                (
                    claim.id.as_str(),
                    (
                        claim.proof_model.as_deref().expect("proved claim model"),
                        claim.proof_lemma.as_deref().expect("proved claim lemma"),
                    ),
                )
            })
            .collect();
        let semantic_sources: BTreeSet<_> = bindings
            .semantic_sources
            .iter()
            .map(String::as_str)
            .collect();
        let required_kinds: BTreeSet<_> =
            bindings.required_kinds.iter().map(String::as_str).collect();
        let mut binding_ids = BTreeSet::new();
        let mut bound_claim_kinds = BTreeSet::new();
        if claim_ids.windows(2).any(|pair| pair[0] == pair[1])
            || claim_ids != manifest.stable_claim_ids
            || bindings.bindings.iter().any(|binding| {
                !binding.is_valid()
                    || !binding_ids.insert(binding.binding_id.as_str())
                    || !semantic_sources.contains(binding.authority_path.as_str())
                    || !claim_proofs
                        .get(binding.claim_id.as_str())
                        .is_some_and(|proof| {
                            proof.0 == binding.proof_model && proof.1 == binding.proof_lemma
                        })
                    || !required_kinds.contains(binding.kind.as_str())
                    || !bound_claim_kinds.insert((binding.claim_id.as_str(), binding.kind.as_str()))
            })
            || claim_ids.iter().any(|claim_id| {
                required_kinds
                    .iter()
                    .any(|kind| !bound_claim_kinds.contains(&(claim_id.as_str(), *kind)))
            })
        {
            return Err(accounting(ErrorCode::InvalidAuthorityInput));
        }

        Ok(Self {
            claim_ids,
            non_claim_count: claims.non_claims.len(),
        })
    }

    #[must_use]
    pub fn claim_ids(&self) -> &[String] {
        &self.claim_ids
    }

    #[must_use]
    pub const fn non_claim_count(&self) -> usize {
        self.non_claim_count
    }

    pub fn require_proved(&self, claim_id: &str) -> Result<(), Error> {
        if self
            .claim_ids
            .binary_search_by(|candidate| candidate.as_str().cmp(claim_id))
            .is_ok()
        {
            Ok(())
        } else {
            Err(accounting(ErrorCode::SecurityClaimUnproved))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Claims {
    #[serde(rename = "$schema")]
    schema: String,
    #[serde(rename = "$id")]
    id: String,
    registry_version: String,
    lifecycle: String,
    claim_status_values: Vec<String>,
    claims: Vec<Claim>,
    non_claims: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Claim {
    id: String,
    property: String,
    scope: String,
    adversary: Vec<String>,
    assumptions: Vec<String>,
    proof_model: Option<String>,
    proof_lemma: Option<String>,
    counterexample_status: String,
    residual_risk: String,
    status: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Bindings {
    #[serde(rename = "$schema")]
    schema: String,
    #[serde(rename = "$id")]
    id: String,
    registry_version: String,
    lifecycle: String,
    status: String,
    required_kinds: Vec<String>,
    semantic_source_digest: String,
    semantic_sources: Vec<String>,
    bindings: Vec<Binding>,
    authority: String,
    missing_binding_policy: String,
    model_authority: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Binding {
    binding_id: String,
    claim_id: String,
    kind: String,
    authority_path: String,
    authority_pointer: String,
    authority_digest: String,
    authority_value_digest: String,
    proof_model: String,
    proof_lemma: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    stable_claim_ids: Vec<String>,
}

impl Claim {
    fn is_valid(&self) -> bool {
        valid_claim_id(&self.id)
            && lower_token(&self.property, 128)
            && lower_token(&self.scope, 128)
            && !self.adversary.is_empty()
            && self.adversary.len() <= 32
            && unique(&self.adversary)
            && self.adversary.iter().all(|value| valid_adversary(value))
            && self.assumptions.len() <= 64
            && unique(&self.assumptions)
            && self.assumptions.iter().all(|value| lower_token(value, 128))
            && self.proof_model.as_deref().is_some_and(model_reference)
            && self.proof_lemma.as_deref().is_some_and(model_reference)
            && matches!(
                self.counterexample_status.as_str(),
                "not-evaluated" | "no-counterexample-found" | "counterexample-found"
            )
            && lower_token(&self.residual_risk, 128)
            && self.status == "proved"
    }
}

impl Binding {
    fn is_valid(&self) -> bool {
        self.binding_id.starts_with("BIND-SEC-")
            && self.binding_id.len() <= 128
            && self
                .binding_id
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            && valid_claim_id(&self.claim_id)
            && matches!(
                self.kind.as_str(),
                "protocol-line-id"
                    | "profile-id"
                    | "algorithm-id"
                    | "domain-separator"
                    | "field-label"
                    | "bound"
                    | "failure-enum"
            )
            && source_path(&self.authority_path)
            && json_pointer(&self.authority_pointer)
            && hex_digest(&self.authority_digest)
            && hex_digest(&self.authority_value_digest)
            && model_reference(&self.proof_model)
            && model_reference(&self.proof_lemma)
    }
}

fn unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn lower_token(value: &str, maximum: usize) -> bool {
    let bytes = value.as_bytes();
    (2..=maximum).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn valid_claim_id(value: &str) -> bool {
    value.len() == 7
        && value.starts_with("SEC-")
        && value.as_bytes()[4..].iter().all(u8::is_ascii_digit)
}

fn valid_adversary(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=8).contains(&bytes.len()) && bytes[0] == b'A' && bytes[1..].iter().all(u8::is_ascii_digit)
}

fn model_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn source_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('/')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

fn json_pointer(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'~' | b'_' | b'-'))
}

const fn accounting(code: ErrorCode) -> Error {
    Error::terminal(code, Stage::SecurityAccounting)
}
