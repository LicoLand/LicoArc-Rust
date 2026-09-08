#[test]
fn dependency_graph_has_no_external_implementation_link() {
    let manifest = include_str!("../Cargo.toml");
    assert!(!manifest.lines().any(|line| line.contains("path = \"..")
        || line.trim_start().starts_with("git =")
        || line.trim_start().starts_with("workspace =")));
    assert!(!manifest.contains("build ="));
}

#[test]
fn documentation_facts_are_consistent() {
    let facts = [
        include_str!("../PRODUCT.md"),
        include_str!("../CONTEXT.md"),
        include_str!("../README.md"),
        include_str!("../SECURITY.md"),
        include_str!("../docs/STATUS.md"),
        include_str!("../docs/provider-adoption/fixed-cryptography.md"),
        include_str!("../docs/provider-adoption/dependency-boundary.md"),
    ]
    .join("\n");
    assert!(facts.contains("Candidate/COMPLETE"));
    assert!(facts.contains("stable-core"));
    for nonclaim in [
        "publication",
        "product integration",
        "interoperability",
        "external audit",
        "physical erasure",
    ] {
        assert!(facts.to_ascii_lowercase().contains(nonclaim));
    }
    assert!(!facts.contains("session-ineligible"));
    assert!(!facts.contains("current claims remain unproved"));
}

#[test]
fn production_sources_keep_local_unsafe_forbidden() {
    assert!(include_str!("../src/lib.rs").contains("#![forbid(unsafe_code)]"));
    assert!(!include_str!("../tools/verify").contains("curl"));
    assert!(!include_str!("../tools/verify").contains("wget"));
}
