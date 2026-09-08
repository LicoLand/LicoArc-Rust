use std::collections::BTreeSet;

use licoarc::{AuthorityBundle, conformance::ConformanceRegistry, provider::RustCryptoProvider};

#[test]
fn exact_complete_standalone_conformance() {
    let path = std::env::var_os("LICOARC_AUTHORITY_BUNDLE")
        .expect("LICOARC_AUTHORITY_BUNDLE must name the explicit read-only bundle");
    let bytes = std::fs::read(path).expect("explicit authority bundle must be readable");
    let line = AuthorityBundle::new(&bytes)
        .admit()
        .expect("authority bundle must verify");
    let registry = ConformanceRegistry::from_protocol_line(&line)
        .expect("complete aggregate and corpus closure must verify");

    assert_eq!(registry.cases().len(), line.conformance_case_count());
    assert_eq!(
        registry
            .cases()
            .iter()
            .map(|case| (&case.corpus_id, &case.id))
            .collect::<BTreeSet<_>>()
            .len(),
        line.conformance_case_count()
    );
    assert_eq!(
        registry
            .cases()
            .iter()
            .map(|case| case.operation_id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        line.operation_ids().len()
    );

    let report = registry
        .execute_all_with_provider(&line, &RustCryptoProvider)
        .expect("all standalone cases must execute exactly once and match exactly");
    assert!(report.summary.complete());
    assert_eq!(report.summary.declared, line.conformance_case_count());
    assert_eq!(report.summary.visited, report.summary.declared);
    assert_eq!(report.summary.executed, report.summary.declared);
    assert_eq!(report.summary.passed, report.summary.declared);
    assert_eq!(
        report.summary.capability_coverage,
        line.capability_ids().len()
    );
    assert_eq!(
        report.summary.operation_coverage,
        line.operation_ids().len()
    );
    assert_eq!(
        report.summary.blocked
            + report.summary.skipped
            + report.summary.source_only
            + report.summary.unmapped
            + report.summary.duplicate
            + report.summary.absent
            + report.summary.surplus,
        0
    );
}
