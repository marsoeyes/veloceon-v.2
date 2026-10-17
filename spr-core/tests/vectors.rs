use spr_core::vectors;

#[test]
fn reference_derivation_vectors() {
    let checks = vectors::crypto_checks();
    let failed: Vec<String> = checks
        .iter()
        .filter(|c| !c.ok)
        .map(|c| {
            format!(
                "{}\n  expected: {}\n  actual:   {}",
                c.name, c.expected, c.actual
            )
        })
        .collect();
    assert!(
        failed.is_empty(),
        "{} of {} vectors failed:\n{}",
        failed.len(),
        checks.len(),
        failed.join("\n")
    );
}

#[test]
fn end_to_end_recovery() {
    let c = vectors::engine_check();
    assert!(
        c.ok,
        "{}: expected {}\nactual   {}",
        c.name, c.expected, c.actual
    );
}
