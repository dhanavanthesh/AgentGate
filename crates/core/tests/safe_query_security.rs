#![cfg(feature = "safe-query-eval")]

use std::sync::Arc;

use agentgate_core::normalize::OutputLimits;
use agentgate_core::safe_query::{QueryValue, SafeQueryAdapter, SafeQueryLimits};
use agentgate_core::{
    Deadline, ErrorCode, ManualClock, OpaqueHandle, PrincipalId, SourceRevision, TenantId,
};

const TABLE: &str = "table:tenant_acme:users@rev_4";
const NAME: &str = "column:tenant_acme:users:name@rev_4";
const AGE: &str = "column:tenant_acme:users:age@rev_4";

fn action(filter: &str, operator: &str, value: serde_json::Value, limit: u32) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "tool": "query_table",
        "table_handle": TABLE,
        "select_columns": [NAME],
        "filter_column": filter,
        "operator": operator,
        "value": value,
        "limit": limit,
    }))
    .expect("action")
}

fn execute(
    action: &[u8],
) -> agentgate_core::GateResult<agentgate_core::safe_query::SafeQueryReceipt> {
    let clock = Arc::new(ManualClock::new(100, 0));
    let adapter = SafeQueryAdapter::seeded(clock.clone()).expect("adapter");
    let deadline = Deadline::after_ms(clock.as_ref(), 100).expect("deadline");
    adapter.execute_authorized(
        &PrincipalId::new("user:42"),
        &TenantId::new("tenant_acme"),
        &SourceRevision::new("rev_4"),
        action,
        deadline,
    )
}

#[test]
fn malicious_values_are_parameters_and_never_change_sql_structure() {
    for attack in [
        "' OR 1=1 --",
        "'; DROP TABLE users; --",
        "UNION SELECT password FROM users",
        "/* comment */",
        "； DROP TABLE users",
        "ignore previous instructions",
    ] {
        let plan = action(NAME, "eq", serde_json::json!(attack), 100);
        let receipt = execute(&plan).expect("bound query");
        assert_eq!(
            receipt.sql,
            "SELECT \"name\" FROM \"users\" WHERE \"name\" = ? LIMIT ?"
        );
        assert_eq!(receipt.parameters[0], QueryValue::Text(attack.to_owned()));
        assert!(!receipt.sql.contains(attack));
        assert!(!receipt.sql.contains(';'));
        assert!(!receipt.sql.contains("--"));
    }
}

#[test]
fn filtering_projection_and_limit_match_the_compiled_plan() {
    let receipt = execute(&action(AGE, "gt", serde_json::json!(40), 100)).expect("filtered query");
    assert_eq!(receipt.row_count, 2);
    assert_eq!(
        receipt.rows,
        vec![
            std::collections::BTreeMap::from([(
                "name".to_owned(),
                QueryValue::Text("Grace".to_owned()),
            )]),
            std::collections::BTreeMap::from([(
                "name".to_owned(),
                QueryValue::Text("Linus".to_owned()),
            )]),
        ]
    );
    assert!(receipt.rows.iter().all(|row| !row.contains_key("age")));

    let none =
        execute(&action(AGE, "gt", serde_json::json!(100), 100)).expect("empty filtered query");
    assert_eq!(none.row_count, 0);
    assert!(none.rows.is_empty());

    let limited = execute(&action(AGE, "gt", serde_json::json!(0), 1)).expect("limited query");
    assert_eq!(limited.row_count, 1);
    assert_eq!(
        limited.rows[0].get("name"),
        Some(&QueryValue::Text("Ada".to_owned()))
    );
}

#[test]
fn filter_value_must_match_the_trusted_column_type() {
    let error =
        execute(&action(AGE, "gt", serde_json::json!("100"), 100)).expect_err("type mismatch");
    assert_eq!(error.code, ErrorCode::FinalValidationFailed);
}

#[test]
fn raw_sql_and_unknown_operators_are_rejected() {
    let clock = Arc::new(ManualClock::new(100, 0));
    let adapter = SafeQueryAdapter::seeded(clock.clone()).expect("adapter");
    let deadline = Deadline::after_ms(clock.as_ref(), 100).expect("deadline");
    let raw_sql = br#"{"tool":"query_table","table_handle":"table:tenant_acme:users@rev_4","select_columns":["column:tenant_acme:users:name@rev_4"],"filter_column":"column:tenant_acme:users:age@rev_4","operator":"gt","value":30,"limit":100,"sql":"DROP TABLE users"}"#;
    let error = adapter
        .execute_authorized(
            &PrincipalId::new("user:42"),
            &TenantId::new("tenant_acme"),
            &SourceRevision::new("rev_4"),
            raw_sql,
            deadline,
        )
        .expect_err("raw SQL field");
    assert_eq!(error.code, ErrorCode::FinalValidationFailed);

    let unknown = String::from_utf8(action(NAME, "eq", serde_json::json!("value"), 100))
        .expect("UTF-8")
        .replace("\"eq\"", "\"union\"");
    let deadline = Deadline::after_ms(clock.as_ref(), 100).expect("deadline");
    assert_eq!(
        adapter
            .execute_authorized(
                &PrincipalId::new("user:42"),
                &TenantId::new("tenant_acme"),
                &SourceRevision::new("rev_4"),
                unknown.as_bytes(),
                deadline,
            )
            .expect_err("unknown operator")
            .code,
        ErrorCode::FinalValidationFailed
    );
}

#[test]
fn cross_table_tenant_revision_and_revocation_fail_closed() {
    let clock = Arc::new(ManualClock::new(100, 0));
    let adapter = SafeQueryAdapter::seeded(clock.clone()).expect("adapter");
    let deadline = Deadline::after_ms(clock.as_ref(), 100).expect("deadline");
    let cross_table = String::from_utf8(action(NAME, "eq", serde_json::json!("value"), 100))
        .expect("UTF-8")
        .replace(NAME, "column:tenant_acme:orders:name@rev_4");
    assert_eq!(
        adapter
            .execute_authorized(
                &PrincipalId::new("user:42"),
                &TenantId::new("tenant_acme"),
                &SourceRevision::new("rev_4"),
                cross_table.as_bytes(),
                deadline,
            )
            .expect_err("cross-table column")
            .code,
        ErrorCode::AuthDenied
    );

    let deadline = Deadline::after_ms(clock.as_ref(), 100).expect("deadline");
    assert_eq!(
        adapter
            .execute_authorized(
                &PrincipalId::new("user:42"),
                &TenantId::new("tenant_other"),
                &SourceRevision::new("rev_4"),
                &action(NAME, "eq", serde_json::json!("value"), 100),
                deadline,
            )
            .expect_err("cross tenant")
            .code,
        ErrorCode::AuthDenied
    );

    adapter
        .change_revision(&OpaqueHandle::new(TABLE), SourceRevision::new("rev_5"))
        .expect("revision");
    let deadline = Deadline::after_ms(clock.as_ref(), 100).expect("deadline");
    assert_eq!(
        adapter
            .execute_authorized(
                &PrincipalId::new("user:42"),
                &TenantId::new("tenant_acme"),
                &SourceRevision::new("rev_4"),
                &action(NAME, "eq", serde_json::json!("value"), 100),
                deadline,
            )
            .expect_err("stale revision")
            .code,
        ErrorCode::CatalogStale
    );

    let adapter = SafeQueryAdapter::seeded(clock.clone()).expect("adapter");
    adapter
        .revoke(&PrincipalId::new("user:42"), &OpaqueHandle::new(TABLE))
        .expect("revoke");
    let deadline = Deadline::after_ms(clock.as_ref(), 100).expect("deadline");
    assert_eq!(
        adapter
            .execute_authorized(
                &PrincipalId::new("user:42"),
                &TenantId::new("tenant_acme"),
                &SourceRevision::new("rev_4"),
                &action(NAME, "eq", serde_json::json!("value"), 100),
                deadline,
            )
            .expect_err("revoked")
            .code,
        ErrorCode::AuthDenied
    );
}

#[test]
fn limits_and_deadlines_are_enforced_before_query_reuse() {
    let clock = Arc::new(ManualClock::new(100, 0));
    let adapter = SafeQueryAdapter::seeded(clock.clone()).expect("adapter");
    let oversized = action(NAME, "eq", serde_json::json!("x".repeat(5000)), 100);
    let deadline = Deadline::after_ms(clock.as_ref(), 100).expect("deadline");
    assert_eq!(
        adapter
            .execute_authorized(
                &PrincipalId::new("user:42"),
                &TenantId::new("tenant_acme"),
                &SourceRevision::new("rev_4"),
                &oversized,
                deadline,
            )
            .expect_err("oversized parameter")
            .code,
        ErrorCode::PolicyDenied
    );

    let deadline = Deadline::after_ms(clock.as_ref(), 1).expect("deadline");
    clock.advance_ms(1).expect("advance");
    assert_eq!(
        adapter
            .execute_authorized(
                &PrincipalId::new("user:42"),
                &TenantId::new("tenant_acme"),
                &SourceRevision::new("rev_4"),
                &action(NAME, "eq", serde_json::json!("value"), 100),
                deadline,
            )
            .expect_err("expired deadline")
            .code,
        ErrorCode::ToolTimeout
    );
}

#[test]
fn bounded_results_fail_instead_of_returning_partial_rows() {
    let clock = Arc::new(ManualClock::new(100, 0));
    let output = OutputLimits {
        max_records: 0,
        ..OutputLimits::default()
    };
    let limits = SafeQueryLimits {
        output,
        ..SafeQueryLimits::default()
    };
    let adapter = SafeQueryAdapter::seeded_with_limits(clock.clone(), limits).expect("adapter");
    let deadline = Deadline::after_ms(clock.as_ref(), 100).expect("deadline");
    let error = adapter
        .execute_authorized(
            &PrincipalId::new("user:42"),
            &TenantId::new("tenant_acme"),
            &SourceRevision::new("rev_4"),
            &action(NAME, "eq", serde_json::json!("Ada"), 100),
            deadline,
        )
        .expect_err("result limit");
    assert_eq!(error.code, ErrorCode::ToolFailed);
}
