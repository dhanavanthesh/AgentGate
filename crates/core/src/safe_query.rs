//! Opt-in SafeQuery research surface. It is not registered with the runtime.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::clock::Clock;
use crate::deadline::Deadline;
use crate::error::{ErrorCode, GateError, GateResult};
use crate::ids::{OpaqueHandle, PrincipalId, SourceRevision, TenantId};
use crate::normalize::{parse_and_bound, OutputLimits};

pub const QUERY_TOOL: &str = "query_table";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QueryOperator {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

impl QueryOperator {
    const fn sql(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Ne => "<>",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::Lt => "<",
            Self::Le => "<=",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum QueryValue {
    Bool(bool),
    Integer(i64),
    Text(String),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawQueryPlan {
    tool: String,
    table_handle: String,
    select_columns: Vec<String>,
    filter_column: String,
    operator: QueryOperator,
    value: QueryValue,
    limit: u32,
}

#[derive(Clone, Debug)]
pub struct SafeQueryLimits {
    pub max_action_bytes: usize,
    pub max_selected_columns: usize,
    pub max_parameter_string_bytes: usize,
    pub max_limit: u32,
    pub output: OutputLimits,
}

impl Default for SafeQueryLimits {
    fn default() -> Self {
        Self {
            max_action_bytes: 16 * 1024,
            max_selected_columns: 16,
            max_parameter_string_bytes: 4096,
            max_limit: 1000,
            output: OutputLimits::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SafeQueryReceipt {
    pub sql: String,
    pub parameters: Vec<QueryValue>,
    pub rows: Vec<BTreeMap<String, QueryValue>>,
    pub row_count: usize,
}

#[derive(Clone, Copy)]
enum ColumnType {
    Integer,
    Text,
}

#[derive(Clone)]
struct ColumnMetadata {
    identifier: String,
    value_type: ColumnType,
}

#[derive(Clone)]
struct TableMetadata {
    handle: OpaqueHandle,
    tenant: TenantId,
    revision: SourceRevision,
    sql_identifier: String,
    columns: BTreeMap<OpaqueHandle, ColumnMetadata>,
    readable_by: BTreeSet<PrincipalId>,
    rows: Vec<BTreeMap<String, QueryValue>>,
}

struct State {
    tables: BTreeMap<OpaqueHandle, TableMetadata>,
}

pub struct SafeQueryAdapter {
    state: Mutex<State>,
    clock: Arc<dyn Clock>,
    limits: SafeQueryLimits,
}

impl SafeQueryAdapter {
    pub fn seeded(clock: Arc<dyn Clock>) -> GateResult<Self> {
        Self::seeded_with_limits(clock, SafeQueryLimits::default())
    }

    pub fn seeded_with_limits(clock: Arc<dyn Clock>, limits: SafeQueryLimits) -> GateResult<Self> {
        let tenant = TenantId::new("tenant_acme");
        let revision = SourceRevision::new("rev_4");
        let table_handle = OpaqueHandle::new("table:tenant_acme:users@rev_4");
        let name_handle = OpaqueHandle::new("column:tenant_acme:users:name@rev_4");
        let age_handle = OpaqueHandle::new("column:tenant_acme:users:age@rev_4");
        let mut columns = BTreeMap::new();
        columns.insert(
            name_handle,
            ColumnMetadata {
                identifier: "name".to_owned(),
                value_type: ColumnType::Text,
            },
        );
        columns.insert(
            age_handle,
            ColumnMetadata {
                identifier: "age".to_owned(),
                value_type: ColumnType::Integer,
            },
        );
        let rows = vec![row("Ada", 37), row("Grace", 85), row("Linus", 54)];
        let metadata = TableMetadata {
            handle: table_handle.clone(),
            tenant,
            revision,
            sql_identifier: "users".to_owned(),
            columns,
            readable_by: BTreeSet::from([PrincipalId::new("user:42")]),
            rows,
        };
        validate_metadata(&metadata)?;
        Ok(Self {
            state: Mutex::new(State {
                tables: BTreeMap::from([(table_handle, metadata)]),
            }),
            clock,
            limits,
        })
    }

    pub fn execute_authorized(
        &self,
        principal: &PrincipalId,
        tenant: &TenantId,
        expected_revision: &SourceRevision,
        action_json: &[u8],
        deadline: Deadline,
    ) -> GateResult<SafeQueryReceipt> {
        deadline.check(self.clock.as_ref())?;
        let raw = parse_plan(action_json, &self.limits)?;
        let state = self.lock()?;
        deadline.check(self.clock.as_ref())?;
        let table_handle = OpaqueHandle::new(&raw.table_handle);
        let table = state
            .tables
            .get(&table_handle)
            .ok_or_else(|| GateError::new(ErrorCode::AuthDenied, "table handle is unavailable"))?;
        if &table.tenant != tenant || !table.readable_by.contains(principal) {
            return Err(GateError::new(
                ErrorCode::AuthDenied,
                "current table authorization denied",
            ));
        }
        if &table.revision != expected_revision {
            return Err(GateError::new(
                ErrorCode::CatalogStale,
                "table revision changed",
            ));
        }
        let compiled = compile_sql(table, &raw, &self.limits)?;
        let row_limit = usize::try_from(raw.limit)
            .map_err(|_| GateError::new(ErrorCode::PolicyDenied, "query limit overflow"))?;
        let capacity = row_limit
            .min(self.limits.output.max_records)
            .min(table.rows.len());
        let mut rows = Vec::with_capacity(capacity);
        let mut projected_bytes = 0usize;
        for source in &table.rows {
            if !matches_filter(source, &compiled)? {
                continue;
            }
            if rows.len() >= self.limits.output.max_records {
                return Err(GateError::new(
                    ErrorCode::ToolFailed,
                    "query result exceeds record limit",
                ));
            }
            let projected = project_row(source, &compiled.selected)?;
            let encoded = serde_json::to_vec(&projected).map_err(|_| {
                GateError::new(ErrorCode::ToolFailed, "projected row encoding failed")
            })?;
            projected_bytes = projected_bytes.checked_add(encoded.len()).ok_or_else(|| {
                GateError::new(
                    ErrorCode::InternalInvariant,
                    "query byte accounting overflow",
                )
            })?;
            if projected_bytes > self.limits.output.max_serialized_bytes {
                return Err(GateError::new(
                    ErrorCode::ToolFailed,
                    "query result exceeds byte limit",
                ));
            }
            rows.push(projected);
            if rows.len() == row_limit {
                break;
            }
        }
        let receipt = SafeQueryReceipt {
            sql: compiled.sql,
            parameters: compiled.parameters,
            row_count: rows.len(),
            rows,
        };
        drop(state);
        let encoded = serde_json::to_vec(&receipt)
            .map_err(|_| GateError::new(ErrorCode::ToolFailed, "query result encoding failed"))?;
        parse_and_bound(&encoded, &self.limits.output)?;
        deadline.check(self.clock.as_ref())?;
        Ok(receipt)
    }

    pub fn revoke(&self, principal: &PrincipalId, table: &OpaqueHandle) -> GateResult<()> {
        let mut state = self.lock()?;
        let metadata = state
            .tables
            .get_mut(table)
            .ok_or_else(|| GateError::new(ErrorCode::AuthDenied, "table handle is unavailable"))?;
        metadata.readable_by.remove(principal);
        Ok(())
    }

    pub fn change_revision(
        &self,
        table: &OpaqueHandle,
        revision: SourceRevision,
    ) -> GateResult<()> {
        let mut state = self.lock()?;
        let metadata = state
            .tables
            .get_mut(table)
            .ok_or_else(|| GateError::new(ErrorCode::AuthDenied, "table handle is unavailable"))?;
        metadata.revision = revision;
        Ok(())
    }

    fn lock(&self) -> GateResult<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| GateError::new(ErrorCode::AuthDenied, "query adapter lock poisoned"))
    }
}

fn parse_plan(bytes: &[u8], limits: &SafeQueryLimits) -> GateResult<RawQueryPlan> {
    if bytes.len() > limits.max_action_bytes {
        return Err(GateError::new(
            ErrorCode::FinalValidationFailed,
            "query plan exceeds byte limit",
        ));
    }
    let plan: RawQueryPlan = serde_json::from_slice(bytes).map_err(|_| {
        GateError::new(
            ErrorCode::FinalValidationFailed,
            "query plan is malformed or outside the typed contract",
        )
    })?;
    if plan.tool != QUERY_TOOL {
        return Err(GateError::new(
            ErrorCode::FinalValidationFailed,
            "query tool identifier differs",
        ));
    }
    if plan.select_columns.is_empty()
        || plan.select_columns.len() > limits.max_selected_columns
        || plan.limit == 0
        || plan.limit > limits.max_limit
    {
        return Err(GateError::new(
            ErrorCode::PolicyDenied,
            "query plan exceeds selection or row limits",
        ));
    }
    if matches!(&plan.value, QueryValue::Text(value) if value.len() > limits.max_parameter_string_bytes)
    {
        return Err(GateError::new(
            ErrorCode::PolicyDenied,
            "query parameter string exceeds limit",
        ));
    }
    Ok(plan)
}

fn compile_sql(
    table: &TableMetadata,
    plan: &RawQueryPlan,
    limits: &SafeQueryLimits,
) -> GateResult<CompiledQuery> {
    if plan.table_handle != table.handle.as_str() {
        return Err(GateError::new(
            ErrorCode::AuthDenied,
            "query table handle differs",
        ));
    }
    let mut selected_sql = Vec::with_capacity(plan.select_columns.len());
    let mut selected = Vec::with_capacity(plan.select_columns.len());
    let mut unique = BTreeSet::new();
    for handle in &plan.select_columns {
        let handle = OpaqueHandle::new(handle);
        let identifier = table.columns.get(&handle).ok_or_else(|| {
            GateError::new(
                ErrorCode::AuthDenied,
                "selected column is not under the authorized table",
            )
        })?;
        if !unique.insert(handle) {
            return Err(GateError::new(
                ErrorCode::PolicyDenied,
                "selected columns contain a duplicate",
            ));
        }
        selected_sql.push(quote_identifier(&identifier.identifier)?);
        selected.push(identifier.identifier.clone());
    }
    if selected.len() > limits.max_selected_columns {
        return Err(GateError::new(
            ErrorCode::PolicyDenied,
            "too many selected columns",
        ));
    }
    let filter = table
        .columns
        .get(&OpaqueHandle::new(&plan.filter_column))
        .ok_or_else(|| {
            GateError::new(
                ErrorCode::AuthDenied,
                "filter column is not under the authorized table",
            )
        })?;
    let sql = format!(
        "SELECT {} FROM {} WHERE {} {} ? LIMIT ?",
        selected_sql.join(", "),
        quote_identifier(&table.sql_identifier)?,
        quote_identifier(&filter.identifier)?,
        plan.operator.sql(),
    );
    validate_filter_type(filter.value_type, &plan.value)?;
    Ok(CompiledQuery {
        sql,
        parameters: vec![
            plan.value.clone(),
            QueryValue::Integer(i64::from(plan.limit)),
        ],
        selected,
        filter: filter.identifier.clone(),
        operator: plan.operator,
        value: plan.value.clone(),
    })
}

struct CompiledQuery {
    sql: String,
    parameters: Vec<QueryValue>,
    selected: Vec<String>,
    filter: String,
    operator: QueryOperator,
    value: QueryValue,
}

fn validate_filter_type(expected: ColumnType, value: &QueryValue) -> GateResult<()> {
    let matches = matches!(
        (expected, value),
        (ColumnType::Integer, QueryValue::Integer(_)) | (ColumnType::Text, QueryValue::Text(_))
    );
    if !matches {
        return Err(GateError::new(
            ErrorCode::FinalValidationFailed,
            "query filter value or operator differs from the column type",
        ));
    }
    Ok(())
}

fn matches_filter(row: &BTreeMap<String, QueryValue>, query: &CompiledQuery) -> GateResult<bool> {
    let actual = row.get(&query.filter).ok_or_else(|| {
        GateError::new(ErrorCode::ToolFailed, "trusted row lacks the filter column")
    })?;
    let ordering = compare_values(actual, &query.value)?;
    Ok(match query.operator {
        QueryOperator::Eq => ordering == Ordering::Equal,
        QueryOperator::Ne => ordering != Ordering::Equal,
        QueryOperator::Gt => ordering == Ordering::Greater,
        QueryOperator::Ge => ordering != Ordering::Less,
        QueryOperator::Lt => ordering == Ordering::Less,
        QueryOperator::Le => ordering != Ordering::Greater,
    })
}

fn compare_values(left: &QueryValue, right: &QueryValue) -> GateResult<Ordering> {
    match (left, right) {
        (QueryValue::Bool(left), QueryValue::Bool(right)) => Ok(left.cmp(right)),
        (QueryValue::Integer(left), QueryValue::Integer(right)) => Ok(left.cmp(right)),
        (QueryValue::Text(left), QueryValue::Text(right)) => Ok(left.cmp(right)),
        _ => Err(GateError::new(
            ErrorCode::ToolFailed,
            "trusted row value differs from the declared column type",
        )),
    }
}

fn project_row(
    source: &BTreeMap<String, QueryValue>,
    selected: &[String],
) -> GateResult<BTreeMap<String, QueryValue>> {
    selected
        .iter()
        .map(|column| {
            source
                .get(column)
                .cloned()
                .map(|value| (column.clone(), value))
                .ok_or_else(|| {
                    GateError::new(ErrorCode::ToolFailed, "trusted row lacks a selected column")
                })
        })
        .collect()
}

fn validate_metadata(table: &TableMetadata) -> GateResult<()> {
    validate_identifier(&table.sql_identifier)?;
    for column in table.columns.values() {
        validate_identifier(&column.identifier)?;
    }
    for row in &table.rows {
        for column in table.columns.values() {
            let value = row.get(&column.identifier).ok_or_else(|| {
                GateError::new(
                    ErrorCode::CatalogInvalid,
                    "trusted row lacks a declared column",
                )
            })?;
            validate_filter_type(column.value_type, value)?;
        }
    }
    if !table.handle.as_str().starts_with("table:") {
        return Err(GateError::new(
            ErrorCode::CatalogInvalid,
            "table handle namespace is invalid",
        ));
    }
    Ok(())
}

fn row(name: &str, age: i64) -> BTreeMap<String, QueryValue> {
    BTreeMap::from([
        ("name".to_owned(), QueryValue::Text(name.to_owned())),
        ("age".to_owned(), QueryValue::Integer(age)),
    ])
}

fn quote_identifier(identifier: &str) -> GateResult<String> {
    validate_identifier(identifier)?;
    Ok(format!("\"{identifier}\""))
}

fn validate_identifier(identifier: &str) -> GateResult<()> {
    let mut chars = identifier.chars();
    let Some(first) = chars.next() else {
        return Err(GateError::new(
            ErrorCode::CatalogInvalid,
            "trusted SQL identifier is empty",
        ));
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || !chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        return Err(GateError::new(
            ErrorCode::CatalogInvalid,
            "trusted SQL identifier is invalid",
        ));
    }
    Ok(())
}
