//! Explicit Entity Framework table mappings (task B-062).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 2 admits the mapping subset
//! only when the source states it: an EF `[Table("...")]` attribute or a
//! literal `.ToTable("...")` call. EF Core also maps an entity to a table by
//! convention (the `DbSet` property name, or the pluralised class name), and
//! that convention is resolved by the runtime model builder, not by the source
//! this build reads.
//!
//! This adapter therefore records the two things separately:
//!
//! * an explicit attribute or literal fluent call is a
//!   [`FactQuality::ExactStatic`] mapping;
//! * a mapping that only a convention or a runtime value would produce is
//!   recorded as [`UnresolvedMapping`] with a reason, so a later consumer can
//!   see that no mapping was invented.
//!
//! No EF runtime is executed and no model is materialised.

use crate::{Diagnostic, Span};

use super::{
    first_literal_argument, lines_with_offsets, parse_string_literal, split_arguments,
    strip_line_comment, FactQuality,
};

/// Pattern id for an explicit `[Table]` attribute mapping.
pub const PATTERN_TABLE_ATTRIBUTE: &str = "ef-table-attribute";
/// Pattern id for an explicit literal `.ToTable(...)` mapping.
pub const PATTERN_FLUENT_TO_TABLE: &str = "ef-fluent-to-table";
/// Pattern id for a `DbSet` property that only a convention would map.
pub const PATTERN_DBSET_CONVENTION: &str = "ef-dbset-convention";
/// Pattern id for an entity configuration with no explicit table call.
pub const PATTERN_ENTITY_CONVENTION: &str = "ef-entity-convention";
/// Pattern id for an attribute or call whose table name is not a literal.
pub const PATTERN_DYNAMIC_TABLE: &str = "ef-dynamic-table-name";

/// Reason recorded when only a runtime convention names the table.
pub const REASON_CONVENTION_NOT_EXPLICIT: &str = "unresolved-convention-not-explicit";
/// Reason recorded when the table name is computed at runtime.
pub const REASON_DYNAMIC_TABLE: &str = "unresolved-dynamic-table-name";

/// How the mapping was stated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MappingEvidence {
    /// An entity attribute such as `[Table("Orders")]`.
    Attribute,
    /// A fluent call such as `.ToTable("Orders")`.
    Fluent,
}

impl MappingEvidence {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attribute => "attribute",
            Self::Fluent => "fluent",
        }
    }
}

/// One explicit entity-to-table mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityTableMapping {
    /// Owning file.
    pub file: String,
    /// The entity type the mapping was stated on, when the source names it.
    pub entity: Option<String>,
    /// The literal table name.
    pub table: String,
    /// The literal schema, when the source states one.
    pub schema: Option<String>,
    /// Whether the mapping came from an attribute or a fluent call.
    pub evidence: MappingEvidence,
    /// Quality of the mapping; an explicit literal mapping is `exact_static`.
    pub quality: FactQuality,
    /// Span of the statement.
    pub span: Span,
}

impl EntityTableMapping {
    /// The table name qualified by the schema, when one is known.
    #[must_use]
    pub fn qualified_table(&self) -> String {
        match &self.schema {
            Some(schema) => format!("{schema}.{}", self.table),
            None => self.table.clone(),
        }
    }
}

/// One mapping this adapter refused to invent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedMapping {
    /// Owning file.
    pub file: String,
    /// The entity type, when the source names it.
    pub entity: Option<String>,
    /// A `PATTERN_*` id naming what was not analysed.
    pub pattern: String,
    /// A `REASON_*` value explaining the refusal.
    pub reason: String,
    /// Span of the statement.
    pub span: Span,
}

/// Result of scanning one source file for EF table mappings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EfMappingAnalysis {
    /// Explicit mappings, in source order.
    pub mappings: Vec<EntityTableMapping>,
    /// Refused mappings, in source order.
    pub unresolved: Vec<UnresolvedMapping>,
    /// Diagnostics attached to the file.
    pub diagnostics: Vec<Diagnostic>,
}

impl EfMappingAnalysis {
    /// Whether any candidate mapping was refused.
    #[must_use]
    pub fn has_unresolved(&self) -> bool {
        !self.unresolved.is_empty()
    }

    /// The explicit mapping for `entity`, when exactly one exists.
    #[must_use]
    pub fn mapping_for(&self, entity: &str) -> Option<&EntityTableMapping> {
        let mut found = None;
        for mapping in &self.mappings {
            if mapping.entity.as_deref() == Some(entity) {
                if found.is_some() {
                    return None;
                }
                found = Some(mapping);
            }
        }
        found
    }
}

/// The class name in a declaration line such as `public class Order`.
fn declared_class(line: &str) -> Option<String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let index = tokens
        .iter()
        .position(|token| *token == "class" || *token == "record")?;
    let name = tokens.get(index + 1)?;
    let name: String = name
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// The `Entity<Name>()` type argument, when a fluent line names one.
fn entity_type_argument(line: &str) -> Option<String> {
    let marker = "Entity<";
    let start = line.find(marker)? + marker.len();
    let rest = &line[start..];
    let end = rest.find('>')?;
    let name: String = rest[..end]
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '.')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name.rsplit('.').next().unwrap_or(&name).to_string())
    }
}

/// Table/schema pair from `[Table(...)]` arguments.
fn attribute_table(arguments: &str) -> (Option<String>, Option<String>) {
    let mut table = first_literal_argument(arguments);
    let mut schema = None;
    for argument in split_arguments(arguments) {
        let trimmed = argument.trim();
        if let Some(value) = trimmed
            .strip_prefix("Schema")
            .and_then(|rest| rest.trim_start().strip_prefix('='))
        {
            schema = parse_string_literal(value.trim());
        } else if let Some(value) = trimmed
            .strip_prefix("Name")
            .and_then(|rest| rest.trim_start().strip_prefix('='))
        {
            if table.is_none() {
                table = parse_string_literal(value.trim());
            }
        }
    }
    (table, schema)
}

/// Whether an attribute line states a table mapping at all.
fn has_table_attribute(line: &str) -> bool {
    line.contains("[Table") || line.contains("[Table(")
}

/// Scan one C# source file for explicit EF table mappings.
#[must_use]
pub fn analyze(file: &str, source: &str) -> EfMappingAnalysis {
    let mut analysis = EfMappingAnalysis::default();
    let mut current_class: Option<String> = None;
    // An attribute precedes the declaration it annotates, so a mapping that is
    // pushed before its class is remembered here and attached by the next
    // class declaration.
    let mut pending: Option<(bool, usize)> = None;
    for (offset, raw_line) in lines_with_offsets(source) {
        let line = strip_line_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let span = Span::new(offset, offset + line.len());
        if let Some(class) = declared_class(trimmed) {
            if let Some((is_mapping, index)) = pending.take() {
                if is_mapping {
                    analysis.mappings[index].entity = Some(class.clone());
                } else {
                    analysis.unresolved[index].entity = Some(class.clone());
                }
            }
            current_class = Some(class);
        }
        if has_table_attribute(trimmed) || trimmed.starts_with("[Table") {
            let arguments = trimmed
                .split_once("Table")
                .map(|(_, rest)| rest)
                .and_then(|rest| rest.trim_start().strip_prefix('('))
                .and_then(|rest| rest.rsplit_once(')'))
                .map_or("", |(inner, _)| inner);
            if arguments.trim().is_empty() {
                let entity: Option<String> = None;
                let index = analysis.unresolved.len();
                analysis.unresolved.push(UnresolvedMapping {
                    file: file.to_string(),
                    entity: entity.clone(),
                    pattern: PATTERN_DBSET_CONVENTION.to_string(),
                    reason: REASON_CONVENTION_NOT_EXPLICIT.to_string(),
                    span,
                });
                if entity.is_none() {
                    pending = Some((false, index));
                }
                continue;
            }
            let (table, schema) = attribute_table(arguments);
            match table {
                Some(table) => {
                    let entity: Option<String> = None;
                    let index = analysis.mappings.len();
                    analysis.mappings.push(EntityTableMapping {
                        file: file.to_string(),
                        entity: entity.clone(),
                        table,
                        schema,
                        evidence: MappingEvidence::Attribute,
                        quality: FactQuality::ExactStatic,
                        span,
                    });
                    if entity.is_none() {
                        pending = Some((true, index));
                    }
                }
                None => {
                    let entity: Option<String> = None;
                    let index = analysis.unresolved.len();
                    analysis.unresolved.push(UnresolvedMapping {
                        file: file.to_string(),
                        entity: entity.clone(),
                        pattern: PATTERN_DYNAMIC_TABLE.to_string(),
                        reason: REASON_DYNAMIC_TABLE.to_string(),
                        span,
                    });
                    if entity.is_none() {
                        pending = Some((false, index));
                    }
                }
            }
        }
        if let Some(dbset) = dbset_property(trimmed) {
            analysis.unresolved.push(UnresolvedMapping {
                file: file.to_string(),
                entity: Some(dbset),
                pattern: PATTERN_DBSET_CONVENTION.to_string(),
                reason: REASON_CONVENTION_NOT_EXPLICIT.to_string(),
                span,
            });
        }
        if let Some(call_start) = trimmed.find(".ToTable") {
            let after = &trimmed[call_start + ".ToTable".len()..];
            let arguments = after
                .trim_start()
                .strip_prefix('(')
                .and_then(|rest| rest.rsplit_once(')'))
                .map_or("", |(inner, _)| inner);
            let entity = entity_type_argument(trimmed).or_else(|| current_class.clone());
            let values = split_arguments(arguments);
            let table = values
                .first()
                .and_then(|value| parse_string_literal(value.trim()));
            let schema = values
                .get(1)
                .and_then(|value| parse_string_literal(value.trim()));
            match table {
                Some(table) => analysis.mappings.push(EntityTableMapping {
                    file: file.to_string(),
                    entity,
                    table,
                    schema,
                    evidence: MappingEvidence::Fluent,
                    quality: FactQuality::ExactStatic,
                    span,
                }),
                None => analysis.unresolved.push(UnresolvedMapping {
                    file: file.to_string(),
                    entity,
                    pattern: PATTERN_DYNAMIC_TABLE.to_string(),
                    reason: REASON_DYNAMIC_TABLE.to_string(),
                    span,
                }),
            }
        } else if trimmed.contains(".Entity<") {
            analysis.unresolved.push(UnresolvedMapping {
                file: file.to_string(),
                entity: entity_type_argument(trimmed),
                pattern: PATTERN_ENTITY_CONVENTION.to_string(),
                reason: REASON_CONVENTION_NOT_EXPLICIT.to_string(),
                span,
            });
        }
    }
    analysis
}

/// The entity type of a `DbSet<Name>` property, whose table is conventional.
fn dbset_property(line: &str) -> Option<String> {
    let marker = "DbSet<";
    let start = line.find(marker)? + marker.len();
    let rest = &line[start..];
    let end = rest.find('>')?;
    let name: String = rest[..end]
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '.')
        .collect();
    if name.is_empty() {
        return None;
    }
    if !rest[end..].contains("get;") && !rest[end..].contains('{') {
        return None;
    }
    Some(name.rsplit('.').next().unwrap_or(&name).to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        analyze, MappingEvidence, PATTERN_DYNAMIC_TABLE, REASON_CONVENTION_NOT_EXPLICIT,
        REASON_DYNAMIC_TABLE,
    };
    use crate::l3::FactQuality;

    #[test]
    fn explicit_attribute_and_fluent_mappings_are_retained() {
        let source = r#"
namespace Shop.Data;

[Table("Orders", Schema = "dbo")]
public class Order
{
    public int Id { get; set; }
}

public class ShopContext : DbContext
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Customer>().ToTable("Customers");
        modelBuilder.Entity<Invoice>().ToTable("Invoices", "billing");
    }
}
"#;
        let analysis = analyze("Shop/Data/ShopContext.cs", source);
        assert_eq!(analysis.mappings.len(), 3);
        let order = analysis.mapping_for("Order").expect("attribute mapping");
        assert_eq!(order.table, "Orders");
        assert_eq!(order.schema.as_deref(), Some("dbo"));
        assert_eq!(order.evidence, MappingEvidence::Attribute);
        assert_eq!(order.quality, FactQuality::ExactStatic);
        assert_eq!(order.qualified_table(), "dbo.Orders");
        let customer = analysis.mapping_for("Customer").expect("fluent mapping");
        assert_eq!(customer.table, "Customers");
        assert_eq!(customer.evidence, MappingEvidence::Fluent);
        let invoice = analysis.mapping_for("Invoice").expect("fluent mapping");
        assert_eq!(invoice.qualified_table(), "billing.Invoices");
    }

    #[test]
    fn conventions_and_runtime_names_are_never_invented() {
        let source = r#"
public class ShopContext : DbContext
{
    public DbSet<Order> Orders { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Order>();
        modelBuilder.Entity<Product>().ToTable(tableName);
    }
}

[Table]
public class Legacy
{
}
"#;
        let analysis = analyze("Shop/Data/ShopContext.cs", source);
        assert!(analysis.mappings.is_empty());
        assert!(analysis.has_unresolved());
        assert!(analysis.unresolved.iter().all(|entry| {
            entry.reason == REASON_CONVENTION_NOT_EXPLICIT || entry.reason == REASON_DYNAMIC_TABLE
        }));
        assert!(analysis
            .unresolved
            .iter()
            .any(|entry| entry.reason == REASON_DYNAMIC_TABLE
                && entry.entity.as_deref() == Some("Product")));
        assert!(analysis
            .unresolved
            .iter()
            .any(|entry| entry.entity.as_deref() == Some("Order")
                && entry.pattern == super::PATTERN_ENTITY_CONVENTION));
        assert!(analysis
            .unresolved
            .iter()
            .any(|entry| entry.entity.as_deref() == Some("Legacy")));
    }

    #[test]
    fn a_dynamic_table_attribute_is_unresolved_not_ignored() {
        let source = r#"
[Table(nameof(LegacyOrder))]
public class LegacyOrder
{
}
"#;
        let analysis = analyze("Legacy.cs", source);
        assert!(analysis.mappings.is_empty());
        assert_eq!(analysis.unresolved.len(), 1);
        assert_eq!(analysis.unresolved[0].pattern, PATTERN_DYNAMIC_TABLE);
        assert_eq!(analysis.unresolved[0].reason, REASON_DYNAMIC_TABLE);
    }

    #[test]
    fn a_literal_dbset_is_still_only_a_convention() {
        let source = "public DbSet<Customer> Customer { get; set; }";
        let analysis = analyze("Ctx.cs", source);
        assert!(analysis.mappings.is_empty());
        assert_eq!(analysis.unresolved.len(), 1);
        assert_eq!(
            analysis.unresolved[0].reason,
            REASON_CONVENTION_NOT_EXPLICIT
        );
    }
}
