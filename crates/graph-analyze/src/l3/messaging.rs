//! Explicit messaging topic patterns (task B-063).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 2 lists literal publish and
//! subscribe calls and topic attributes as the supported messaging subset, and
//! requires a topic that only exists at runtime to be reported as unsupported.
//! Two boundaries follow from that:
//!
//! * the adapter reads a topic only from exactly one string literal argument;
//!   `Publish(topicName)` and `Publish($"orders.{id}")` are computed values and
//!   stay unresolved;
//! * a producer and a consumer are linked only when the operator configured the
//!   topic for the solution. A literal topic nobody configured is recorded as
//!   unresolved rather than being paired by name similarity.
//!
//! Nothing here connects to a broker and no message is ever sent.

use crate::{Diagnostic, Span};

use super::{
    lines_with_offsets, parse_string_literal, split_arguments, strip_line_comment, FactQuality,
};

/// Pattern id for a literal publish call.
pub const PATTERN_PUBLISH: &str = "messaging-publish";
/// Pattern id for a literal subscribe or consume call.
pub const PATTERN_SUBSCRIBE: &str = "messaging-subscribe";
/// Pattern id for a literal topic attribute.
pub const PATTERN_TOPIC_ATTRIBUTE: &str = "messaging-topic-attribute";
/// Pattern id for a publish or subscribe call with a computed topic.
pub const PATTERN_DYNAMIC_TOPIC: &str = "messaging-dynamic-topic";

/// Reason recorded when a topic expression is computed at runtime.
pub const REASON_DYNAMIC_TOPIC: &str = "unresolved-dynamic-topic";
/// Reason recorded when a literal topic is not part of the solution mapping.
pub const REASON_TOPIC_NOT_CONFIGURED: &str = "unresolved-topic-not-configured";

/// Which side of a topic a file sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MessagingRole {
    /// The source publishes to the topic.
    Producer,
    /// The source subscribes to or consumes the topic.
    Consumer,
}

impl MessagingRole {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Producer => "producer",
            Self::Consumer => "consumer",
        }
    }
}

/// One literal topic binding found in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicBinding {
    /// Owning project.
    pub project: String,
    /// Declaring file.
    pub file: String,
    /// Which side of the topic this binding is.
    pub role: MessagingRole,
    /// The literal topic name.
    pub topic: String,
    /// Quality of the binding; a single literal is `exact_static`.
    pub quality: FactQuality,
    /// Span of the binding.
    pub span: Span,
}

/// One messaging fragment this adapter refused to analyse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedTopic {
    /// Owning file.
    pub file: String,
    /// Which side of the topic the fragment would have been.
    pub role: MessagingRole,
    /// A `PATTERN_*` id naming what was not analysed.
    pub pattern: String,
    /// A `REASON_*` value explaining the refusal.
    pub reason: String,
    /// Span of the fragment.
    pub span: Span,
}

/// Result of scanning one source file for messaging bindings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MessagingAnalysis {
    /// Literal bindings, in source order.
    pub bindings: Vec<TopicBinding>,
    /// Refused fragments, in source order.
    pub unresolved: Vec<UnresolvedTopic>,
    /// Diagnostics attached to the file.
    pub diagnostics: Vec<Diagnostic>,
}

impl MessagingAnalysis {
    /// Whether any fragment was refused instead of analysed.
    #[must_use]
    pub fn has_unresolved(&self) -> bool {
        !self.unresolved.is_empty()
    }

    /// Literal bindings on one side, in source order.
    #[must_use]
    pub fn bindings_for(&self, role: MessagingRole) -> Vec<&TopicBinding> {
        self.bindings
            .iter()
            .filter(|binding| binding.role == role)
            .collect()
    }
}

/// Producer-side calls this adapter recognises.
const PUBLISH_CALLS: [&str; 5] = [
    "PublishAsync",
    "Publish",
    "ProduceAsync",
    "Produce",
    "SendAsync",
];
/// Consumer-side calls this adapter recognises.
const SUBSCRIBE_CALLS: [&str; 4] = ["SubscribeAsync", "Subscribe", "ConsumeAsync", "Consume"];
/// Topic attributes this adapter recognises as consumer subscriptions.
const TOPIC_ATTRIBUTES: [&str; 4] = [
    "[Topic(",
    "[KafkaTopic(",
    "[ServiceBusTopic(",
    "[ServiceBusQueue(",
];

/// The text between the first `(` after `marker` and its matching `)`.
fn parenthesised<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let start = line.find(marker)? + marker.len();
    let rest = &line[start..];
    let rest = rest.strip_prefix('(').unwrap_or(rest);
    let mut depth = 0_i32;
    let mut in_string: Option<char> = None;
    let mut escaped = false;
    for (index, ch) in rest.char_indices() {
        if let Some(quote) = in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                in_string = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => in_string = Some(ch),
            '(' => depth += 1,
            ')' => {
                if depth == 0 {
                    return Some(&rest[..index]);
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    None
}

/// The first literal argument, or `None` when the first argument is computed.
fn first_argument_is_literal(arguments: &str) -> Option<Option<String>> {
    let first = split_arguments(arguments).into_iter().next()?;
    Some(parse_string_literal(first.trim()))
}

/// Scan one source file for literal topic bindings.
///
/// `project` is the owning project of `file`, so a binding can be linked later
/// without re-reading the file.
#[must_use]
pub fn analyze(project: &str, file: &str, source: &str) -> MessagingAnalysis {
    let mut analysis = MessagingAnalysis::default();
    for (offset, raw_line) in lines_with_offsets(source) {
        let line = strip_line_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let span = Span::new(offset, offset + line.len());
        for attribute in TOPIC_ATTRIBUTES {
            if let Some(arguments) = parenthesised(trimmed, attribute) {
                match first_argument_is_literal(arguments) {
                    Some(Some(topic)) => analysis.bindings.push(TopicBinding {
                        project: project.to_string(),
                        file: file.to_string(),
                        role: MessagingRole::Consumer,
                        topic,
                        quality: FactQuality::ExactStatic,
                        span,
                    }),
                    Some(None) | None => analysis.unresolved.push(UnresolvedTopic {
                        file: file.to_string(),
                        role: MessagingRole::Consumer,
                        pattern: PATTERN_TOPIC_ATTRIBUTE.to_string(),
                        reason: REASON_DYNAMIC_TOPIC.to_string(),
                        span,
                    }),
                }
            }
        }
        for (calls, role, pattern) in [
            (&PUBLISH_CALLS[..], MessagingRole::Producer, PATTERN_PUBLISH),
            (
                &SUBSCRIBE_CALLS[..],
                MessagingRole::Consumer,
                PATTERN_SUBSCRIBE,
            ),
        ] {
            for call in calls {
                let marker = format!(".{call}");
                if !trimmed.contains(marker.as_str()) {
                    continue;
                }
                let Some(arguments) = parenthesised(trimmed, marker.as_str()) else {
                    continue;
                };
                match first_argument_is_literal(arguments) {
                    Some(Some(topic)) => analysis.bindings.push(TopicBinding {
                        project: project.to_string(),
                        file: file.to_string(),
                        role,
                        topic,
                        quality: FactQuality::ExactStatic,
                        span,
                    }),
                    Some(None) => analysis.unresolved.push(UnresolvedTopic {
                        file: file.to_string(),
                        role,
                        pattern: pattern.to_string(),
                        reason: REASON_DYNAMIC_TOPIC.to_string(),
                        span,
                    }),
                    None => {}
                }
                break;
            }
        }
    }
    analysis
}

/// One topic the solution operator configured for linking.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConfiguredTopic {
    /// The literal topic name.
    pub topic: String,
    /// The project that owns the topic contract.
    pub project: String,
}

/// The configured topic set of one solution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MessagingConfig {
    /// Configured topics.
    pub topics: Vec<ConfiguredTopic>,
}

impl MessagingConfig {
    /// The owning project of a configured topic, when configured exactly once.
    #[must_use]
    pub fn owner_of(&self, topic: &str) -> Option<&str> {
        let mut found: Option<&str> = None;
        for configured in &self.topics {
            if configured.topic == topic {
                if found.is_some_and(|previous| previous != configured.project) {
                    return None;
                }
                found = Some(&configured.project);
            }
        }
        found
    }
}

/// One producer-to-consumer link through a configured topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicLink {
    /// The configured topic.
    pub topic: String,
    /// Project that owns the topic contract.
    pub topic_project: String,
    /// The producing project.
    pub producer_project: String,
    /// The consuming project.
    pub consumer_project: String,
    /// Quality of the link; a single producer and consumer is `exact_static`,
    /// a fan-out stays `inferred_static`.
    pub quality: FactQuality,
}

/// A binding the link refused to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlinkedTopicBinding {
    /// The binding's project.
    pub project: String,
    /// The binding's file.
    pub file: String,
    /// The binding's role.
    pub role: MessagingRole,
    /// The literal topic as written.
    pub topic: String,
    /// A `REASON_*` value explaining why no link was made.
    pub reason: String,
}

/// Result of linking producer and consumer bindings through configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MessagingLinkReport {
    /// Links, ordered by topic then producer then consumer.
    pub links: Vec<TopicLink>,
    /// Bindings that produced no link, in binding order.
    pub unlinked: Vec<UnlinkedTopicBinding>,
    /// Topics that have a producer but no consumer, or the reverse.
    pub unmatched_topics: Vec<String>,
}

impl MessagingLinkReport {
    /// Whether any binding was left out of the links.
    #[must_use]
    pub fn has_unresolved(&self) -> bool {
        !self.unlinked.is_empty() || !self.unmatched_topics.is_empty()
    }
}

/// Link literal bindings through the configured topic set.
#[must_use]
pub fn link(bindings: &[TopicBinding], config: &MessagingConfig) -> MessagingLinkReport {
    let mut report = MessagingLinkReport::default();
    let mut usable: Vec<&TopicBinding> = Vec::new();
    for binding in bindings {
        if config.owner_of(&binding.topic).is_none() {
            report.unlinked.push(UnlinkedTopicBinding {
                project: binding.project.clone(),
                file: binding.file.clone(),
                role: binding.role,
                topic: binding.topic.clone(),
                reason: REASON_TOPIC_NOT_CONFIGURED.to_string(),
            });
            continue;
        }
        usable.push(binding);
    }
    let mut topics: Vec<String> = usable.iter().map(|binding| binding.topic.clone()).collect();
    topics.sort();
    topics.dedup();
    for topic in topics {
        let Some(topic_project) = config.owner_of(&topic) else {
            continue;
        };
        let mut producers: Vec<&str> = usable
            .iter()
            .filter(|binding| binding.topic == topic && binding.role == MessagingRole::Producer)
            .map(|binding| binding.project.as_str())
            .collect();
        let mut consumers: Vec<&str> = usable
            .iter()
            .filter(|binding| binding.topic == topic && binding.role == MessagingRole::Consumer)
            .map(|binding| binding.project.as_str())
            .collect();
        producers.sort_unstable();
        producers.dedup();
        consumers.sort_unstable();
        consumers.dedup();
        if producers.is_empty() || consumers.is_empty() {
            report.unmatched_topics.push(topic);
            continue;
        }
        let unique = producers.len() == 1 && consumers.len() == 1;
        for producer in &producers {
            for consumer in &consumers {
                if producer == consumer {
                    continue;
                }
                report.links.push(TopicLink {
                    topic: topic.clone(),
                    topic_project: topic_project.to_string(),
                    producer_project: (*producer).to_string(),
                    consumer_project: (*consumer).to_string(),
                    quality: if unique {
                        FactQuality::ExactStatic
                    } else {
                        FactQuality::InferredStatic
                    },
                });
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::{
        analyze, link, ConfiguredTopic, MessagingConfig, MessagingRole, REASON_DYNAMIC_TOPIC,
        REASON_TOPIC_NOT_CONFIGURED,
    };
    use crate::l3::FactQuality;

    #[test]
    fn literal_producers_and_consumers_link_through_configuration() {
        let producer = analyze(
            "Orders",
            "Orders/Messaging/OrderPublisher.cs",
            "await bus.PublishAsync(\"orders.created\", message);",
        );
        let consumer = analyze(
            "Billing",
            "Billing/Messaging/OrderConsumer.cs",
            "bus.Subscribe(\"orders.created\");",
        );
        assert_eq!(producer.bindings.len(), 1);
        assert_eq!(producer.bindings[0].role, MessagingRole::Producer);
        assert_eq!(consumer.bindings.len(), 1);
        assert_eq!(consumer.bindings[0].role, MessagingRole::Consumer);
        let config = MessagingConfig {
            topics: vec![ConfiguredTopic {
                topic: "orders.created".to_string(),
                project: "Orders".to_string(),
            }],
        };
        let bindings: Vec<_> = producer
            .bindings
            .iter()
            .chain(consumer.bindings.iter())
            .cloned()
            .collect();
        let report = link(&bindings, &config);
        assert_eq!(report.links.len(), 1);
        let topic_link = &report.links[0];
        assert_eq!(topic_link.topic_project, "Orders");
        assert_eq!(topic_link.producer_project, "Orders");
        assert_eq!(topic_link.consumer_project, "Billing");
        assert_eq!(topic_link.quality, FactQuality::ExactStatic);
        assert!(!report.has_unresolved());
    }

    #[test]
    fn unknown_topic_expressions_stay_unresolved() {
        let analysis = analyze(
            "Orders",
            "Orders/Messaging/OrderPublisher.cs",
            r#"
                await bus.PublishAsync(topicName, message);
                await bus.PublishAsync($"orders.{tenant}", message);
                await bus.Subscribe("orders.created");
            "#,
        );
        assert_eq!(analysis.bindings.len(), 1);
        assert_eq!(analysis.unresolved.len(), 2);
        assert!(analysis
            .unresolved
            .iter()
            .all(|entry| entry.reason == REASON_DYNAMIC_TOPIC));
        assert_eq!(analysis.unresolved[0].role, MessagingRole::Producer);
        // The computed fragments never became literal bindings.
        assert_eq!(analysis.bindings_for(MessagingRole::Producer).len(), 0);
    }

    #[test]
    fn an_unconfigured_literal_topic_is_not_linked() {
        let binding = analyze(
            "Orders",
            "p.cs",
            "broker.Publish(\"orders.deleted\", payload);",
        );
        let config = MessagingConfig {
            topics: vec![ConfiguredTopic {
                topic: "orders.created".to_string(),
                project: "Orders".to_string(),
            }],
        };
        let report = link(&binding.bindings, &config);
        assert!(report.links.is_empty());
        assert_eq!(report.unlinked.len(), 1);
        assert_eq!(report.unlinked[0].reason, REASON_TOPIC_NOT_CONFIGURED);
        assert!(report.has_unresolved());
    }

    #[test]
    fn a_topic_without_a_consumer_is_reported_as_unmatched() {
        let binding = analyze(
            "Orders",
            "p.cs",
            "broker.Publish(\"orders.created\", payload);",
        );
        let config = MessagingConfig {
            topics: vec![ConfiguredTopic {
                topic: "orders.created".to_string(),
                project: "Orders".to_string(),
            }],
        };
        let report = link(&binding.bindings, &config);
        assert!(report.links.is_empty());
        assert_eq!(report.unmatched_topics, vec!["orders.created".to_string()]);
    }

    #[test]
    fn a_topic_attribute_declares_a_consumer_binding() {
        let analysis = analyze(
            "Billing",
            "Billing/Consumers/OrderConsumer.cs",
            "[Topic(\"orders.created\")]\npublic class OrderConsumer : IConsumer<OrderCreated> { }",
        );
        assert_eq!(analysis.bindings.len(), 1);
        assert_eq!(analysis.bindings[0].role, MessagingRole::Consumer);
        assert_eq!(analysis.bindings[0].topic, "orders.created");
    }

    #[test]
    fn a_fan_out_topic_stays_inferred_static() {
        let first = analyze("A", "a.cs", "bus.Publish(\"orders.created\", m);");
        let second = analyze("B", "b.cs", "bus.Publish(\"orders.created\", m);");
        let consumer = analyze("C", "c.cs", "bus.Subscribe(\"orders.created\");");
        let config = MessagingConfig {
            topics: vec![ConfiguredTopic {
                topic: "orders.created".to_string(),
                project: "Orders".to_string(),
            }],
        };
        let bindings: Vec<_> = first
            .bindings
            .iter()
            .chain(second.bindings.iter())
            .chain(consumer.bindings.iter())
            .cloned()
            .collect();
        let report = link(&bindings, &config);
        assert_eq!(report.links.len(), 2);
        assert!(report
            .links
            .iter()
            .all(|topic_link| topic_link.quality == FactQuality::InferredStatic));
    }
}
