//! Deterministic sharding of a record set (task B-068).
//!
//! A bucket is chosen by hashing the record key, so a key always lands in the
//! same bucket for a given bucket count, in this process and in the next one.
//! That is why the bucket function is SHA-256 based instead of using the
//! standard library's randomised hasher: a published locator must stay valid.
//!
//! Two rules shape the plan:
//!
//! * a bucket that holds records always exists and keeps its name. Buckets that
//!   hold nothing are not published, so adding records to an unrelated bucket
//!   cannot move this one;
//! * a bucket whose bytes exceed the cap is split into byte-capped parts
//!   deterministically, and a part never depends on any other bucket. A single
//!   record that cannot fit inside the cap is an error, not a silently oversized
//!   shard.

use crate::canonical::canonical_record;
use crate::{ExportError, GraphRecord, Result};

/// Error code for a record that cannot fit inside the shard byte cap.
pub const ERR_RECORD_TOO_LARGE: &str = "export-record-too-large";

/// How a record set is divided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardPolicy {
    /// Number of hash buckets. At least one.
    pub bucket_count: usize,
    /// Maximum canonical bytes in one published shard.
    pub max_bytes: usize,
}

impl Default for ShardPolicy {
    fn default() -> Self {
        Self {
            bucket_count: 256,
            max_bytes: 4 * 1024 * 1024,
        }
    }
}

/// The stable bucket of `key` for `bucket_count` buckets.
#[must_use]
pub fn bucket_of(key: &str, bucket_count: usize) -> usize {
    let count = bucket_count.max(1);
    if count == 1 {
        return 0;
    }
    let digest = crate::sha256_bytes(key.as_bytes());
    let mut first_eight = [0_u8; 8];
    first_eight.copy_from_slice(&digest[..8]);
    (u64::from_be_bytes(first_eight) % count as u64) as usize
}

/// The stable directory name of a bucket.
#[must_use]
pub fn bucket_name(bucket: usize, bucket_count: usize) -> String {
    let width = (bucket_count.max(1) - 1).to_string().len().max(3);
    format!("bucket-{bucket:0width$}")
}

/// One shard the plan will publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedShard {
    /// The hash bucket this shard belongs to.
    pub bucket: usize,
    /// Stable shard name: `bucket-003` or `bucket-003/part-000`.
    pub name: String,
    /// Canonical byte length of the shard.
    pub byte_len: usize,
    /// Record keys in the shard, in canonical order.
    pub record_keys: Vec<String>,
    /// SHA-256 of the shard bytes.
    pub sha256: String,
}

/// A deterministic shard plan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShardPlan {
    /// Shards, ordered by bucket then part.
    pub shards: Vec<PlannedShard>,
}

impl ShardPlan {
    /// Shards belonging to one bucket, in part order.
    #[must_use]
    pub fn shards_for(&self, bucket: usize) -> Vec<&PlannedShard> {
        self.shards
            .iter()
            .filter(|shard| shard.bucket == bucket)
            .collect()
    }

    /// Buckets that have at least one shard, in ascending order.
    #[must_use]
    pub fn buckets(&self) -> Vec<usize> {
        let mut buckets: Vec<usize> = self.shards.iter().map(|shard| shard.bucket).collect();
        buckets.sort_unstable();
        buckets.dedup();
        buckets
    }

    /// Total published bytes.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.shards.iter().map(|shard| shard.byte_len).sum()
    }

    /// Whether every shard respects the policy's byte cap.
    #[must_use]
    pub fn respects_cap(&self, policy: &ShardPolicy) -> bool {
        self.shards
            .iter()
            .all(|shard| shard.byte_len <= policy.max_bytes)
    }
}

/// Plan the shards of `records` under `policy`.
///
/// # Errors
///
/// Returns [`ERR_RECORD_TOO_LARGE`] when a single record's canonical bytes
/// exceed the cap, because no cap-respecting split can publish it.
pub fn plan(records: &[GraphRecord], policy: &ShardPolicy) -> Result<ShardPlan> {
    let mut buckets: Vec<usize> = records
        .iter()
        .map(|record| bucket_of(&record.key, policy.bucket_count))
        .collect();
    buckets.sort_unstable();
    buckets.dedup();
    let mut plan = ShardPlan::default();
    for bucket in buckets {
        let mut owned: Vec<&GraphRecord> = records
            .iter()
            .filter(|record| bucket_of(&record.key, policy.bucket_count) == bucket)
            .collect();
        owned.sort_by(|left, right| left.key.cmp(&right.key));
        let parts = split_bucket(&owned, policy, bucket)?;
        plan.shards.extend(parts);
    }
    Ok(plan)
}

/// Split one bucket's records into byte-capped parts.
fn split_bucket(
    records: &[&GraphRecord],
    policy: &ShardPolicy,
    bucket: usize,
) -> Result<Vec<PlannedShard>> {
    let base = bucket_name(bucket, policy.bucket_count);
    let mut parts: Vec<PlannedShard> = Vec::new();
    let mut current_bytes = Vec::new();
    let mut current_keys = Vec::new();
    let mut part = 0_usize;
    let flush = |part: usize,
                 bytes: &mut Vec<u8>,
                 keys: &mut Vec<String>,
                 parts: &mut Vec<PlannedShard>|
     -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let name = if parts.is_empty() && part == 0 {
            base.clone()
        } else {
            format!("{base}/part-{part:03}")
        };
        let sha256 = crate::sha256_hex(bytes);
        parts.push(PlannedShard {
            bucket,
            name,
            byte_len: bytes.len(),
            record_keys: std::mem::take(keys),
            sha256,
        });
        bytes.clear();
        Ok(())
    };
    for record in records {
        let line = canonical_record(record)?;
        if line.len() + 1 > policy.max_bytes {
            return Err(ExportError::new(
                ERR_RECORD_TOO_LARGE,
                format!(
                    "record {} needs {} bytes but the shard cap is {}",
                    record.key,
                    line.len() + 1,
                    policy.max_bytes
                ),
            ));
        }
        if !current_bytes.is_empty() && current_bytes.len() + line.len() + 1 > policy.max_bytes {
            let name_parts = parts.len();
            let part_index = if name_parts == 0 { 0 } else { part };
            flush(
                part_index,
                &mut current_bytes,
                &mut current_keys,
                &mut parts,
            )?;
            part += 1;
        }
        current_bytes.extend_from_slice(line.as_bytes());
        current_bytes.push(b'\n');
        current_keys.push(record.key.clone());
    }
    let part_index = if parts.is_empty() { 0 } else { part };
    flush(
        part_index,
        &mut current_bytes,
        &mut current_keys,
        &mut parts,
    )?;
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{bucket_name, bucket_of, plan, ShardPolicy, ERR_RECORD_TOO_LARGE};
    use crate::GraphRecord;

    fn record(key: &str) -> GraphRecord {
        GraphRecord::new(key, "edge", json!({"from": "a", "to": "b"}))
    }

    #[test]
    fn a_bucket_is_stable_for_a_key() {
        let bucket = bucket_of("edge:a->b", 256);
        assert_eq!(bucket, bucket_of("edge:a->b", 256));
        assert!(bucket < 256);
        assert_eq!(bucket_of("anything", 1), 0);
        assert_eq!(bucket_name(3, 256), "bucket-003");
        assert_eq!(bucket_name(7, 16), "bucket-007");
    }

    #[test]
    fn nonempty_buckets_stay_stable_when_other_buckets_change() {
        let policy = ShardPolicy {
            bucket_count: 16,
            max_bytes: 4096,
        };
        let first = vec![record("edge:a->b"), record("edge:b->c")];
        let mut second = first.clone();
        second.push(record("edge:c->d"));
        let plan_a = plan(&first, &policy).expect("plan");
        let plan_b = plan(&second, &policy).expect("plan");
        for shard in &plan_a.shards {
            let counterpart = plan_b
                .shards
                .iter()
                .find(|candidate| candidate.name == shard.name)
                .expect("bucket survives");
            assert_eq!(counterpart.record_keys, shard.record_keys);
            assert_eq!(counterpart.sha256, shard.sha256);
        }
    }

    #[test]
    fn an_oversized_bucket_splits_into_capped_parts_deterministically() {
        let policy = ShardPolicy {
            bucket_count: 1,
            max_bytes: 120,
        };
        let records: Vec<GraphRecord> = (0..6).map(|n| record(&format!("edge:{n:03}"))).collect();
        let first = plan(&records, &policy).expect("plan");
        let second = plan(&records, &policy).expect("plan");
        assert_eq!(first, second);
        assert!(first.buckets() == vec![0]);
        assert!(first.shards.len() > 1);
        assert!(first.respects_cap(&policy));
        assert!(first.shards.iter().all(|shard| shard.byte_len <= 120));
        assert_eq!(first.shards[0].name, "bucket-000");
        assert!(first.shards[1].name.starts_with("bucket-000/part-"));
        let total_keys: usize = first
            .shards
            .iter()
            .map(|shard| shard.record_keys.len())
            .sum();
        assert_eq!(total_keys, records.len());
    }

    #[test]
    fn a_split_does_not_depend_on_other_buckets() {
        let policy = ShardPolicy {
            bucket_count: 8,
            max_bytes: 140,
        };
        let target: Vec<GraphRecord> = (0..4)
            .map(|n| record(&format!("edge:target:{n}")))
            .collect();
        let bucket = bucket_of("edge:target:0", 8);
        // Only keys that hash to a different bucket can prove independence, so
        // pick them by hashing rather than by name.
        let mut with_others = target.clone();
        let mut candidate = 0;
        while with_others.len() == target.len() {
            let key = format!("edge:other:{candidate}");
            if bucket_of(&key, 8) != bucket {
                with_others.push(record(&key));
            }
            candidate += 1;
        }
        assert!(with_others
            .iter()
            .skip(target.len())
            .all(|extra| bucket_of(&extra.key, 8) != bucket));
        let plan_a = plan(&target, &policy).expect("plan");
        let plan_b = plan(&with_others, &policy).expect("plan");
        assert_eq!(
            plan_a.shards_for(bucket),
            plan_b.shards_for(bucket),
            "an unrelated bucket changed this bucket's parts"
        );
    }

    #[test]
    fn a_single_record_over_the_cap_is_an_error_not_an_oversized_shard() {
        let policy = ShardPolicy {
            bucket_count: 4,
            max_bytes: 8,
        };
        let error = plan(&[record("edge:a->b")], &policy).expect_err("must refuse");
        assert_eq!(error.code, ERR_RECORD_TOO_LARGE);
    }
}
