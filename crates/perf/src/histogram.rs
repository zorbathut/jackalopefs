//! Log-linear histograms of latencies and sizes, kept as counts since the process started so that a reader takes quantiles over any interval from the difference of two readings: the time_stats idea from bcachefs, made exact for windows rather than an exponentially weighted estimate.
//!
//! Buckets are `(lo, hi]`, four to each power of two above 4 and one each for 0 to 4, so a bucket is at most 25% wide and a power of two (a 4 KiB read, a 128 KiB readahead) is the exact upper bound of its own. On the wire a bucket goes as its upper bound and count, so a reader needs none of this.

use jackalopefs_proto::control::Bucket;

/// One bucket for each of 0 to 4, then four for each power of two up to 2^64.
pub(crate) const BUCKETS: usize = 5 + 4 * 62;

/// The bucket of `v`.
pub(crate) fn bucket(v: u64) -> usize {
    if v <= 4 {
        return v as usize;
    }
    // Taken on v - 1, so a bucket's upper bound belongs to it.
    let x = v - 1;
    let e = 63 - x.leading_zeros() as usize;
    let quarter = ((x >> (e - 2)) & 3) as usize;
    5 + 4 * (e - 2) + quarter
}

/// The largest value in bucket `i`.
pub(crate) fn upper(i: usize) -> u64 {
    if i <= 4 {
        return i as u64;
    }
    let e = (i - 5) / 4 + 2;
    let quarter = ((i - 5) % 4) as u128;
    let hi = (1u128 << e) + (quarter + 1) * (1u128 << (e - 2));
    u64::try_from(hi).unwrap_or(u64::MAX)
}

#[derive(Clone)]
pub struct Histogram(Box<[u64; BUCKETS]>);

impl Default for Histogram {
    fn default() -> Histogram {
        Histogram(Box::new([0; BUCKETS]))
    }
}

impl Histogram {
    pub fn record(&mut self, v: u64) {
        self.0[bucket(v)] += 1;
    }

    /// The buckets that have counts, by upper bound.
    pub fn buckets(&self) -> Vec<Bucket> {
        self.0
            .iter()
            .enumerate()
            .filter(|(_, count)| **count > 0)
            .map(|(i, count)| Bucket {
                upper: upper(i),
                count: *count,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_value_is_in_its_bucket_and_buckets_rise_with_values() {
        let mut values: Vec<u64> = (0..=20).collect();
        for k in 3..64 {
            let p = 1u64 << k;
            values.extend([p - 1, p, p + 1, p + p / 4, p + p / 4 + 1]);
        }
        values.push(u64::MAX);
        values.sort_unstable();
        let mut last = 0;
        for v in values {
            let i = bucket(v);
            assert!(i < BUCKETS, "{v} in bucket {i}");
            assert!(
                v <= upper(i),
                "{v} above its bucket {i}'s bound {}",
                upper(i)
            );
            assert!(i == 0 || v > upper(i - 1), "{v} belongs below bucket {i}");
            assert!(i >= last, "bucket of {v} fell");
            last = i;
        }
    }

    #[test]
    fn powers_of_two_bound_their_buckets_exactly() {
        for k in 0..64 {
            let p = 1u64 << k;
            assert_eq!(upper(bucket(p)), p);
        }
        assert_eq!(upper(BUCKETS - 1), u64::MAX);
    }

    #[test]
    fn a_bucket_is_at_most_a_quarter_wide() {
        for i in 6..BUCKETS - 1 {
            let (lo, hi) = (upper(i - 1), upper(i));
            assert!(
                (hi - lo) as f64 <= 0.25 * lo as f64 + 1.0,
                "bucket {i}: ({lo}, {hi}]"
            );
        }
    }

    #[test]
    fn only_counted_buckets_are_listed() {
        let mut h = Histogram::default();
        h.record(4096);
        h.record(4096);
        h.record(131072);
        assert_eq!(
            h.buckets(),
            vec![
                Bucket {
                    upper: 4096,
                    count: 2
                },
                Bucket {
                    upper: 131072,
                    count: 1
                },
            ]
        );
    }
}
