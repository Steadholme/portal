//! The dashboard's live data snapshot: one concurrent fetch of every backend, cached a few
//! seconds.
//!
//! A page load needs both Beacon projections (public and operator), Vitals (host gauges), and
//! Watchtower (audit count + recent activity). All five requests fan out CONCURRENTLY via
//! `tokio::join!`, each independently resilient: a down backend leaves its slice at its default
//! ("unknown"/"—"/empty) and never blocks the others. The whole result is cached for
//! [`CACHE_TTL`], so back-to-back loads share one refresh.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::{beacon, vitals, watchtower};

/// How long a fetched snapshot stays fresh before the next page load refetches.
pub const CACHE_TTL: Duration = Duration::from_secs(5);

/// An aggregated, render-ready view of every backend. Cheap to share behind `Arc`.
#[derive(Debug, Default)]
pub struct Snapshot {
    /// Beacon public projection: the only component statuses external dashboard responses may
    /// render.
    pub public_statuses: beacon::Statuses,
    /// Beacon operator projection: the full component snapshot for attested Estate and `/ops`.
    pub operator_statuses: beacon::Statuses,
    /// Vitals: latest host gauges (CPU %, memory %, load).
    pub metrics: vitals::Metrics,
    /// Watchtower: audit-chain length + integrity flag.
    pub verify: watchtower::Verify,
    /// Watchtower: the recent-activity feed (newest-first, already truncated).
    pub events: Vec<watchtower::Event>,
}

impl Snapshot {
    /// Fan out one concurrent fetch of every backend and assemble the snapshot. Always
    /// succeeds: unreachable backends contribute their default (empty) slice.
    pub async fn fetch(config: &Config) -> Snapshot {
        let (public_statuses, operator_statuses, metrics, verify, events) = tokio::join!(
            beacon::fetch(&config.beacon_public_url),
            beacon::fetch(&config.beacon_url),
            vitals::fetch(&config.vitals_url),
            watchtower::fetch_verify(&config.watchtower_url),
            watchtower::fetch_events(&config.watchtower_url),
        );
        Snapshot {
            public_statuses,
            operator_statuses,
            metrics,
            verify,
            events,
        }
    }
}

/// The cached cell: the freshest snapshot tagged with when it was taken (empty until the
/// first fetch).
type Cached = Mutex<Option<(Instant, Arc<Snapshot>)>>;

/// A few-second cache around [`Snapshot::fetch`]. Cheap to clone (state behind `Arc`).
#[derive(Clone)]
pub struct SnapshotCache {
    ttl: Duration,
    inner: Arc<Cached>,
}

impl SnapshotCache {
    /// New cache with the given freshness window.
    pub fn new(ttl: Duration) -> Self {
        SnapshotCache {
            ttl,
            inner: Arc::new(Mutex::new(None)),
        }
    }

    /// Return the live snapshot, serving a cached one while it is fresh and otherwise
    /// refetching every backend concurrently. The lock is never held across the network
    /// `.await`, so concurrent page loads stay non-blocking.
    pub async fn get(&self, config: &Config) -> Arc<Snapshot> {
        if let Some((at, snap)) = self.inner.lock().unwrap().as_ref() {
            if at.elapsed() < self.ttl {
                return Arc::clone(snap);
            }
        }
        let fresh = Arc::new(Snapshot::fetch(config).await);
        *self.inner.lock().unwrap() = Some((Instant::now(), Arc::clone(&fresh)));
        fresh
    }
}
