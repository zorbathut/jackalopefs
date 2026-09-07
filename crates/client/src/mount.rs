//! Mount lifecycle: FUSE session, invalidator, and client, started and torn down together.

use crate::client::Client;
use crate::fuse::{Backend, Shared};
use crate::invalidate::Invalidator;
use crate::perf::{Perf, TRACE_TARGET};
use anyhow::Context;
use fuser::{BackgroundSession, MountOption, SessionACL};
use jackalopefs_perf::line_quic;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Where the kernel publishes what it granted this mount. What `init` asked for is only a request: the readahead in particular is capped by the mount's backing-device setting, and the queue limits are whatever the kernel accepted.
struct KernelLimits {
    /// `/sys/fs/fuse/connections/<minor>`: `max_background`, `congestion_threshold`, and `waiting`, the requests queued for the daemon right now.
    connection: PathBuf,
    /// `/sys/class/bdi/0:<minor>`: `read_ahead_kb`, the ceiling on every read the kernel issues.
    bdi: PathBuf,
}

impl KernelLimits {
    /// Locate the mount's sysfs entries; nothing here goes through the mount itself, so a slow or lost server cannot delay or fail the mount over a diagnostic.
    fn find(mountpoint: &Path) -> Option<KernelLimits> {
        let table = match std::fs::read_to_string("/proc/self/mountinfo") {
            Ok(table) => table,
            Err(e) => {
                tracing::warn!("cannot read /proc/self/mountinfo: {e}; the kernel's FUSE limits cannot be reported");
                return None;
            }
        };
        let Some(minor) = mount_minor(&table, &spelled_by_kernel(mountpoint)) else {
            tracing::warn!(
                "{} is not in /proc/self/mountinfo; the kernel's FUSE limits cannot be reported",
                mountpoint.display()
            );
            return None;
        };
        let limits = KernelLimits {
            connection: PathBuf::from(format!("/sys/fs/fuse/connections/{minor}")),
            bdi: PathBuf::from(format!("/sys/class/bdi/0:{minor}")),
        };
        if limits.connection.is_dir() {
            Some(limits)
        } else {
            tracing::warn!(
                "no {} for this mount; the kernel's FUSE limits cannot be reported",
                limits.connection.display()
            );
            None
        }
    }

    fn read(&self, dir: &Path, name: &str) -> Option<u64> {
        let path = dir.join(name);
        match std::fs::read_to_string(&path) {
            Ok(text) => match text.trim().parse() {
                Ok(value) => Some(value),
                Err(e) => {
                    tracing::warn!("{}: unreadable value {text:?}: {e}", path.display());
                    None
                }
            },
            Err(e) => {
                tracing::warn!("{}: {e}", path.display());
                None
            }
        }
    }

    fn log(&self) {
        tracing::info!(
            read_ahead_kb = self.read(&self.bdi, "read_ahead_kb"),
            max_background = self.read(&self.connection, "max_background"),
            congestion_threshold = self.read(&self.connection, "congestion_threshold"),
            "FUSE limits the kernel granted, from {} and {}",
            self.bdi.display(),
            self.connection.display()
        );
    }

    /// Requests the kernel has queued for the daemon at this moment.
    fn waiting(&self) -> Option<u64> {
        self.read(&self.connection, "waiting")
    }
}

/// The mount point as the mount table spells it: absolute, the parent resolved, the last component as given. Resolving the whole path would stat the mount point, which is a request through the mount.
fn spelled_by_kernel(mountpoint: &Path) -> PathBuf {
    let absolute = match std::path::absolute(mountpoint) {
        Ok(absolute) => absolute,
        Err(e) => {
            tracing::debug!("cannot make {} absolute: {e}", mountpoint.display());
            return mountpoint.to_path_buf();
        }
    };
    match (absolute.parent(), absolute.file_name()) {
        (Some(parent), Some(name)) => match parent.canonicalize() {
            Ok(parent) => parent.join(name),
            Err(e) => {
                tracing::debug!("cannot resolve {}: {e}", parent.display());
                absolute
            }
        },
        _ => absolute,
    }
}

/// The device minor of the newest mount at `target` in a `/proc/self/mountinfo` table, whose fields are `id parent major:minor root mountpoint …` with spaces and other special characters in paths written as octal escapes.
fn mount_minor(table: &str, target: &Path) -> Option<u32> {
    table.lines().rev().find_map(|line| {
        let mut fields = line.split(' ');
        let dev = fields.nth(2)?;
        let mountpoint = fields.nth(1)?;
        (Path::new(&unescape_mountinfo(mountpoint)) == target)
            .then(|| dev.split_once(':')?.1.parse().ok())
            .flatten()
    })
}

fn unescape_mountinfo(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            out.push(
                bytes[i + 1..i + 4]
                    .iter()
                    .fold(0u8, |acc, b| acc.wrapping_mul(8).wrapping_add(b - b'0')),
            );
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Clone, Debug)]
pub struct MountOptions {
    pub entry_ttl: Duration,
    pub attr_ttl: Duration,
    /// Let every local user through; they all act as the server user, so this hands them the export.
    pub allow_other: bool,
    /// Ask fusermount to clean up the mount point if this process dies; needs `allow_other`.
    pub auto_unmount: bool,
    /// Have the kernel enforce mode bits against the reported attributes before forwarding a request; the server checks only its own access, so a mount other users share needs this to enforce anything.
    pub default_permissions: bool,
}

/// A live mount. [`Mount::unmount`] is the orderly way down; dropping one unmounts too, blocking the dropping thread while it does, and is meant for panic paths.
pub struct Mount {
    session: Option<BackgroundSession>,
    invalidator: Option<Invalidator>,
    shared: Arc<Shared>,
    limits: Option<KernelLimits>,
}

impl Mount {
    /// Mount `client` at `mountpoint`. Must be called from within a multi-thread tokio runtime: the FUSE session thread hands every request to it, and unmounting waits for those requests to finish.
    pub async fn start(
        mut client: Client,
        mountpoint: &Path,
        options: MountOptions,
    ) -> anyhow::Result<Mount> {
        let events = client
            .take_events()
            .context("client events already taken")?;
        let state = client.state();
        let client = Arc::new(client);
        let (backend, shared) = Backend::new(
            client,
            options.entry_ttl,
            options.attr_ttl,
            tokio::runtime::Handle::current(),
        );
        let mut config = fuser::Config::default();
        config.mount_options = vec![
            MountOption::FSName("jackalopefs".into()),
            MountOption::Subtype("jackalopefs".into()),
        ];
        config.acl = if options.allow_other {
            SessionACL::All
        } else {
            SessionACL::Owner
        };
        if options.auto_unmount {
            config.mount_options.push(MountOption::AutoUnmount);
        }
        if options.default_permissions {
            config.mount_options.push(MountOption::DefaultPermissions);
        }
        let mountpoint = mountpoint.to_path_buf();
        let target = mountpoint.clone();
        let session = tokio::task::spawn_blocking(move || {
            fuser::Session::new(backend, &target, &config).and_then(|s| s.spawn())
        })
        .await
        .context("mount task")?
        .context("mounting")?;
        let invalidator = Invalidator::start(shared.clone(), events, state, session.notifier());
        let limits = KernelLimits::find(&mountpoint);
        if let Some(limits) = &limits {
            limits.log();
        }
        Ok(Mount {
            session: Some(session),
            invalidator: Some(invalidator),
            shared,
            limits,
        })
    }

    pub fn perf(&self) -> &Arc<Perf> {
        self.shared.client.perf()
    }

    /// Log the per-op tables for the window since the last report, the kernel's queue depth, and the connection's QUIC statistics.
    pub fn report(&self) {
        self.perf().report();
        if let Some(waiting) = self.limits.as_ref().and_then(KernelLimits::waiting) {
            tracing::info!(target: TRACE_TARGET, "perf kernel queue waiting={waiting}");
        }
        match self.shared.client.conn_stats() {
            Some((generation, stats)) => tracing::info!(
                target: TRACE_TARGET,
                "{}",
                line_quic(&format!("generation={generation}"), &stats)
            ),
            None => tracing::info!(target: TRACE_TARGET, "perf quic: not connected"),
        }
    }

    /// Unmount, stop invalidating, and close the connection. Every step is bounded.
    pub async fn unmount(mut self) -> anyhow::Result<()> {
        let outcome = match self.session.take() {
            Some(session) => {
                match tokio::task::spawn_blocking(move || session.umount_and_join())
                    .await
                    .context("unmount task")?
                {
                    // umount2 answers EINVAL when the target is no longer a mount point: someone detached it already (fusermount3 -uz), which is the end state wanted here. The unprivileged path gets the same leniency from fusermount.
                    Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                        tracing::info!("the mount point was already detached");
                        Ok(())
                    }
                    outcome => outcome.context("unmounting"),
                }
            }
            None => Ok(()),
        };
        if let Some(invalidator) = self.invalidator.take() {
            tokio::task::spawn_blocking(move || invalidator.stop())
                .await
                .context("invalidator shutdown")?;
        }
        // The session thread is joined, so no new kernel request can arrive; the sysfs entries left with the mount.
        self.limits = None;
        self.report();
        self.shared.client.shutdown().await;
        outcome
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            if let Err(e) = session.umount_and_join() {
                tracing::warn!("unmount on drop failed: {e}");
            }
        }
        // Once the mount is gone the notifier can no longer block, so joining its thread is safe here.
        self.invalidator.take();
        self.shared.client.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_table_is_matched_by_decoded_path_and_the_newest_entry_wins() {
        let table = "\
36 25 0:31 / /proc rw,nosuid - proc proc rw
622 31 0:141 / /mnt/my\\040share rw,nosuid,nodev shared:931 - fuse.jackalopefs jackalopefs rw
623 31 0:150 / /mnt/my\\040share rw,nosuid,nodev - fuse.jackalopefs jackalopefs rw
";
        assert_eq!(mount_minor(table, Path::new("/mnt/my share")), Some(150));
        assert_eq!(mount_minor(table, Path::new("/proc")), Some(31));
        assert_eq!(mount_minor(table, Path::new("/mnt/other")), None);
        assert_eq!(unescape_mountinfo("a\\011b\\134c\\12"), "a\tb\\c\\12");
    }
}
