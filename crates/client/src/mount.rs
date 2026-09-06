//! Mount lifecycle: FUSE session, invalidator, and client, started and torn down together.

use crate::client::Client;
use crate::fuse::{Backend, Shared};
use crate::invalidate::Invalidator;
use anyhow::Context;
use fuser::{BackgroundSession, MountOption, SessionACL};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

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
        let session = tokio::task::spawn_blocking(move || {
            fuser::Session::new(backend, &mountpoint, &config).and_then(|s| s.spawn())
        })
        .await
        .context("mount task")?
        .context("mounting")?;
        let invalidator = Invalidator::start(shared.clone(), events, state, session.notifier());
        Ok(Mount {
            session: Some(session),
            invalidator: Some(invalidator),
            shared,
        })
    }

    /// Unmount, stop invalidating, and close the connection. Every step is bounded.
    pub async fn unmount(mut self) -> anyhow::Result<()> {
        let outcome = match self.session.take() {
            Some(session) => tokio::task::spawn_blocking(move || session.umount_and_join())
                .await
                .context("unmount task")?
                .context("unmounting"),
            None => Ok(()),
        };
        if let Some(invalidator) = self.invalidator.take() {
            tokio::task::spawn_blocking(move || invalidator.stop())
                .await
                .context("invalidator shutdown")?;
        }
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
