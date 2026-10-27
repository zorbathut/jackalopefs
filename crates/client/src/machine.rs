//! The client's half of the session protocol as steps that neither wait nor do IO: what a connection carries ([`AttachedState`]), a call's sends, give-up and resend ([`CallState`]), and what the end of an open or a release leaves owed. The async code around them (`Caller::attempt`, the connection manager) does the IO and the waiting, and asks these what to do and when; the model-based test takes the same steps without it.
//!
//! These steps are modelled in `spec/session.qnt`; a change to them updates the model, or its commit says why not (`spec/README.md`, "Keeping it in sync").

use crate::client::Error;
use crate::handles::HandleTable;
use jackalopefs_proto::Response;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::watch;

/// A connection's part in the protocol: its generation, its changes given up on that the server has not yet said what became of, and whether the connection manager has handed it to calls (published it). Made at the handshake, before the reopens, which count their give-ups on it.
#[derive(Debug)]
pub struct AttachedState {
    /// Increments with every successful connection; callers that lost a reply wait for a strictly newer generation before retrying.
    pub generation: u64,
    /// Changes on this connection that a call gave up on, and the server has not yet said what became of; a change is sent only once there are none.
    pub cancels: watch::Sender<usize>,
    published: AtomicBool,
}

impl AttachedState {
    pub fn new(generation: u64) -> AttachedState {
        AttachedState {
            generation,
            cancels: watch::Sender::new(0),
            published: AtomicBool::new(false),
        }
    }

    /// The connection manager hands the connection to calls: its reopens are done.
    pub fn publish(&self) {
        self.published.store(true, Ordering::Release);
    }

    pub fn published(&self) -> bool {
        self.published.load(Ordering::Acquire)
    }
}

/// A change on a connection that the call gave up on and the server has not yet said what became of, counted on the connection's [`AttachedState::cancels`] until dropped.
pub(crate) struct CancelPending(watch::Sender<usize>);

impl CancelPending {
    pub(crate) fn count(cancels: &watch::Sender<usize>) -> CancelPending {
        cancels.send_modify(|n| *n += 1);
        CancelPending(cancels.clone())
    }
}

impl Drop for CancelPending {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n -= 1);
    }
}

/// How a call ended, as the model has it: a reply, an errno, given up on (`Error::Interrupted`, `Error::Timeout`), or failed with its reply lost (`Error::Disconnected`). Both of the last are "unknown" to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndCall {
    Replied,
    Errno,
    GaveUp,
    Failed,
}

/// Where a call stands: waiting to be sent; in flight on the connection of a generation, from when its exchange begins (waiting for a stream, being written, waiting for its answer); or ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StatusCall {
    Waiting,
    InFlight { generation: u64 },
    Ended(EndCall),
}

/// Whether a waiting call may be sent on a connection: not on this one, once the connection's pending cancels are answered, or now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sendable {
    No,
    AfterCancels,
    Now,
}

/// How an exchange failed with its connection: before its frame was surely carried whole (never seen by the server, so sent again untouched), or after, its reply lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LossExchange {
    NotSent,
    Lost,
}

/// One call, from its start to its end, through its attempts: owned by the call's own task, so it takes no lock.
#[derive(Debug)]
pub(crate) struct CallState {
    /// The request takes part in the session's ordering ([`jackalopefs_proto::Request::changes`]).
    changes: bool,
    /// A reply lost with its connection may be asked for once more (`retry_safe`).
    resendable: bool,
    lost_once: bool,
    /// The generation the call waits for at least: it takes no connection older than this.
    min_generation: u64,
    /// The attempts sent.
    attempt: u32,
    status: StatusCall,
}

impl CallState {
    pub(crate) fn new(changes: bool, resendable: bool) -> CallState {
        CallState {
            changes,
            resendable,
            lost_once: false,
            min_generation: 0,
            attempt: 0,
            status: StatusCall::Waiting,
        }
    }

    /// Whether the waiting call may take `attached`: it is published, and of at least the generation the call waits for.
    pub(crate) fn takes(&self, attached: &AttachedState) -> bool {
        self.status == StatusCall::Waiting
            && attached.published()
            && attached.generation >= self.min_generation
    }

    /// Whether the call may be sent on `attached` now, `pending` being the connection's count of pending cancels as just read: a change waits for every change the connection gave up on to be answered, so none of those can land after it.
    pub(crate) fn sendable(&self, attached: &AttachedState, pending: usize) -> Sendable {
        if !self.takes(attached) {
            Sendable::No
        } else if self.changes && pending != 0 {
            Sendable::AfterCancels
        } else {
            Sendable::Now
        }
    }

    /// The call's request goes out on the connection of `generation`.
    pub(crate) fn sent(&mut self, generation: u64) {
        debug_assert_eq!(self.status, StatusCall::Waiting);
        self.attempt += 1;
        self.status = StatusCall::InFlight { generation };
    }

    /// The answer came: a reply, or an errno.
    pub(crate) fn answered(&mut self, errno: bool) {
        self.status = StatusCall::Ended(if errno {
            EndCall::Errno
        } else {
            EndCall::Replied
        });
    }

    /// The exchange failed with its connection. A frame not surely carried whole goes again on a newer connection; a reply lost goes again once more if that is safe, and otherwise the call fails with [`Error::Disconnected`].
    pub(crate) fn lost(&mut self, loss: LossExchange) -> Result<(), Error> {
        let StatusCall::InFlight { generation } = self.status else {
            unreachable!(
                "only a call in flight loses its exchange: {:?}",
                self.status
            )
        };
        match loss {
            LossExchange::NotSent => {}
            LossExchange::Lost if self.resendable && !self.lost_once => self.lost_once = true,
            LossExchange::Lost => {
                self.status = StatusCall::Ended(EndCall::Failed);
                return Err(Error::Disconnected);
            }
        }
        self.min_generation = generation + 1;
        self.status = StatusCall::Waiting;
        Ok(())
    }

    /// The call stops waiting (the kernel interrupted it, or its deadline passed), its request `written` whole or not, and returns at once. Whether the server must be told and its answer counted on the connection's pending cancels: for a change written whole while in flight.
    pub(crate) fn gave_up(&mut self, written: bool) -> bool {
        let counted = counts_give_up(
            matches!(self.status, StatusCall::InFlight { .. }),
            written,
            self.changes,
        );
        self.status = StatusCall::Ended(EndCall::GaveUp);
        counted
    }

    /// The call fails in a way the protocol has no part in (a protocol error, a stale handle, an owner with no counterpart).
    pub(crate) fn failed(&mut self) {
        self.status = StatusCall::Ended(EndCall::Failed);
    }

    #[cfg(test)]
    pub(crate) fn status(&self) -> StatusCall {
        self.status
    }

    #[cfg(test)]
    pub(crate) fn attempt(&self) -> u32 {
        self.attempt
    }

    #[cfg(test)]
    pub(crate) fn min_generation(&self) -> u64 {
        self.min_generation
    }

    #[cfg(test)]
    pub(crate) fn lost_once(&self) -> bool {
        self.lost_once
    }
}

/// Whether a request given up on is counted on its connection's pending cancels, the server told and its answer waited for: a change in flight whose request was written whole. One given up on before that reached the server with nothing the server could run, and anything else is not ordered.
pub(crate) fn counts_give_up(in_flight: bool, written: bool, changes: bool) -> bool {
    in_flight && written && changes
}

/// What the end of an open leaves: the handle kept; the release of its id owed, since the outcome leaves doubt about whether the server opened something; or nothing, the server having refused the open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SettleOpen {
    Keep,
    Owe,
    Nothing,
}

/// What an open's `result` leaves.
pub(crate) fn open_settled(result: &Result<Response, Error>) -> SettleOpen {
    match result {
        Ok(Response::Opened { .. }) => SettleOpen::Keep,
        Ok(_)
        | Err(Error::Timeout | Error::Interrupted | Error::Disconnected | Error::Protocol(_)) => {
            SettleOpen::Owe
        }
        Err(_) => SettleOpen::Nothing,
    }
}

/// Whether a release that ended with `result` is owed: it found no connection, or timed out. Without it the server would hold the descriptor for as long as the session lives.
pub(crate) fn release_owed(result: &Result<Response, Error>) -> bool {
    matches!(result, Err(Error::Timeout | Error::Disconnected))
}

/// The kernel releases `fh`: forget it, so a reconnect never reopens it, and say whether to tell the server; not for a dead handle, whose release whatever killed it owed.
pub(crate) fn release_begins(handles: &HandleTable, fh: u64) -> bool {
    !handles.remove(fh).is_some_and(|rec| rec.is_dead())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn published(generation: u64) -> AttachedState {
        let attached = AttachedState::new(generation);
        attached.publish();
        attached
    }

    #[test]
    fn a_call_takes_only_a_published_connection_of_the_generation_it_waits_for() {
        let mut call = CallState::new(false, true);
        let first = AttachedState::new(1);
        assert_eq!(call.sendable(&first, 0), Sendable::No, "not published");
        first.publish();
        assert_eq!(call.sendable(&first, 0), Sendable::Now);
        call.sent(1);
        assert!(call.lost(LossExchange::NotSent).is_ok());
        assert_eq!(call.status(), StatusCall::Waiting);
        assert_eq!(
            call.sendable(&first, 0),
            Sendable::No,
            "the connection that failed it"
        );
        assert_eq!(call.sendable(&published(2), 0), Sendable::Now);
        assert_eq!(
            (call.attempt(), call.min_generation(), call.lost_once()),
            (1, 2, false)
        );
    }

    #[test]
    fn only_a_change_waits_for_the_pending_cancels() {
        let attached = published(1);
        assert_eq!(
            CallState::new(true, true).sendable(&attached, 1),
            Sendable::AfterCancels
        );
        assert_eq!(
            CallState::new(true, true).sendable(&attached, 0),
            Sendable::Now
        );
        assert_eq!(
            CallState::new(false, true).sendable(&attached, 1),
            Sendable::Now
        );
    }

    #[test]
    fn a_lost_reply_is_asked_for_once_more_when_that_is_safe() {
        let mut call = CallState::new(true, true);
        call.sent(1);
        assert!(call.lost(LossExchange::Lost).is_ok());
        assert_eq!(
            (call.status(), call.min_generation(), call.lost_once()),
            (StatusCall::Waiting, 2, true)
        );
        call.sent(2);
        assert!(matches!(
            call.lost(LossExchange::Lost),
            Err(Error::Disconnected)
        ));
        assert_eq!(call.status(), StatusCall::Ended(EndCall::Failed));
        let mut unsafe_to_resend = CallState::new(true, false);
        unsafe_to_resend.sent(1);
        assert!(matches!(
            unsafe_to_resend.lost(LossExchange::Lost),
            Err(Error::Disconnected)
        ));
    }

    #[test]
    fn a_give_up_is_counted_for_a_change_written_whole() {
        let gave_up = |changes: bool, sent: bool, written: bool| {
            let mut call = CallState::new(changes, true);
            if sent {
                call.sent(1);
            }
            let counted = call.gave_up(written);
            assert_eq!(call.status(), StatusCall::Ended(EndCall::GaveUp));
            counted
        };
        assert!(gave_up(true, true, true));
        assert!(!gave_up(true, true, false), "not written whole");
        assert!(!gave_up(true, false, false), "never sent");
        assert!(!gave_up(false, true, true), "not a change");
    }

    #[test]
    fn the_kernels_release_of_a_dead_handle_sends_nothing() {
        use crate::handles::tests::attr;
        use crate::handles::HandleKind;
        use crate::inodes::KeyNode;
        let handles = HandleTable::default();
        let path = jackalopefs_proto::Path::root();
        handles.insert(
            1,
            2,
            KeyNode::of(&attr(2)),
            path.clone(),
            libc::O_RDONLY,
            HandleKind::File,
            None,
        );
        handles.insert(
            2,
            3,
            KeyNode::of(&attr(3)),
            path,
            libc::O_RDONLY,
            HandleKind::File,
            None,
        );
        handles.kill_all();
        assert!(!release_begins(&handles, 1), "its release is owed already");
        assert!(handles.get(1).is_none(), "forgotten all the same");
        assert!(
            release_begins(&handles, 7),
            "a handle the client has no record of is released"
        );
    }

    #[test]
    fn what_an_open_and_a_release_leave_owed() {
        let attr = crate::handles::tests::attr(2);
        assert_eq!(
            open_settled(&Ok(Response::Opened { attr })),
            SettleOpen::Keep
        );
        assert_eq!(open_settled(&Ok(Response::Ok)), SettleOpen::Owe);
        for doubt in [
            Error::Timeout,
            Error::Interrupted,
            Error::Disconnected,
            Error::Protocol(String::new()),
        ] {
            assert_eq!(open_settled(&Err(doubt)), SettleOpen::Owe);
        }
        assert_eq!(
            open_settled(&Err(Error::Remote(libc::ENOENT))),
            SettleOpen::Nothing
        );
        assert!(release_owed(&Err(Error::Timeout)));
        assert!(release_owed(&Err(Error::Disconnected)));
        assert!(!release_owed(&Ok(Response::Ok)));
        assert!(!release_owed(&Err(Error::Interrupted)));
    }
}
