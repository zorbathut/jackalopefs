//! The control socket: how `jackalopefs-ctl` reads a running process's counters and subscribes to its events and requests, without a restart. It is a Linux abstract Unix socket, `jackalopefs/{uid}/{side}-{pid}`, so there is no file to create, protect or clean up; only the process's own user (and root) may use it. It is served from a thread of its own, so it answers while the process's runtime is the thing that is stuck.

use crate::hub::Hub;
use jackalopefs_proto::control::{Ask, ControlReply, ControlRequest, Counters};
use jackalopefs_proto::{read_frame, write_frame, CONTROL_REVISION};
use std::io;
use std::os::linux::net::SocketAddrExt;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

/// What a process shows through its control socket.
pub trait Source: Send + Sync + 'static {
    /// `client` or `server`.
    fn side(&self) -> &'static str;
    /// The mount and its server, or the export and its address.
    fn describe(&self) -> String;
    /// The events, the per-operation totals and the requests in flight; [`Control`] fills in the rest.
    fn counters(&self) -> Counters;
    /// When the process started, for its uptime.
    fn started(&self) -> Instant;
    fn hub(&self) -> Arc<Hub>;
}

/// The socket's abstract name for process `pid` of user `uid`.
pub fn socket_name(uid: u32, side: &str, pid: u32) -> String {
    format!("jackalopefs/{uid}/{side}-{pid}")
}

/// Whether a peer running as `peer` may use the socket of a process running as `ours`: the same user, or root.
pub fn admits(peer: u32, ours: u32) -> bool {
    peer == ours || peer == 0
}

/// How long the socket waits after it fails to accept before it tries again.
const ACCEPT_RETRY: std::time::Duration = std::time::Duration::from_secs(1);

/// Serves the control socket until dropped.
pub struct Control {
    name: String,
    stop: Arc<Notify>,
}

impl Control {
    /// Serve `source` on this process's socket name.
    pub fn spawn(source: Arc<dyn Source>) -> io::Result<Control> {
        let name = socket_name(
            nix::unistd::getuid().as_raw(),
            source.side(),
            std::process::id(),
        );
        Control::spawn_named(source, name)
    }

    /// Serve `source` on the abstract socket `name`.
    pub fn spawn_named(source: Arc<dyn Source>, name: String) -> io::Result<Control> {
        let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
        let listener = std::os::unix::net::UnixListener::bind_addr(&address)?;
        listener.set_nonblocking(true)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let stop = Arc::new(Notify::new());
        // Not joined when stopped: an answer blocked on a lock the process holds wedged would hold up the process's shutdown too.
        std::thread::Builder::new()
            .name("jfs-control".into())
            .spawn({
                let stop = stop.clone();
                move || runtime.block_on(serve(listener, source, stop))
            })?;
        tracing::info!(
            "control socket @{name}: jackalopefs-ctl shows counters, events and requests live"
        );
        Ok(Control { name, stop })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        self.stop.notify_one();
    }
}

async fn serve(
    listener: std::os::unix::net::UnixListener,
    source: Arc<dyn Source>,
    stop: Arc<Notify>,
) {
    let listener = match UnixListener::from_std(listener) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::warn!("cannot serve the control socket: {e}");
            return;
        }
    };
    let ours = nix::unistd::getuid().as_raw();
    let mut failing = false;
    loop {
        let stream = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    failing = false;
                    stream
                }
                // An error that persists (out of descriptors) would fail again at once: wait before trying again, and say so once.
                Err(e) => {
                    if !failing {
                        tracing::warn!("control socket: cannot accept: {e}; trying again every second");
                        failing = true;
                    }
                    tokio::time::sleep(ACCEPT_RETRY).await;
                    continue;
                }
            },
            _ = stop.notified() => return,
        };
        match stream.peer_cred() {
            Ok(peer) if admits(peer.uid(), ours) => {
                tokio::spawn(answer(stream, source.clone()));
            }
            Ok(peer) => {
                tracing::warn!(uid = peer.uid(), "control socket: refusing another user");
            }
            Err(e) => tracing::warn!("control socket: cannot tell who connected: {e}"),
        }
    }
}

/// Answer one connection: counters as often as asked, or one subscription until the peer goes.
async fn answer(stream: UnixStream, source: Arc<dyn Source>) {
    let (mut rx, mut tx) = stream.into_split();
    loop {
        let request: ControlRequest = match read_frame(&mut rx).await {
            Ok(request) => request,
            Err(e) if e.is_eof() => return,
            Err(e) => {
                tracing::debug!("control socket: unreadable request: {e}");
                return;
            }
        };
        if request.revision != CONTROL_REVISION {
            let why = format!(
                "control protocol revision {:016x}; this process speaks {CONTROL_REVISION:016x}",
                request.revision
            );
            if let Err(e) = write_frame(&mut tx, &ControlReply::Refused(why)).await {
                tracing::debug!("control socket: cannot refuse: {e}");
            }
            return;
        }
        match request.ask {
            Ask::Counters => {
                let counters = Counters {
                    side: source.side().into(),
                    pid: std::process::id(),
                    describe: source.describe(),
                    uptime_ns: source.started().elapsed().as_nanos() as u64,
                    ..source.counters()
                };
                if let Err(e) = write_frame(&mut tx, &ControlReply::Counters(counters)).await {
                    tracing::debug!("control socket: cannot answer: {e}");
                    return;
                }
            }
            Ask::Subscribe(selection) => {
                let (_tap, mut records) = source.hub().subscribe(selection);
                let mut probe = [0u8; 1];
                loop {
                    tokio::select! {
                        record = records.recv() => {
                            let Some(record) = record else { return };
                            if let Err(e) = write_frame(&mut tx, &ControlReply::Record(record)).await {
                                tracing::debug!("control socket: subscriber gone: {e}");
                                return;
                            }
                        }
                        // A subscriber sends nothing more; a read that returns is the subscriber going, which ends the tap at once.
                        _ = rx.read(&mut probe) => return,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event;
    use crate::events::{Events, Kind};
    use crate::hub::IdsEvent;
    use jackalopefs_proto::control::{Happened, Names, Selection};
    use std::time::Duration;

    #[derive(Clone, Copy, Debug)]
    struct Only;

    impl Kind for Only {
        const ALL: &'static [Only] = &[Only];
        fn name(self) -> &'static str {
            "only"
        }
        fn index(self) -> usize {
            0
        }
    }

    struct Test {
        hub: Arc<Hub>,
        events: Arc<Events<Only>>,
    }

    impl Source for Test {
        fn side(&self) -> &'static str {
            "test"
        }
        fn describe(&self) -> String {
            "a test".into()
        }
        fn counters(&self) -> Counters {
            Counters {
                events: self
                    .events
                    .counts()
                    .into_iter()
                    .map(|(name, n)| (name.to_owned(), n))
                    .collect(),
                ..Counters::default()
            }
        }
        fn hub(&self) -> Arc<Hub> {
            self.hub.clone()
        }
        fn started(&self) -> Instant {
            Instant::now()
        }
    }

    fn serving(test: &str) -> (Arc<Test>, Control) {
        let hub = Arc::new(Hub::default());
        let source = Arc::new(Test {
            events: Events::new(&hub),
            hub,
        });
        let name = format!("jackalopefs-test/{}/{test}", std::process::id());
        let control = Control::spawn_named(source.clone(), name).unwrap();
        (source, control)
    }

    async fn connect(control: &Control) -> UnixStream {
        let address =
            std::os::unix::net::SocketAddr::from_abstract_name(control.name().as_bytes()).unwrap();
        let stream = std::os::unix::net::UnixStream::connect_addr(&address).unwrap();
        stream.set_nonblocking(true).unwrap();
        UnixStream::from_std(stream).unwrap()
    }

    async fn ask(stream: &mut UnixStream, request: ControlRequest) -> ControlReply {
        write_frame(stream, &request).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), read_frame(stream))
            .await
            .expect("no reply")
            .unwrap()
    }

    #[test]
    fn only_the_same_user_or_root_is_admitted() {
        assert!(admits(1000, 1000));
        assert!(admits(0, 1000));
        assert!(!admits(1001, 1000));
    }

    #[tokio::test]
    async fn counters_are_answered_as_often_as_asked() {
        let (source, control) = serving("counters");
        let mut stream = connect(&control).await;
        source.events.inc(Only);
        let counters = |reply| match reply {
            ControlReply::Counters(c) => c,
            other => panic!("{other:?}"),
        };
        let first = counters(
            ask(
                &mut stream,
                ControlRequest {
                    revision: CONTROL_REVISION,
                    ask: Ask::Counters,
                },
            )
            .await,
        );
        assert_eq!(first.side, "test");
        assert_eq!(first.pid, std::process::id());
        assert_eq!(first.events, vec![("only".to_owned(), 1)]);
        source.events.inc(Only);
        let second = counters(
            ask(
                &mut stream,
                ControlRequest {
                    revision: CONTROL_REVISION,
                    ask: Ask::Counters,
                },
            )
            .await,
        );
        assert_eq!(second.events, vec![("only".to_owned(), 2)]);
    }

    #[tokio::test]
    async fn another_revision_is_refused() {
        let (_source, control) = serving("revision");
        let mut stream = connect(&control).await;
        let reply = ask(
            &mut stream,
            ControlRequest {
                revision: CONTROL_REVISION ^ 1,
                ask: Ask::Counters,
            },
        )
        .await;
        assert!(matches!(reply, ControlReply::Refused(_)), "{reply:?}");
    }

    #[tokio::test]
    async fn a_subscriber_gets_events_and_its_tap_goes_with_it() {
        let (source, control) = serving("subscribe");
        let mut stream = connect(&control).await;
        write_frame(
            &mut stream,
            &ControlRequest {
                revision: CONTROL_REVISION,
                ask: Ask::Subscribe(Selection {
                    events: Names::Some(vec!["only".into()]),
                    ..Selection::default()
                }),
            },
        )
        .await
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !source.events.traced(Only) {
            assert!(Instant::now() < deadline, "the subscription did not arrive");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        event!(target: "jackalopefs_perf_test::event", source.events, Only, IdsEvent::default(), "what happened".to_string());
        let reply: ControlReply =
            tokio::time::timeout(Duration::from_secs(5), read_frame(&mut stream))
                .await
                .expect("no record")
                .unwrap();
        match reply {
            ControlReply::Record(record) => assert!(
                matches!(&record.what, Happened::Event { detail, .. } if detail == "what happened"),
                "{record:?}"
            ),
            other => panic!("{other:?}"),
        }
        drop(stream);
        while source.events.traced(Only) {
            assert!(Instant::now() < deadline, "the tap outlived its subscriber");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
