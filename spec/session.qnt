// One jackalopefs session, as `docs/design.md`'s "Failure model" describes it: the client's calls, connections and handles, the server's requests with their phases, and the mechanisms M1 to M4, checked against the invariants S1 to S3 for small bounds. Each action names the code it stands for, by file and function; line numbers are as of the commit that last touched this file. `spec/README.md` says how to run the checks and what each must show.
module session {
  /// The call pool. A call is a user's request or an orphan release; a slot is used once. An open's handle id is its call id, so ids are never reused.
  const N: int
  /// The request pool. A slot is used once (a frame the server never saw whole excepted), so this bounds how many requests a trace sends.
  const R: int
  /// The most connections the client makes, and so the most sessions it can be given.
  const MAX_GEN: int
  /// How many released ids a session remembers (`handles.rs` `RELEASED_KEPT`).
  const RELEASED_KEPT: int

  pure val CALLS = 1.to(N)
  pure val REQS = 1.to(R)
  pure val GENS = 1.to(MAX_GEN)
  pure val SIDS = 1.to(MAX_GEN)
  pure val BOOLS = Set(true, false)

  // ---- Types ----

  /// What a call asks for. `Change` stands for every ordered request that keeps no handle (mkdir, write, ...); an `Open` keeps one under the call's own id; a `Release` lets one go, the user's or an orphan's. Reads are left out: no invariant in scope mentions them.
  type Kind = Change | Open | Release(int)
  type StatusCall = Idle | Waiting | InFlight | Ended
  /// How a call ended. `GaveUp` is EINTR or ETIMEDOUT; `Failed` is the EIO after a reply lost with its connection that may not be sent again. Both are "unknown" to the caller.
  type Outcome = NoOutcome | Replied | Errno | GaveUp | Failed
  type Call = {
    kind: Kind,
    status: StatusCall,
    // `retry_safe`: a reply lost with its connection may be asked for once more.
    resendable: bool,
    // A kernel request's call, which a signal ends; a release's is not (the kernel never interrupts FUSE_RELEASE), nor an orphan's.
    interruptible: bool,
    attempt: int,
    // `Caller::attempt`'s `min_generation`: the call takes no connection older than this.
    minGen: int,
    lostOnce: bool,
    // The request of the attempt in flight, 0 when none is.
    req: int,
    outcome: Outcome,
    // The calls that had ended when this one started: design.md's "b after a".
    endedBefore: Set[int]
  }

  /// Where a request came from: a call's attempt, or the connection manager's own traffic: a reopen of a held handle after a new session, or a release owed from before (a handle a reopen killed included).
  type Origin = NoOrigin | OfCall(int) | Reopen(int) | OwedRelease(int)
  /// A request as the server has it. `Transit`: written by the client, not decoded. `Held`: decoded with a fence above zero, waiting in `drain`. `Ready`: decoded with a fence of zero, or drained, waiting for a blocking thread; the fence is not read again from here. `Cancelled`: dropped unrun on the client's cancel. `Superseded`: refused by the epoch check in `drain` or `begin`. `Dropped`: gone with the connection on the server's side, or reset before it was read whole. `Abandoned`: running, and given up on.
  type Phase = Absent | Transit | Held | Ready | Cancelled | Superseded | Dropped | Running | Abandoned | Finished
  /// What the server has sent back on the stream and the client has not yet read.
  type Answer = NoAnswer | Reply | ErrnoReply | Unrun | Fenced
  /// What `Handles::reserve` gave an open: nothing yet; a refusal, the id having been released; a slot of the pool; or the slot of the entry already under the id, a retried open's.
  type Slot = NoSlot | Refused | Taken | Kept
  type Req = {
    origin: Origin,
    attempt: int,
    phase: Phase,
    conn: int,
    epoch: int,
    session: int,
    // The client reset its side of the stream.
    cancelSent: bool,
    // The client counted the cancel on its connection's `cancels`.
    counted: bool,
    // The server has acted on the reset.
    cancelSeen: bool,
    answer: Answer,
    slot: Slot
  }

  /// One connection, by the client's generation. `clientAlive` and `serverAlive` are each end's view; `published` is the connection manager's: the reopens are done and calls may use it. `cancels` is `Attached::cancels`; `owedToSend` is what `take_owed` handed `send_releases`, not yet sent.
  type Conn = { session: int, epoch: int, clientAlive: bool, serverAlive: bool, published: bool, cancels: int, owedToSend: Set[int] }

  /// A handle the server holds: the request that inserted it (0 for none), and whether a release of the id had run already when it was inserted, which only the window's eviction lets happen.
  type Entry = { by: int, releasedBefore: bool }
  /// `SessionState`: the attachment's epoch and counts, whether the session is in the server's table (`live`) and whether its grace period is running (`detached`); its `Handles`, with the released ids it remembers (`released`, the window) and every id ever released (a ghost). `handshakeLost` bounds that action to once between connections.
  type Session = { epoch: int, running: int, abandoned: int, runningOlder: int, live: bool, detached: bool, handshakeLost: bool, handles: int -> Entry, released: List[int], releasedEver: Set[int] }

  /// The client's handle table: for each id, the request whose reply it accepted, or the reopen it expects (0 for none held); the handles a reopen killed (`HandleRec::dead`); the releases owed; the opens of unknown outcome whose orphan release has not started; the handles reopened on the current session.
  type Client = { held: int -> int, dead: Set[int], owed: Set[int], orphansDue: Set[int], reopened: Set[int] }

  // ---- State ----

  var calls: int -> Call
  var reqs: int -> Req
  var conns: int -> Conn
  /// The newest generation; its connection is the one calls use.
  var gen: int
  var sessions: int -> Session
  /// The session the client's newest connection attached.
  var sid: int
  var client: Client
  /// `HandlePool::used`, shared by every session.
  var pool: int
  /// Ghosts, each set by `begin` when a request begins out of order and never cleared: S1 broken within one session, S1 broken across the client's sessions, a resend begun before its original finished.
  var overtook: bool
  var overtookAcross: bool
  var resendOvertook: bool

  // ---- Helpers ----

  /// `Request::changes`: the requests that take part in the session's ordering.
  pure def ordered(kind: Kind): bool = match kind { Release(_) => false | _ => true }
  pure def isRelease(kind: Kind): bool = match kind { Release(_) => true | _ => false }
  pure def isOpen(kind: Kind): bool = match kind { Open => true | _ => false }
  pure def begun(p: Phase): bool = p == Running or p == Abandoned or p == Finished
  pure def terminal(p: Phase): bool = p == Absent or p == Cancelled or p == Superseded or p == Dropped or p == Finished

  pure val idleCall: Call = { kind: Change, status: Idle, resendable: false, interruptible: false, attempt: 0, minGen: 1, lostOnce: false, req: 0, outcome: NoOutcome, endedBefore: Set() }
  pure val absentReq: Req = { origin: NoOrigin, attempt: 0, phase: Absent, conn: 0, epoch: 0, session: 0, cancelSent: false, counted: false, cancelSeen: false, answer: NoAnswer, slot: NoSlot }
  pure def newReq(origin: Origin, attempt: int, g: int, k: Conn): Req = { origin: origin, attempt: attempt, phase: Transit, conn: g, epoch: k.epoch, session: k.session, cancelSent: false, counted: false, cancelSeen: false, answer: NoAnswer, slot: NoSlot }
  pure val noConn: Conn = { session: 0, epoch: 0, clientAlive: false, serverAlive: false, published: false, cancels: 0, owedToSend: Set() }
  pure def liveConn(s: int, epoch: int, published: bool, owedToSend: Set[int]): Conn = { session: s, epoch: epoch, clientAlive: true, serverAlive: true, published: published, cancels: 0, owedToSend: owedToSend }
  pure val noEntry: Entry = { by: 0, releasedBefore: false }
  pure val noSession: Session = { epoch: 0, running: 0, abandoned: 0, runningOlder: 0, live: false, detached: false, handshakeLost: false, handles: CALLS.mapBy(fh => noEntry), released: [], releasedEver: Set() }
  pure val freshSession: Session = noSession.with("epoch", 1).with("live", true)
  pure val emptyClient: Client = { held: CALLS.mapBy(fh => 0), dead: Set(), owed: Set(), orphansDue: Set(), reopened: Set() }

  pure def listHas(l: List[int], x: int): bool = l.indices().exists(i => l[i] == x)

  /// `Released::record`: the id joins the window, the oldest leaving if it is full.
  pure def remember(released: List[int], fh: int): List[int] =
    if (listHas(released, fh)) released
    else if (released.length() >= RELEASED_KEPT) released.slice(1, released.length()).append(fh)
    else released.append(fh)

  def kindOf(c: int): Kind = calls.get(c).kind
  def orderedReq(q: Req): bool = match q.origin { OfCall(c) => ordered(kindOf(c)) | Reopen(_) => true | _ => false }
  def opensReq(q: Req): bool = match q.origin { OfCall(c) => isOpen(kindOf(c)) | Reopen(_) => true | _ => false }
  def releasesReq(q: Req): bool = match q.origin { OfCall(c) => isRelease(kindOf(c)) | OwedRelease(_) => true | _ => false }
  /// The handle an open keeps or a release lets go, 0 for a change.
  def fhOf(q: Req): int = match q.origin {
    OfCall(c) => match kindOf(c) { Open => c | Release(fh) => fh | Change => 0 }
    | Reopen(fh) => fh
    | OwedRelease(fh) => fh
    | NoOrigin => 0
  }

  val endedNow = CALLS.filter(c => calls.get(c).status == Ended)
  /// The request slot the next send takes: the lowest free one, or `R + 1` when none is.
  val lowestFree = REQS.filter(r => reqs.get(r).phase == Absent).fold(R + 1, (low, r) => if (r < low) r else low)
  val heldNow = CALLS.filter(fh => client.held.get(fh) != 0)

  /// `SessionState::fencing`: what a change from the connection attached at `epoch` waits for; nothing for a connection no longer current, whose changes will not run.
  def fencing(s: int, epoch: int): int = {
    val ses = sessions.get(s)
    if (ses.epoch == epoch) ses.runningOlder + ses.abandoned else 0
  }

  action keepCalls = calls' = calls
  action keepReqs = reqs' = reqs
  action keepConns = all { conns' = conns, gen' = gen, sid' = sid }
  action keepSessions = all { sessions' = sessions, pool' = pool }
  action keepClient = client' = client
  action keepGhosts = all { overtook' = overtook, overtookAcross' = overtookAcross, resendOvertook' = resendOvertook }

  // ---- The client's calls (`crates/client/src/client.rs`) ----

  /// `Client::call` starts a call; `retry_safe` fixes what a lost reply does to it (a release is always resent, an open not if it truncates). A release is the kernel's, of a handle the client holds, which it forgets at once; or an orphan's, for an open of unknown outcome (`release_orphan`, spawned with no kernel request to interrupt it).
  action start(c: int, kind: Kind, resendable: bool): bool = all {
    calls.get(c).status == Idle,
    match kind { Release(fh) => client.held.get(fh) != 0 or client.orphansDue.contains(fh) | _ => true },
    calls' = calls.set(c, { kind: kind, status: Waiting, resendable: resendable or isRelease(kind), interruptible: not(isRelease(kind)), attempt: 0, minGen: 1, lostOnce: false, req: 0, outcome: NoOutcome, endedBefore: endedNow }),
    client' = match kind {
      Release(fh) => client.with("held", client.held.set(fh, 0)).with("orphansDue", client.orphansDue.exclude(Set(fh)))
      | _ => client
    },
    keepReqs,
    keepConns,
    keepSessions,
    keepGhosts,
  }

  /// `Caller::attempt` 798-847: the call takes the current connection once it is published and at least `min_generation`; a change waits first for the connection's pending cancels to be answered (811-827); `exchange` writes the request.
  def canSend(c: int): bool = {
    val call = calls.get(c)
    val conn = conns.get(gen)
    call.status == Waiting and conn.clientAlive and conn.published and gen >= call.minGen and (not(ordered(call.kind)) or conn.cancels == 0) and lowestFree <= R
  }
  action send(c: int): bool = {
    val call = calls.get(c)
    val r = lowestFree
    all {
      canSend(c),
      calls' = calls.set(c, call.with("status", InFlight).with("attempt", call.attempt + 1).with("req", r)),
      reqs' = reqs.set(r, newReq(OfCall(c), call.attempt + 1, gen, conns.get(gen))),
      keepConns,
      keepSessions,
      keepClient,
      keepGhosts,
    }
  }

  /// The kernel interrupts the request, or `op_timeout` passes (`give_up`): the call returns at once (L1). `exchange` 538-562: a change already written has its send side reset and is counted on `Attached::cancels` in the same step as the return (M2's client half); a release's streams are dropped unanswered, and its frame, if not yet read whole, is gone with the reset (`dropped`). An open of unknown outcome gets an orphan release (the open path, 1063-1076); a release that timed out is owed (`release` 917).
  action giveUp(c: int, dropped: bool): bool = {
    val call = calls.get(c)
    val q = reqs.get(call.req)
    val cancels = call.status == InFlight and ordered(call.kind)
    all {
      call.status == Waiting or call.status == InFlight,
      calls' = calls.set(c, call.with("status", Ended).with("outcome", GaveUp).with("req", 0)),
      reqs' = if (cancels) reqs.set(call.req, q.with("cancelSent", true).with("counted", true))
        else if (call.status == InFlight and dropped and q.phase == Transit) reqs.set(call.req, q.with("phase", Dropped))
        else reqs,
      conns' = if (cancels) conns.setBy(q.conn, k => k.with("cancels", k.cancels + 1)) else conns,
      client' = match call.kind {
        Open => client.with("orphansDue", client.orphansDue.union(Set(c)))
        | Release(fh) => client.with("owed", client.owed.union(Set(fh)))
        | Change => client
      },
      gen' = gen,
      sid' = sid,
      keepSessions,
      keepGhosts,
    }
  }

  /// `attempt` 871-890: a reply lost with its connection is asked for once more on a newer connection if `retry_safe` and not already resent (M3); otherwise the call fails with EIO.
  pure def lostCall(call: Call, g: int): Call =
    if (call.resendable and not(call.lostOnce)) call.with("status", Waiting).with("minGen", g + 1).with("lostOnce", true).with("req", 0)
    else call.with("status", Ended).with("outcome", Failed).with("req", 0)

  /// `ConnManager` sees the connection end (`conn.rs` 353): every exchange on it fails. The calls in `notSent`, whose frames the stream may not have carried whole, go to the next connection untouched (`attempt` 856-870, `NotSent`); the rest lost their reply, `lostCall`, an open that fails getting an orphan release and a release being owed. The readers of the pending cancels fail too, so their count goes with the connection. Reopens not yet accepted fail with it (`apply_reopen` on `Err`): their handles are dead and their releases owed.
  action loseClient(g: int, notSent: Set[int]): bool = {
    val inflight = CALLS.filter(c => calls.get(c).status == InFlight and reqs.get(calls.get(c).req).conn == g)
    val failing = inflight.exclude(notSent).filter(c => not(calls.get(c).resendable and not(calls.get(c).lostOnce)))
    val unreopened = if (conns.get(g).published) Set() else heldNow.exclude(client.reopened)
    all {
      conns.get(g).clientAlive,
      notSent.subseteq(inflight.filter(c => reqs.get(calls.get(c).req).phase == Transit)),
      conns' = conns.setBy(g, k => k.with("clientAlive", false).with("cancels", 0)),
      calls' = CALLS.mapBy(c => {
        val call = calls.get(c)
        if (notSent.contains(c)) call.with("status", Waiting).with("minGen", g + 1).with("req", 0)
        else if (inflight.contains(c)) lostCall(call, g)
        else call
      }),
      reqs' = REQS.mapBy(r => if (notSent.exists(c => calls.get(c).req == r)) absentReq else reqs.get(r)),
      client' = {
        held: CALLS.mapBy(fh => if (unreopened.contains(fh)) 0 else client.held.get(fh)),
        dead: client.dead.union(unreopened),
        owed: client.owed.union(unreopened).union(failing.filter(c => isRelease(kindOf(c))).map(c => match kindOf(c) { Release(fh) => fh | _ => 0 })),
        orphansDue: client.orphansDue.union(failing.filter(c => isOpen(kindOf(c)))),
        reopened: client.reopened
      },
      gen' = gen,
      sid' = sid,
      keepSessions,
      keepGhosts,
    }
  }

  /// The answer reaches the client (`exchange` 538-600; for a change given up on, its background reader 548-560): a reply ends the call still waiting for it, an open's keeping the handle; an answer to a cancel, whatever it says, uncounts the change on `cancels`. A reopen's reply keeps the handle alive, an errno kills it (`apply_reopen`) and its release is owed (`reopen_handles` 627-634); an owed release's reply settles it (`send_releases` 677-684).
  action receive(r: int): bool = {
    val q = reqs.get(r)
    all {
      q.answer != NoAnswer,
      conns.get(q.conn).clientAlive,
      reqs' = reqs.set(r, q.with("answer", NoAnswer).with("counted", false)),
      match q.origin {
        OfCall(c) => {
          val call = calls.get(c)
          if (call.status == InFlight and call.req == r) all {
            calls' = calls.set(c, call.with("status", Ended).with("outcome", if (q.answer == Reply) Replied else Errno).with("req", 0)),
            conns' = conns,
            client' = if (q.answer == Reply and isOpen(call.kind)) client.with("held", client.held.set(c, r)) else client,
          } else all {
            keepCalls,
            conns' = if (q.counted) conns.setBy(q.conn, k => k.with("cancels", k.cancels - 1)) else conns,
            keepClient,
          }
        }
        | Reopen(fh) => all {
          keepCalls,
          conns' = conns,
          client' = if (client.held.get(fh) != r) client
            else if (q.answer == Reply) client.with("reopened", client.reopened.union(Set(fh)))
            else if (q.answer == ErrnoReply) client.with("held", client.held.set(fh, 0)).with("dead", client.dead.union(Set(fh))).with("owed", client.owed.union(Set(fh)))
            else client,
        }
        | OwedRelease(fh) => all {
          keepCalls,
          conns' = conns,
          client' = if (q.answer == Reply) client.with("owed", client.owed.exclude(Set(fh))) else client,
        }
        | NoOrigin => all { keepCalls, conns' = conns, keepClient }
      },
      gen' = gen,
      sid' = sid,
      keepSessions,
      keepGhosts,
    }
  }

  // ---- The connection manager's own traffic after a new session (`crates/client/src/conn.rs`) ----

  /// `reopen_handles` 578-640: each held handle is opened again under its id, before the connection is published; the client expects the server's entry from this request.
  action sendReopen(fh: int): bool = {
    val conn = conns.get(gen)
    val r = lowestFree
    all {
      conn.clientAlive,
      not(conn.published),
      client.held.get(fh) != 0,
      not(client.reopened.contains(fh)),
      reqs.get(client.held.get(fh)).conn != gen,
      r <= R,
      reqs' = reqs.set(r, newReq(Reopen(fh), 1, gen, conn)),
      client' = client.with("held", client.held.set(fh, r)),
      keepCalls,
      keepConns,
      keepSessions,
      keepGhosts,
    }
  }

  /// A reopen's `timeout` passes (`reopen_handles` 599-612): the exchange is dropped, both sides of its stream reset, nothing counted on `cancels`; the handle is dead and its release owed.
  action giveUpReopen(r: int): bool = {
    val q = reqs.get(r)
    val fh = fhOf(q)
    all {
      match q.origin { Reopen(_) => true | _ => false },
      not(terminal(q.phase)),
      not(q.cancelSent),
      conns.get(q.conn).clientAlive,
      client.held.get(fh) == r,
      reqs' = reqs.set(r, q.with("cancelSent", true)),
      client' = client.with("held", client.held.set(fh, 0)).with("dead", client.dead.union(Set(fh))).with("owed", client.owed.union(Set(fh))),
      keepCalls,
      keepConns,
      keepSessions,
      keepGhosts,
    }
  }

  /// Every held handle has been reopened or killed: the connection is published (`conn.rs` 310-325) and the releases owed go out behind it (`take_owed`, 328).
  action publish: bool = {
    val conn = conns.get(gen)
    all {
      conn.clientAlive,
      not(conn.published),
      heldNow.subseteq(client.reopened),
      conns' = conns.set(gen, conn.with("published", true).with("owedToSend", client.owed)),
      keepCalls,
      keepReqs,
      gen' = gen,
      sid' = sid,
      keepSessions,
      keepClient,
      keepGhosts,
    }
  }

  /// `send_releases` 641-690: a release owed is sent with no cancel and no give-up; one the server does not answer stays owed, for the next resume.
  action sendOwed(fh: int): bool = {
    val conn = conns.get(gen)
    val r = lowestFree
    all {
      conn.clientAlive,
      conn.published,
      conn.owedToSend.contains(fh),
      r <= R,
      reqs' = reqs.set(r, newReq(OwedRelease(fh), 1, gen, conn)),
      conns' = conns.set(gen, conn.with("owedToSend", conn.owedToSend.exclude(Set(fh)))),
      keepCalls,
      gen' = gen,
      sid' = sid,
      keepSessions,
      keepClient,
      keepGhosts,
    }
  }

  // ---- Connections and sessions (`crates/client/src/conn.rs`, `crates/server/src/session.rs`) ----

  /// The server's connection task ends (`handle_connection` 671-677, `DetachOnDrop`): the session's grace starts if this connection held its epoch (`Sessions::detach`). A request not yet decoded is gone; one held in `drain` is dropped by `send.stopped()` (1156-1175); one queued for a blocking thread, or running, goes on.
  action loseServer(g: int): bool = {
    val conn = conns.get(g)
    all {
      conn.serverAlive,
      conns' = conns.set(g, conn.with("serverAlive", false)),
      sessions' = sessions.setBy(conn.session, ses => if (ses.epoch == conn.epoch) ses.with("detached", true) else ses),
      pool' = pool,
      reqs' = REQS.mapBy(r => {
        val q = reqs.get(r)
        if (q.conn == g and (q.phase == Transit or q.phase == Held)) q.with("phase", Dropped) else q
      }),
      keepCalls,
      gen' = gen,
      sid' = sid,
      keepClient,
      keepGhosts,
    }
  }

  /// The client connects again and the server resumes the session (`Sessions::resume` 275-291, M1): the epoch moves on, the changes still running become `running_older`, and those given up on are no longer counted apart. A connection the server still held is taken over and closed (`handle_connection` 625-628), what it had not decoded or had held going with it. The connection is published at once, with the releases owed to send (`conn.rs` 328).
  action reconnect: bool = {
    val g = gen + 1
    val old = conns.get(gen)
    val ses = sessions.get(sid)
    all {
      g <= MAX_GEN,
      not(old.clientAlive),
      ses.live,
      gen' = g,
      sid' = sid,
      sessions' = sessions.set(sid, ses.with("epoch", ses.epoch + 1).with("runningOlder", ses.runningOlder + ses.running).with("running", 0).with("abandoned", 0).with("detached", false).with("handshakeLost", false)),
      pool' = pool,
      conns' = conns.set(g, liveConn(sid, ses.epoch + 1, true, client.owed)).setBy(gen, k => k.with("serverAlive", false)),
      reqs' = REQS.mapBy(r => {
        val q = reqs.get(r)
        if (q.conn == gen and old.serverAlive and (q.phase == Transit or q.phase == Held)) q.with("phase", Dropped) else q
      }),
      keepCalls,
      keepClient,
      keepGhosts,
    }
  }

  /// The client connects again, but the server no longer has the session: `Sessions::create` 239-272 makes a new one and the client starts from nothing (`conn.rs` 290-300): the releases owed to the old session are moot, and the held handles are reopened before the connection is published. The old connection, if the server still holds it, is nobody's to close, and its requests go on (G1).
  action newSession: bool = {
    val g = gen + 1
    val s = sid + 1
    all {
      g <= MAX_GEN,
      not(conns.get(gen).clientAlive),
      not(sessions.get(sid).live),
      gen' = g,
      sid' = s,
      sessions' = sessions.set(s, freshSession),
      pool' = pool,
      conns' = conns.set(g, liveConn(s, 1, heldNow == Set(), Set())),
      client' = client.with("owed", Set()).with("reopened", Set()),
      keepCalls,
      keepReqs,
      keepGhosts,
    }
  }

  /// The resume handshake fails after the server resumed (`DetachUnlessAcked` 729-750): the epoch and the counts have moved, no connection of the client's carries the new epoch, and the session is detached again. Once between connections, so the model stays finite.
  action handshakeLost: bool = {
    val ses = sessions.get(sid)
    all {
      not(conns.get(gen).clientAlive),
      ses.live,
      not(ses.handshakeLost),
      sessions' = sessions.set(sid, ses.with("epoch", ses.epoch + 1).with("runningOlder", ses.runningOlder + ses.running).with("running", 0).with("abandoned", 0).with("detached", true).with("handshakeLost", true)),
      pool' = pool,
      keepCalls,
      keepReqs,
      keepConns,
      keepClient,
      keepGhosts,
    }
  }

  /// The session's grace runs out (`Sessions::reap`), or it is the oldest of too many detached ones (`create` 252-269): it leaves the table. Nothing tells its requests, which still compare epochs against it.
  action dropSession(s: int): bool = {
    val ses = sessions.get(s)
    all {
      ses.live,
      ses.detached,
      sessions' = sessions.set(s, ses.with("live", false)),
      pool' = pool,
      keepCalls,
      keepReqs,
      keepConns,
      keepClient,
      keepGhosts,
    }
  }

  /// The last `Arc<SessionState>` of a dropped session goes, once its connection task and every request of it have ended: its `Handles` close and give their slots back.
  action closeSession(s: int): bool = {
    val ses = sessions.get(s)
    val held = CALLS.filter(fh => ses.handles.get(fh).by != 0)
    all {
      ses.epoch > 0,
      not(ses.live),
      GENS.forall(g => conns.get(g).session != s or not(conns.get(g).serverAlive)),
      REQS.forall(r => reqs.get(r).session != s or terminal(reqs.get(r).phase)),
      held != Set(),
      sessions' = sessions.set(s, ses.with("handles", CALLS.mapBy(fh => noEntry))),
      pool' = pool - held.size(),
      keepCalls,
      keepReqs,
      keepConns,
      keepClient,
      keepGhosts,
    }
  }

  // ---- The server's requests (`crates/server/src/session.rs` `handle_request`, `ops.rs`, `handles.rs`) ----

  /// The request is decoded and, for a change, the fence read once (1124-1129): held in `drain` if it is above zero, else straight to the blocking pool. Nothing arrives on a connection the server has lost.
  action arrive(r: int): bool = {
    val q = reqs.get(r)
    all {
      q.phase == Transit,
      conns.get(q.conn).serverAlive,
      reqs' = reqs.set(r, q.with("phase", if (orderedReq(q) and fencing(q.session, q.epoch) > 0) Held else Ready)),
      keepCalls,
      keepConns,
      keepSessions,
      keepClient,
      keepGhosts,
    }
  }

  /// `SessionState::drain` 164-180: the held change goes on once nothing is left of the earlier connections' changes and of those given up on; one whose session has resumed elsewhere meanwhile is let go, and `begin` then refuses it.
  def canDrain(r: int): bool = {
    val q = reqs.get(r)
    val ses = sessions.get(q.session)
    q.phase == Held and (ses.epoch != q.epoch or ses.runningOlder + ses.abandoned == 0)
  }
  action drain(r: int): bool = {
    val q = reqs.get(r)
    val ses = sessions.get(q.session)
    all {
      canDrain(r),
      reqs' = reqs.set(r, q.with("phase", if (ses.epoch != q.epoch) Superseded else Ready)),
      keepCalls,
      keepConns,
      keepSessions,
      keepClient,
      keepGhosts,
    }
  }

  /// Whether `r` beginning now breaks S1: for a change a ended before a change b started, a request of a is begun and unfinished while a request of b begins, or a request of a begins while one of b has begun. With `oneSession`, only pairs of requests on one session count, as design.md's S1 has it.
  def overtakes(r: int, oneSession: bool): bool = {
    val q = reqs.get(r)
    def paired(x: int): bool = begun(reqs.get(x).phase) and (not(oneSession) or reqs.get(x).session == q.session)
    match q.origin {
      OfCall(c) => ordered(kindOf(c)) and (
        calls.get(c).endedBefore.exists(a => ordered(kindOf(a)) and REQS.exists(ra => reqs.get(ra).origin == OfCall(a) and paired(ra) and reqs.get(ra).phase != Finished))
        or CALLS.exists(b => calls.get(b).endedBefore.contains(c) and ordered(kindOf(b)) and REQS.exists(rb => reqs.get(rb).origin == OfCall(b) and paired(rb))))
      | _ => false
    }
  }

  /// Whether `r` beginning now is a resend of a change beginning before an earlier attempt on the same session has finished.
  def resendOvertakes(r: int): bool = {
    val q = reqs.get(r)
    match q.origin {
      OfCall(c) => ordered(kindOf(c)) and REQS.exists(r0 => {
        val q0 = reqs.get(r0)
        q0.origin == OfCall(c) and q0.attempt < q.attempt and q0.session == q.session and begun(q0.phase) and q0.phase != Finished
      })
      | _ => false
    }
  }

  /// `Handles::reserve` 242-259, as the open begins: refused if the id was released (the window), else the slot of the entry already under the id, else a slot of the pool.
  def reserve(q: Req): Slot = {
    val ses = sessions.get(q.session)
    val fh = fhOf(q)
    if (listHas(ses.released, fh)) Refused
    else if (ses.handles.get(fh).by != 0) Kept
    else Taken
  }

  /// `SessionState::begin` 115-128, on the blocking thread: a change is counted as running unless the session has resumed on a newer connection since (superseded); one the client gave up on is `Cancelled` by then and never gets here. The fence is not read again. An unordered request begins whatever the epoch. An open reserves its slot here, before anything is opened. The ghosts record whether this begin broke the ordering.
  action begin(r: int): bool = {
    val q = reqs.get(r)
    val ses = sessions.get(q.session)
    val slot = if (opensReq(q)) reserve(q) else NoSlot
    all {
      q.phase == Ready,
      if (orderedReq(q) and ses.epoch != q.epoch) all {
        reqs' = reqs.set(r, q.with("phase", Superseded)),
        keepSessions,
        keepGhosts,
      } else all {
        reqs' = reqs.set(r, q.with("phase", Running).with("slot", slot)),
        sessions' = if (orderedReq(q)) sessions.set(q.session, ses.with("running", ses.running + 1)) else sessions,
        pool' = if (slot == Taken) pool + 1 else pool,
        overtook' = (overtook or overtakes(r, true)),
        overtookAcross' = (overtookAcross or overtakes(r, false)),
        resendOvertook' = (resendOvertook or resendOvertakes(r)),
      },
      keepCalls,
      keepConns,
      keepClient,
    }
  }

  /// `Slot::insert` 96-128, once the open itself has succeeded (`errno` says it failed): refused, and the slot given back, if the id was released meanwhile or the entry a retried open relied on is gone; else the entry is kept under the id, replacing one already there and giving the second slot back.
  def inserted(ses: Session, q: Req, r: int, errno: bool): (Session, int) = {
    val fh = fhOf(q)
    val taken = if (q.slot == Taken) 1 else 0
    if (q.slot == Refused or errno or listHas(ses.released, fh) or (q.slot == Kept and ses.handles.get(fh).by == 0)) Tup(ses, pool - taken)
    else Tup(
      ses.with("handles", ses.handles.set(fh, { by: r, releasedBefore: ses.releasedEver.contains(fh) })),
      if (ses.handles.get(fh).by != 0) pool - taken else pool
    )
  }

  /// `Handles::remove` 290-303: the id is remembered, and the handle under it, if any, closed and its slot given back; a release of an unknown handle is no error.
  def released(ses: Session, q: Req): (Session, int) = {
    val fh = fhOf(q)
    Tup(
      ses.with("released", remember(ses.released, fh)).with("releasedEver", ses.releasedEver.union(Set(fh))).with("handles", ses.handles.set(fh, noEntry)),
      if (ses.handles.get(fh).by != 0) pool - 1 else pool
    )
  }

  /// The work ends, with a reply or an errno (an open refused at `reserve` always with an errno), and `GuardChange::drop` 190-213 uncounts the change under the epoch it began at; one given up on sends no reply (1272) but its work stands.
  action finish(r: int, errno: bool): bool = {
    val q = reqs.get(r)
    val ses = sessions.get(q.session)
    val failed = errno or q.slot == Refused
    val worked = if (opensReq(q)) inserted(ses, q, r, errno) else if (releasesReq(q)) released(ses, q) else Tup(ses, pool)
    val counted = if (not(orderedReq(q))) worked._1
      else if (ses.epoch == q.epoch) worked._1.with("running", ses.running - 1).with("abandoned", if (q.phase == Abandoned) ses.abandoned - 1 else ses.abandoned)
      else worked._1.with("runningOlder", ses.runningOlder - 1)
    all {
      q.phase == Running or q.phase == Abandoned,
      not(releasesReq(q)) or not(errno),
      reqs' = reqs.set(r, q.with("phase", Finished).with("answer", if (q.phase == Abandoned) q.answer else if (failed) ErrnoReply else Reply)),
      sessions' = sessions.set(q.session, counted),
      pool' = worked._2,
      keepCalls,
      keepConns,
      keepClient,
      keepGhosts,
    }
  }

  /// The client's reset reaches the server (`cancel_asked`; `SessionState::abandon` 131-151): a change not begun is dropped unrun and answered UNRUN (1134-1155 while held, 1234 while queued); one running is answered FENCED and counted in `abandoned` if its connection is current (M2); one finished is answered by its reply as usual. The count moves here, and the client sees the answer at `receive`, a later step: the first of M2's orders.
  action seeCancel(r: int): bool = {
    val q = reqs.get(r)
    val ses = sessions.get(q.session)
    all {
      q.cancelSent,
      not(q.cancelSeen),
      conns.get(q.conn).serverAlive,
      if (q.phase == Transit or q.phase == Held or q.phase == Ready) all {
        reqs' = reqs.set(r, q.with("phase", Cancelled).with("cancelSeen", true).with("answer", Unrun)),
        keepSessions,
      } else if (q.phase == Running) all {
        reqs' = reqs.set(r, q.with("phase", Abandoned).with("cancelSeen", true).with("answer", Fenced)),
        sessions' = if (ses.epoch == q.epoch) sessions.set(q.session, ses.with("abandoned", ses.abandoned + 1)) else sessions,
        pool' = pool,
      } else all {
        reqs' = reqs.set(r, q.with("cancelSeen", true)),
        keepSessions,
      },
      keepCalls,
      keepConns,
      keepClient,
      keepGhosts,
    }
  }

  // ---- Init and step ----

  /// One connection up, attached to a fresh session.
  action init = all {
    calls' = CALLS.mapBy(c => idleCall),
    reqs' = REQS.mapBy(r => absentReq),
    conns' = GENS.mapBy(g => if (g == 1) liveConn(1, 1, true, Set()) else noConn),
    gen' = 1,
    sessions' = SIDS.mapBy(s => if (s == 1) freshSession else noSession),
    sid' = 1,
    client' = emptyClient,
    pool' = 0,
    overtook' = false,
    overtookAcross' = false,
    resendOvertook' = false,
  }

  action stepStart = {
    nondet c = CALLS.oneOf()
    nondet kind = Set(Change, Open).union(CALLS.filter(fh => client.held.get(fh) != 0 or client.orphansDue.contains(fh)).map(fh => Release(fh))).oneOf()
    nondet resendable = BOOLS.oneOf()
    start(c, kind, resendable)
  }
  action stepSend = { nondet c = CALLS.oneOf()  send(c) }
  action stepGiveUp = {
    nondet c = CALLS.oneOf()
    nondet dropped = BOOLS.oneOf()
    giveUp(c, dropped)
  }
  action stepLoseClient = {
    nondet g = GENS.oneOf()
    nondet notSent = CALLS.filter(c => calls.get(c).status == InFlight and reqs.get(calls.get(c).req).conn == g and reqs.get(calls.get(c).req).phase == Transit).powerset().oneOf()
    loseClient(g, notSent)
  }
  action stepLoseServer = { nondet g = GENS.oneOf()  loseServer(g) }
  action stepReceive = { nondet r = REQS.oneOf()  receive(r) }
  action stepSendReopen = { nondet fh = CALLS.oneOf()  sendReopen(fh) }
  action stepGiveUpReopen = { nondet r = REQS.oneOf()  giveUpReopen(r) }
  action stepSendOwed = { nondet fh = CALLS.oneOf()  sendOwed(fh) }
  action stepDropSession = { nondet s = SIDS.oneOf()  dropSession(s) }
  action stepCloseSession = { nondet s = SIDS.oneOf()  closeSession(s) }
  action stepArrive = { nondet r = REQS.oneOf()  arrive(r) }
  action stepDrain = { nondet r = REQS.oneOf()  drain(r) }
  action stepBegin = { nondet r = REQS.oneOf()  begin(r) }
  action stepFinish = {
    nondet r = REQS.oneOf()
    nondet errno = BOOLS.oneOf()
    finish(r, errno)
  }
  action stepSeeCancel = { nondet r = REQS.oneOf()  seeCancel(r) }

  action step = any {
    stepStart,
    stepSend,
    stepGiveUp,
    stepLoseClient,
    stepLoseServer,
    stepReceive,
    stepSendReopen,
    stepGiveUpReopen,
    publish,
    stepSendOwed,
    reconnect,
    newSession,
    handshakeLost,
    stepDropSession,
    stepCloseSession,
    stepArrive,
    stepDrain,
    stepBegin,
    stepFinish,
    stepSeeCancel,
  }

  // ---- Invariants ----

  /// S1, no overtaking, as design.md states it: for changes a and b of one session, b after a, every request of a that ran had finished before any request of b began (`overtakes`).
  val S1 = not(overtook)

  /// S1 across the client's sessions. Expected to fail: a session the server dropped does not stop its old connection's queued changes (G1).
  val S1strong = not(overtookAcross)

  /// S2, bounded repeats: a call's request ran at most twice, the second time only as a resend, and for a change on one session only after the first finished (`resendOvertakes`).
  val S2 = not(resendOvertook) and CALLS.forall(c => {
    val ran = REQS.filter(r => reqs.get(r).origin == OfCall(c) and begun(reqs.get(r).phase))
    ran.size() <= 2 and (ran.size() == 2 implies calls.get(c).resendable)
  })

  /// Nothing is in flight or about to be: every request has ended and every answer on a live connection been read, every call is idle or ended, the current connection is up at both ends and published with no cancel pending and nothing left to send, and no orphan release is due. S3 compares the two handle tables here; `owed` is left to S3 itself.
  val quiescent = {
    val conn = conns.get(gen)
    REQS.forall(r => terminal(reqs.get(r).phase) and (reqs.get(r).answer == NoAnswer or not(conns.get(reqs.get(r).conn).clientAlive)))
      and CALLS.forall(c => calls.get(c).status == Idle or calls.get(c).status == Ended)
      and conn.clientAlive and conn.serverAlive and conn.published and conn.cancels == 0 and conn.owedToSend == Set()
      and client.orphansDue == Set()
  }

  /// The server holds `fh` for the client's session as the client holds it, or one of the known gaps explains the difference: the open's resend failed with an errno after its original was kept (G3), or the id's release was forgotten by the window before the open landed (G4).
  def handleAgrees(fh: int, modulo: bool): bool = {
    val entry = sessions.get(sid).handles.get(fh)
    val serverHas = entry.by != 0
    val clientHas = client.held.get(fh) != 0
    val g3 = reqs.get(entry.by).origin == OfCall(fh) and calls.get(fh).outcome == Errno
    and {
      clientHas implies serverHas,
      serverHas implies (clientHas or (modulo and (g3 or entry.releasedBefore))),
    }
  }

  /// S3, handles, with the known gaps allowed for: once nothing is in flight and every owed release is sent, the server's handles for the session are exactly the client's live ones.
  val S3 = (quiescent and client.owed == Set()) implies CALLS.forall(fh => handleAgrees(fh, true))

  /// S3 with no allowance for the gaps, and a release owed on a live connection not waited for. Expected to fail: G3, G4 and G5 each break it.
  val S3plain = quiescent implies CALLS.forall(fh => handleAgrees(fh, false))
  /// Each gap on its own: S3 with one allowance dropped, or with owed releases not waited for. Each expected to fail.
  val S3noG3 = (quiescent and client.owed == Set()) implies CALLS.forall(fh => {
    val entry = sessions.get(sid).handles.get(fh)
    handleAgrees(fh, true) and ((entry.by != 0 and client.held.get(fh) == 0) implies entry.releasedBefore)
  })
  val S3noG4 = (quiescent and client.owed == Set()) implies CALLS.forall(fh => {
    val entry = sessions.get(sid).handles.get(fh)
    handleAgrees(fh, true) and ((entry.by != 0 and client.held.get(fh) == 0) implies not(entry.releasedBefore))
  })
  val S3noG5 = quiescent implies CALLS.forall(fh => handleAgrees(fh, true))

  /// An open's handle is never replaced by another file's: whatever the client holds under an id, the server's entry for its session under that id is the request the client accepted.
  val S3identity = CALLS.forall(fh => {
    val entry = sessions.get(sid).handles.get(fh)
    (client.held.get(fh) != 0 and entry.by != 0) implies entry.by == client.held.get(fh)
  })

  /// The attachment's counts are what the request phases say they are, through every resume and takeover.
  val countsConsistent = SIDS.forall(s => {
    val ses = sessions.get(s)
    val mine = REQS.filter(r => {
      val q = reqs.get(r)
      q.session == s and orderedReq(q) and (q.phase == Running or q.phase == Abandoned)
    })
    ses.running == mine.filter(r => reqs.get(r).epoch == ses.epoch).size() and
    ses.abandoned == mine.filter(r => reqs.get(r).epoch == ses.epoch and reqs.get(r).phase == Abandoned).size() and
    ses.runningOlder == mine.filter(r => reqs.get(r).epoch < ses.epoch).size()
  })

  /// `HandlePool::used` is the handles every session holds plus the slots of the opens under way that took one.
  val poolConsistent = pool == SIDS.fold(0, (n, s) => n + CALLS.filter(fh => sessions.get(s).handles.get(fh).by != 0).size())
    + REQS.filter(r => reqs.get(r).slot == Taken and (reqs.get(r).phase == Running or reqs.get(r).phase == Abandoned)).size()

  /// A connection the client still uses carries its session's current epoch; the model's own sanity, since `send` relies on it.
  val aliveIsCurrent = GENS.forall(g => {
    val k = conns.get(g)
    k.clientAlive implies (k.session == sid and k.epoch == sessions.get(k.session).epoch)
  })

  // ---- Shorthands for the scenario runs ----

  def reqOf(c: int): int = calls.get(c).req
  def phaseOf(r: int): Phase = reqs.get(r).phase
  def okSoFar: bool = S1 and S2 and S3 and S3identity and countsConsistent and poolConsistent and aliveIsCurrent

  // ---- Reachability: each of these must be reachable, or the model is checking nothing ----

  val seenFenced = REQS.exists(r => reqs.get(r).phase == Abandoned)
  val seenSuperseded = REQS.exists(r => reqs.get(r).phase == Superseded)
  val seenResendRan = CALLS.exists(c => REQS.filter(r => reqs.get(r).origin == OfCall(c) and begun(reqs.get(r).phase)).size() == 2)
  val seenTakeover = GENS.exists(g => g < gen and not(conns.get(g).serverAlive) and conns.get(g).epoch > 0 and REQS.exists(r => reqs.get(r).conn == g and reqs.get(r).phase == Dropped))
  val seenRefused = REQS.exists(r => reqs.get(r).slot == Refused and reqs.get(r).phase == Finished)
  val seenOrphanRan = REQS.exists(r => {
    val q = reqs.get(r)
    q.phase == Finished and releasesReq(q) and fhOf(q) != 0 and (calls.get(fhOf(q)).outcome == GaveUp or calls.get(fhOf(q)).outcome == Failed)
  })
  val seenQuiescentAfterReopen = quiescent and REQS.exists(r => reqs.get(r).phase == Finished and (match reqs.get(r).origin { Reopen(_) => true | _ => false }))
  val seenQuiescentAfterOwed = quiescent and REQS.exists(r => reqs.get(r).phase == Finished and (match reqs.get(r).origin { OwedRelease(_) => true | _ => false }))
  val seenQuiescentHolding = quiescent and heldNow != Set() and gen > 1
}
