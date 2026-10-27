// Replays what a test's client and server did, as `crates/perf/src/spec_trace.rs` recorded it, against the session model: each recorded event becomes the model action it stands for, which must be enabled, and what the code observed (a held change, a superseded one, a cancel's verdict, the attachment's counts, an answer) must be what the model says; every invariant must hold at every step. `spec/README.md`, "Trace validation", says which code point each event is recorded at and which rule applies where the code takes in several steps what the model takes in one.
module replay {
  import session(N = 16, R = 32, MAX_GEN = 4).* from "./session"

  /// One recorded event, flat: `kind` says which fields mean anything. Connections are by the client's generation, sessions and handles by their real ids, calls by the recorder's numbers.
  type Ev = {
    kind: str,
    origin: str,
    call: int,
    gen: int,
    stream: int,
    fh: int,
    session: int,
    ckind: str,
    ordered: bool,
    resendable: bool,
    resumed: bool,
    change: bool,
    held: bool,
    errno: bool,
    written: bool,
    counted: bool,
    failure: str,
    verdict: str,
    end: str,
    begun: str,
    cause: str,
    kept: bool,
    dropped: bool,
    counts: bool,
    epoch: int,
    running: int,
    abandoned: int,
    older: int,
  }

  pure def ev(kind: str): Ev = { kind: kind, origin: "", call: 0, gen: 0, stream: 0, fh: 0, session: 0, ckind: "", ordered: false, resendable: false, resumed: false, change: false, held: false, errno: false, written: false, counted: false, failure: "", verdict: "", end: "", begun: "", cause: "", kept: false, dropped: false, counts: false, epoch: 0, running: 0, abandoned: 0, older: 0 }

  /// Replay's own state: the event it is at, and the model's names for the code's.
  type Rp = {
    at: int,
    // Real call → model call; 0 for a call the model leaves out.
    callOf: int -> int,
    // Real handle → the model call of its open.
    fhCall: int -> int,
    // Real call → the model request its send took, until its stream is known.
    pending: int -> int,
    // Real handle → the model request of its release the release task is sending, until its stream is known.
    owedPending: int -> int,
    // (generation, stream) → model request, and back.
    reqAt: (int, int) -> int,
    keyOf: int -> (int, int),
    // Exchanges the model leaves out (reads, a handle it never had), and attempts nothing of which reached the server: the server may record a frame of the latter never decoded, and nothing else.
    ignored: Set[(int, int)],
    unsent: Set[(int, int)],
    // Exchanges whose answer replay took before the client's loss of their connection.
    received: Set[(int, int)],
    // Real session → model session.
    sidOf: int -> int,
    nextCall: int,
  }
  var rp: Rp

  pure def look(m: a -> int, k: a): int = if (m.keys().contains(k)) m.get(k) else 0
  pure def least(s: Set[int]): int = s.fold(R + 1, (low, x) => if (x < low) x else low)

  action keepAll = all { keepCalls, keepReqs, keepConns, keepSessions, keepClient, keepGhosts }
  /// The event changes nothing the model has, or the model took it earlier.
  action skip = all { keepAll, rp' = rp.with("at", rp.at + 1) }
  /// An event the model cannot take: replay stops here.
  action refuse = all { false, keepAll, rp' = rp }

  /// What replay makes of an exchange the server recorded: the model request it is (above 0), 0 for one the model leaves out, -1 for an attempt nothing of which was sent, -2 for one replay never heard of from the client.
  def keyed(k: (int, int)): int =
    if (rp.reqAt.keys().contains(k)) rp.reqAt.get(k)
    else if (rp.ignored.contains(k)) 0
    else if (rp.unsent.contains(k)) -1
    else -2

  // ---- Lookahead over the trace ----

  pure def after(t: List[Ev], i: int): List[Ev] = t.slice(i + 1, t.length())
  pure def first(l: List[Ev]): Ev = if (l.length() > 0) l[0] else ev("none")
  /// The call's next event after `i` other than its stream being opened.
  pure def nextOfCall(t: List[Ev], i: int, call: int): Ev = first(after(t, i).select(e => e.origin == "call" and e.call == call and e.kind != "stream"))
  /// Whether a failure is one of an attempt nothing of which reaches the server: given up on before the frame was written whole, or the frame not sent whole (`NotSent`, which the code may also hand a call on a connection whose loss the manager has seen and not yet published).
  pure def failsUnsent(e: Ev): bool = e.kind == "failed" and ((e.failure == "gaveup" and not(e.written)) or e.failure == "notsent")
  /// The call's attempt from `i` reaches the server with nothing, or fails on a dead handle. The model takes such an attempt as never sent, which is what its `loseClient` makes of a frame not sent whole.
  pure def unsentCall(t: List[Ev], i: int, call: int): bool = {
    val e = nextOfCall(t, i, call)
    failsUnsent(e) or (e.kind == "failed" and e.failure == "stale")
  }
  /// The exchange on stream `k` fails with nothing of it sent.
  pure def unsentKey(t: List[Ev], i: int, k: (int, int)): bool = failsUnsent(first(after(t, i).select(e => e.kind == "failed" and (e.gen, e.stream) == k)))
  /// The release task's send of the release of real handle `fh` from `i` reaches the server with nothing.
  pure def unsentOwed(t: List[Ev], i: int, fh: int): bool = {
    val e = first(after(t, i).select(x => x.origin == "owed" and x.fh == fh and (x.kind == "stream" or x.kind == "failed")))
    e.kind != "stream" or unsentKey(t, i, (e.gen, e.stream))
  }
  /// The handshake that resumed or made `session` at `i` fails before its Ack.
  pure def handshakeFails(t: List[Ev], i: int, session: int): bool =
    first(after(t, i).select(e => (e.kind == "handshakefailed" or e.kind == "attached") and e.session == session)).kind == "handshakefailed"
  pure val SERVER_KEYED = Set("decoded", "undecoded", "heldended", "began", "abandoned", "finished")
  /// Requests on a connection the server has lost, not yet decoded or held, of which the server records nothing more: a frame that came as the connection went, which no task ever read. The model drops them (`dropCut`) as soon as nothing later needs them.
  def stranded(t: List[Ev], i: int): Set[int] = REQS.filter(r => {
    val q = reqs.get(r)
    (q.phase == Transit or q.phase == Held) and not(conns.get(q.conn).serverAlive) and rp.keyOf.keys().contains(r)
      and t.slice(i, t.length()).select(e => SERVER_KEYED.contains(e.kind) and (e.gen, e.stream) == rp.keyOf.get(r)).length() == 0
  })
  /// Requests on connection `g` whose answer the client read before its manager saw the connection end: the code records the two on different tasks.
  def answeredBefore(t: List[Ev], i: int, g: int): Set[int] = REQS.filter(r => {
    val q = reqs.get(r)
    val k = if (rp.keyOf.keys().contains(r)) rp.keyOf.get(r) else (0, 0)
    q.conn == g and Set(Reply, ErrnoReply, Unrun, Fenced).contains(q.answer) and not(rp.received.contains(k))
      and after(t, i).select(e => (e.kind == "answered" or e.kind == "cancelanswered") and (e.gen, e.stream) == k).length() > 0
  })

  // ---- The client ----

  /// Maps stream `k` to model request `r`, a step on.
  def mapped(k: (int, int), r: int): Rp = rp.with("at", rp.at + 1).with("reqAt", rp.reqAt.put(k, r)).with("keyOf", rp.keyOf.put(r, k))

  action onCallStarted(t: List[Ev], i: int, e: Ev): bool = {
    val c = rp.nextCall
    val fh = look(rp.fhCall, e.fh)
    if (e.ckind == "other" or (e.ckind == "release" and fh == 0) or nextOfCall(t, i, e.call).failure == "stale") skip
    else {
      val kind = if (e.ckind == "open") Open else if (e.ckind == "release") Release(fh) else Change
      all {
        c <= N,
        start(c, kind, e.resendable),
        rp' = {
          val started = rp.with("at", rp.at + 1).with("nextCall", c + 1).with("callOf", rp.callOf.put(e.call, c))
          if (e.ckind == "open") started.with("fhCall", started.fhCall.put(e.fh, c)) else started
        },
      }
    }
  }

  action onCallReady(t: List[Ev], i: int, e: Ev): bool = {
    val c = look(rp.callOf, e.call)
    val sent = rp.with("at", rp.at + 1).with("pending", rp.pending.put(e.call, lowestFree))
    val passed = rp.with("at", rp.at + 1).with("pending", rp.pending.put(e.call, 0))
    if (c == 0) skip
    else if (unsentCall(t, i, e.call)) all { keepAll, rp' = passed }
    else if (gen != e.gen) refuse
    else all { send(c), rp' = sent }
  }

  action onReleaseReady(t: List[Ev], i: int, e: Ev): bool = {
    val fh = look(rp.fhCall, e.fh)
    if (fh == 0) skip
    else if (unsentOwed(t, i, e.fh)) all { keepAll, rp' = rp.with("at", rp.at + 1).with("owedPending", rp.owedPending.put(e.fh, 0)) }
    else if (gen != e.gen) refuse
    else all { owedSend(fh), rp' = rp.with("at", rp.at + 1).with("owedPending", rp.owedPending.put(e.fh, lowestFree)) }
  }

  action onStream(t: List[Ev], i: int, e: Ev): bool = {
    val k = (e.gen, e.stream)
    val ignore = rp.with("at", rp.at + 1).with("ignored", rp.ignored.union(Set(k)))
    val pass = rp.with("at", rp.at + 1).with("unsent", rp.unsent.union(Set(k)))
    if (e.origin == "call") {
      val r = look(rp.pending, e.call)
      if (look(rp.callOf, e.call) == 0) all { keepAll, rp' = ignore }
      else if (r == 0) all { keepAll, rp' = pass }
      else all { keepAll, rp' = mapped(k, r) }
    } else {
      val fh = look(rp.fhCall, e.fh)
      if (fh == 0) all { keepAll, rp' = ignore }
      else if (e.origin == "owed") {
        val r = look(rp.owedPending, e.fh)
        if (r == 0) all { keepAll, rp' = pass } else all { keepAll, rp' = mapped(k, r).with("owedPending", rp.owedPending.put(e.fh, 0)) }
      }
      else if (unsentKey(t, i, k)) all { keepAll, rp' = pass }
      else all { reopenSend(fh), rp' = mapped(k, lowestFree) }
    }
  }

  action onAnswered(e: Ev): bool = {
    val k = (e.gen, e.stream)
    val r = keyed(k)
    if (rp.received.contains(k) or r == 0) skip
    else if (r < 0) refuse
    else all {
      reqs.get(r).answer == (if (e.errno) ErrnoReply else Reply),
      receive(r),
      rp' = rp.with("at", rp.at + 1),
    }
  }

  action onCancelAnswered(e: Ev): bool = {
    val k = (e.gen, e.stream)
    val r = keyed(k)
    val q = reqs.get(r)
    if (rp.received.contains(k)) skip
    else if (r <= 0 or e.verdict == "undecodable") refuse
    // The connection went before an answer, which the model's loss of it takes care of.
    else if (e.verdict == "lost") skip
    else if (e.verdict == "superseded") all { q.phase == Superseded, skip }
    else all {
      if (e.verdict == "unrun" or e.verdict == "unread") q.answer == Unrun
      else if (e.verdict == "fenced") q.answer == Fenced
      else q.answer == Reply or q.answer == ErrnoReply,
      receive(r),
      rp' = rp.with("at", rp.at + 1),
    }
  }

  action onFailed(e: Ev): bool = {
    val c = look(rp.callOf, e.call)
    val r = keyed((e.gen, e.stream))
    if (e.failure == "notsent" or e.failure == "lost") skip
    else if (e.failure == "other") refuse
    else if (e.origin == "call" and e.failure == "stale") { if (c == 0) skip else refuse }
    else if (e.origin == "reopen") {
      val fh = look(rp.fhCall, e.fh)
      if (e.counted) all { reopenGiveUp(r), rp' = rp.with("at", rp.at + 1) }
      else if (not(e.written) and client.toReopen.contains(fh)) all { reopenUnsentGiveUp(fh), rp' = rp.with("at", rp.at + 1) }
      else skip
    }
    else if (e.origin == "owed") refuse
    else if (c != 0) all {
      e.counted == (calls.get(c).status == InFlight and ordered(calls.get(c).kind)),
      giveUp(c),
      rp' = rp.with("at", rp.at + 1),
    }
    else skip
  }

  /// The connection manager seeing connection `g` end is the model's loss of it at the client: until then the code still sends on it, and each exchange on it learns of the loss by itself, before or after. An answer read before the manager saw the end is taken first, a step of its own.
  action onConnLost(t: List[Ev], i: int, e: Ev): bool = {
    val early = answeredBefore(t, i, e.gen)
    if (not(conns.get(e.gen).clientAlive)) skip
    else if (early != Set()) {
      val r = least(early)
      all { receive(r), rp' = rp.with("received", rp.received.union(Set(rp.keyOf.get(r)))) }
    }
    else all { loseClient(e.gen, Set()), rp' = rp.with("at", rp.at + 1) }
  }

  action onPublished(e: Ev): bool =
    if (conns.get(e.gen).published) skip else all { publish, rp' = rp.with("at", rp.at + 1) }

  action onConnected(e: Ev): bool = all {
    gen == e.gen,
    sid == look(rp.sidOf, e.session),
    keepAll,
    rp' = rp.with("at", rp.at + 1),
  }

  /// A release owed is owed in the model already, or its handle dead; or the call that owes it, an open or a release whose exchange failed with its connection, is still in flight in the model and fails when it loses its connection (`lostCall`): the call fails as soon as its stream does, before the connection manager sees the loss, which owes it in the model.
  action onOwed(e: Ev): bool = {
    val fh = look(rp.fhCall, e.fh)
    if (fh == 0) skip
    else all {
      client.owed.contains(fh) or client.dead.contains(fh) or CALLS.exists(c => calls.get(c).status == InFlight and not(calls.get(c).resendable and not(calls.get(c).lostOnce)) and (c == fh or calls.get(c).kind == Release(fh))),
      skip,
    }
  }

  // ---- The server ----

  action onCreated(t: List[Ev], i: int, e: Ev): bool =
    if (rp.sidOf.keys() == Set()) all { keepAll, rp' = rp.with("at", rp.at + 1).with("sidOf", rp.sidOf.put(e.session, 1)) }
    else if (handshakeFails(t, i, e.session)) skip
    else all { newSession, rp' = rp.with("at", rp.at + 1).with("sidOf", rp.sidOf.put(e.session, sid + 1)) }

  action onResumed(t: List[Ev], i: int, e: Ev): bool = {
    val s = look(rp.sidOf, e.session)
    val ses = sessions.get(s)
    all {
      s == sid,
      e.epoch == ses.epoch + 1,
      e.running == 0 and e.abandoned == 0 and e.older == ses.runningOlder + ses.running,
      e.dropped == not(ses.live),
      if (handshakeFails(t, i, e.session)) handshakeLost else reconnect,
      rp' = rp.with("at", rp.at + 1),
    }
  }

  action onAttached(e: Ev): bool = all {
    e.gen == 0 or conns.get(e.gen).epoch == e.epoch,
    skip,
  }

  action onConnEnded(e: Ev): bool =
    if (e.gen == 0 or not(conns.get(e.gen).serverAlive)) skip
    else all { loseServer(e.gen), rp' = rp.with("at", rp.at + 1) }

  action onSessionDropped(e: Ev): bool = all { dropSession(look(rp.sidOf, e.session)), rp' = rp.with("at", rp.at + 1) }

  action onSessionClosed(e: Ev): bool = {
    val s = look(rp.sidOf, e.session)
    if (s == 0 or CALLS.forall(fh => sessions.get(s).handles.get(fh).by == 0)) skip
    else all { closeSession(s), rp' = rp.with("at", rp.at + 1) }
  }

  /// The attachment's counts after the event, as the code saw them, are the model's for the request's session given what the event does to them (`running`, `abandoned` and `running_older` deltas). A change carries its counts, and nothing else does.
  def countsAgree(e: Ev, q: Req, dRunning: int, dAbandoned: int, dOlder: int): bool = {
    val ses = sessions.get(q.session)
    e.counts == orderedReq(q) and (not(e.counts) or (e.epoch == ses.epoch and e.running == ses.running + dRunning and e.abandoned == ses.abandoned + dAbandoned and e.older == ses.runningOlder + dOlder))
  }

  /// The server's events of a request replay has no model request for: one the model leaves out, else nothing but a frame of an attempt never sent that was never decoded.
  action unmapped(e: Ev, r: int): bool =
    if (r == 0 or (r == -1 and e.kind == "undecoded")) skip else refuse

  action onDecoded(e: Ev): bool = {
    val r = keyed((e.gen, e.stream))
    val q = reqs.get(r)
    if (r <= 0) unmapped(e, r)
    else all {
      e.change == orderedReq(q),
      e.held == (orderedReq(q) and fencing(q.session, q.epoch) > 0),
      arrive(r),
      rp' = rp.with("at", rp.at + 1),
    }
  }

  /// A request the server has lost the connection of: the model takes the loss first, a step of its own, since a request's stream failing may come before the connection's task ends; then the request is dropped.
  action lostWith(e: Ev, r: int): bool =
    if (conns.get(e.gen).serverAlive) all { loseServer(e.gen), rp' = rp }
    else all { dropCut(r), rp' = rp.with("at", rp.at + 1) }

  action onUndecoded(e: Ev): bool = {
    val r = keyed((e.gen, e.stream))
    if (r <= 0) unmapped(e, r)
    else if (e.cause == "reset" and conns.get(e.gen).serverAlive) all { reqs.get(r).cancelSent, seeCancel(r), rp' = rp.with("at", rp.at + 1) }
    else if (e.cause == "other") refuse
    else lostWith(e, r)
  }

  action onHeldEnded(e: Ev): bool = {
    val r = keyed((e.gen, e.stream))
    val q = reqs.get(r)
    if (r <= 0) unmapped(e, r)
    else if (e.end == "lost") lostWith(e, r)
    else if (e.end == "stopped") refuse
    else all {
      (e.end == "superseded") == (sessions.get(q.session).epoch != q.epoch),
      drain(r),
      rp' = rp.with("at", rp.at + 1),
    }
  }

  action onBegan(e: Ev): bool = {
    val r = keyed((e.gen, e.stream))
    val q = reqs.get(r)
    val superseded = orderedReq(q) and sessions.get(q.session).epoch != q.epoch
    if (r <= 0) unmapped(e, r)
    else if (e.begun == "cancelled") all { q.phase == Cancelled, skip }
    else all {
      (e.begun == "superseded") == superseded,
      countsAgree(e, q, if (superseded or not(orderedReq(q))) 0 else 1, 0, 0),
      begin(r),
      rp' = rp.with("at", rp.at + 1),
    }
  }

  action onReserved(e: Ev): bool = {
    val s = look(rp.sidOf, e.session)
    val fh = look(rp.fhCall, e.fh)
    all {
      // The reserve is part of the work, which a cancel may have fenced by then.
      REQS.exists(r => reqs.get(r).session == s and (reqs.get(r).phase == Running or reqs.get(r).phase == Abandoned) and opensReq(reqs.get(r)) and fhOf(reqs.get(r)) == fh and reqs.get(r).slot == (if (e.kept) Kept else Taken)),
      skip,
    }
  }

  action onAbandoned(e: Ev): bool = {
    val r = keyed((e.gen, e.stream))
    val q = reqs.get(r)
    val current = sessions.get(q.session).epoch == q.epoch
    if (r <= 0) unmapped(e, r)
    else if (e.verdict == "finished") all { q.phase == Finished, skip }
    else all {
      (e.verdict == "fenced") == (q.phase == Running),
      countsAgree(e, q, 0, if (e.verdict == "fenced" and current) 1 else 0, 0),
      seeCancel(r),
      rp' = rp.with("at", rp.at + 1),
    }
  }

  action onFinished(e: Ev): bool = {
    val r = keyed((e.gen, e.stream))
    val q = reqs.get(r)
    val ses = sessions.get(q.session)
    val current = ses.epoch == q.epoch
    // An open refused at `Slot::insert` fails in the model by itself.
    val errno = e.errno and not(opensReq(q) and q.slot != Kept and insertRefused(ses, q, false))
    if (r <= 0) unmapped(e, r)
    else all {
      countsAgree(e, q,
        if (orderedReq(q) and current) -1 else 0,
        if (orderedReq(q) and current and q.phase == Abandoned) -1 else 0,
        if (orderedReq(q) and not(current)) -1 else 0),
      finish(r, errno),
      rp' = rp.with("at", rp.at + 1),
    }
  }

  // ---- Driving it ----

  action replayEvent(t: List[Ev], i: int, e: Ev): bool =
    if (e.kind == "callstarted") onCallStarted(t, i, e)
    else if (e.kind == "callready") onCallReady(t, i, e)
    else if (e.kind == "releaseready") onReleaseReady(t, i, e)
    else if (e.kind == "stream") onStream(t, i, e)
    else if (e.kind == "answered") onAnswered(e)
    else if (e.kind == "cancelanswered") onCancelAnswered(e)
    else if (e.kind == "failed") onFailed(e)
    else if (e.kind == "connlost") onConnLost(t, i, e)
    else if (e.kind == "published") onPublished(e)
    else if (e.kind == "connected") onConnected(e)
    else if (e.kind == "owed") onOwed(e)
    else if (e.kind == "created") onCreated(t, i, e)
    else if (e.kind == "resumed") onResumed(t, i, e)
    else if (e.kind == "handshakefailed") skip
    else if (e.kind == "attached") onAttached(e)
    else if (e.kind == "connended") onConnEnded(e)
    else if (e.kind == "sessiondropped") onSessionDropped(e)
    else if (e.kind == "sessionclosed") onSessionClosed(e)
    else if (e.kind == "decoded") onDecoded(e)
    else if (e.kind == "undecoded") onUndecoded(e)
    else if (e.kind == "heldended") onHeldEnded(e)
    else if (e.kind == "began") onBegan(e)
    else if (e.kind == "reserved") onReserved(e)
    else if (e.kind == "abandoned") onAbandoned(e)
    else if (e.kind == "finished") onFinished(e)
    else refuse

  /// One step, with every invariant holding before it: a stranded request dropped, or the event at `rp.at` (or a step it needs first); past the end, nothing.
  action replayStep(t: List[Ev]): bool = all {
    okSoFar,
    if (rp.at >= t.length()) all { keepAll, rp' = rp }
    else {
      val s = stranded(t, rp.at)
      if (s != Set()) all { dropCut(least(s)), rp' = rp }
      else replayEvent(t, rp.at, t[rp.at])
    },
  }

  action replayInit = all { init, rp' = { at: 0, callOf: Map(), fhCall: Map(), pending: Map(), owedPending: Map(), reqAt: Map(), keyOf: Map(), ignored: Set(), unsent: Set(), received: Set(), sidOf: Map(), nextCall: 1 } }

  /// A trace replays when every event was taken, and the invariants hold at the end too. A step may go to a loss, an early answer or a stranded request rather than to an event, so a run gives replay three steps an event.
  def replayed(t: List[Ev]): bool = rp.at == t.length() and okSoFar
}
