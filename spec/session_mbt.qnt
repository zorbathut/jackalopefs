// The small instance, for model-based testing (spec/README.md, "Model-based testing"): its runs carry, in each state after the first, which of the client's own steps the state before allowed, so the client's code can be checked to allow exactly those. `quint run` uses this module with `--init mbtInit --step mbtStep`, and `quint test` for its own scripted runs; TLC never sees it.
module session_mbt {
  import session(N = 3, R = 6, MAX_GEN = 3).* from "./session"

  /// What the client may do in a state, but for the request pool, which bounds only the model: the calls it may send, the releases owed it may send, the handles it may reopen, and whether it may publish its connection. `changeWaits` and `releaseWaits` are the corpus's: a change, or a kernel's release, waits on a published connection with cancels pending.
  type Guards = { send: Set[int], owed: Set[int], reopen: Set[int], publish: bool, changeWaits: bool, releaseWaits: bool }

  var guards: Guards

  /// A call, ordered or not, waits on a published connection it may take while the connection has cancels pending.
  def waitsWithCancels(isOrdered: bool): bool = CALLS.exists(c => calls.get(c).status == Waiting and ordered(calls.get(c).kind) == isOrdered and conns.get(gen).clientAlive and conns.get(gen).published and gen >= calls.get(c).minGen and conns.get(gen).cancels > 0)

  val guardsNow: Guards = {
    send: CALLS.filter(c => sendReady(c)),
    owed: CALLS.filter(fh => owedReady(fh)),
    reopen: CALLS.filter(fh => reopenReady(fh)),
    publish: publishReady,
    changeWaits: waitsWithCancels(true),
    releaseWaits: waitsWithCancels(false),
  }

  // ---- States the corpus's runs must pass through, so that `cargo test` sees the client there: each `never*` is violated by a run that reaches its state (`scripts/spec/mbt.sh corpus`) ----

  /// The state before had a change wait on a published connection for its pending cancels: a run reaching it checks the client's guards there.
  val neverChangeWaitsForCancels = not(guards.changeWaits)
  /// The state before allowed the client to publish its connection, after a new session's reopens.
  val neverPublishable = not(guards.publish)
  /// A call's reply lost twice: the second time it fails.
  val neverLostTwice = not(CALLS.exists(c => calls.get(c).lostOnce and calls.get(c).outcome == Failed))

  /// A step of a scripted run, recording what the state before allowed, as `mbtStep` does.
  action g(a: bool): bool = all { guards' = guardsNow, a }

  // ---- Scripted runs for the states random runs rarely reach; their traces carry the guards too ----

  /// A kernel's release, not ordered, goes out while a change given up on is still to be answered.
  run releaseWaitsTest = mbtInit
    .then(g(start(1, Open, true))).then(g(send(1))).then(g(arrive(1))).then(g(begin(1))).then(g(finish(1, false))).then(g(receive(1)))
    .then(g(start(2, Change, true))).then(g(send(2))).then(g(arrive(2))).then(g(begin(2))).then(g(giveUp(2)))
    .then(g(start(3, Release(1), true))).expect(conns.get(1).cancels == 1)
    .then(g(send(3))).expect(guards.releaseWaits and guards.send == Set(3))
    .then(g(seeCancel(2))).then(g(receive(2))).then(g(finish(2, false)))
    .then(g(arrive(3))).then(g(begin(3))).then(g(finish(3, false))).then(g(receive(3)))
    .expect(quiescent and okSoFar)

  /// A new session reopens two handles, and publishes once both have answered.
  run reopenRoundTest = mbtInit
    .then(g(start(1, Open, true))).then(g(send(1))).then(g(arrive(1))).then(g(begin(1))).then(g(finish(1, false))).then(g(receive(1)))
    .then(g(start(2, Open, true))).then(g(send(2))).then(g(arrive(2))).then(g(begin(2))).then(g(finish(2, false))).then(g(receive(2)))
    .then(g(loseClient(1, Set()))).then(g(loseServer(1))).then(g(dropSession(1))).then(g(newSession))
    .then(g(reopenSend(1))).expect(guards.reopen == Set(1, 2))
    .then(g(reopenSend(2))).then(g(arrive(3))).then(g(begin(3))).then(g(finish(3, false))).then(g(receive(3)))
    .then(g(arrive(4))).then(g(begin(4))).then(g(finish(4, false))).then(g(receive(4)))
    .then(g(publish)).expect(guards.publish)
    .then(g(closeSession(1)))
    .expect(quiescent and okSoFar)

  action mbtInit = all { init, guards' = { send: Set(), owed: Set(), reopen: Set(), publish: false, changeWaits: false, releaseWaits: false } }
  action mbtStep = all { guards' = guardsNow, step }
}
