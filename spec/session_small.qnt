// The instance the simulator and the scenario runs use; one instance per file, since the checkers take the whole file's compiled form and Apalache refuses one past 20 MB.
/// The bounds the simulator runs with, and the scenario runs: the disconnect grid's columns and the focused tests as traces (`quint test`).
module session_small {
  import session(N = 3, R = 6, MAX_GEN = 3, RELEASED_KEPT = 1).* from "./session"

  /// `reply_lost`: the original ran, its reply went with the connection, and the resend on the next connection waits behind it and then runs once.
  run replyLostTest = init
    .then(start(1, Change, true)).then(send(1)).then(arrive(1)).then(begin(1))
    .then(loseClient(1, Set())).expect(calls.get(1).status == Waiting and calls.get(1).lostOnce and calls.get(1).minGen == 2)
    .then(loseServer(1)).then(reconnect).expect(sessions.get(1).runningOlder == 1)
    .then(send(1)).expect(reqOf(1) == 2).then(arrive(2)).expect(phaseOf(2) == Held)
    .expect(not(canDrain(2)))
    .then(finish(1, false)).expect(sessions.get(1).runningOlder == 0)
    .then(drain(2)).then(begin(2)).expect(phaseOf(1) == Finished and okSoFar)
    .then(finish(2, false)).then(receive(2)).expect(calls.get(1).outcome == Replied and okSoFar)

  /// `original_late`: the original had not begun when its connection was lost and the session resumed elsewhere; it is refused by the epoch check, and the call's resend runs alone.
  run originalLateTest = init
    .then(start(1, Change, true)).then(send(1)).then(arrive(1)).expect(phaseOf(1) == Ready)
    .then(loseClient(1, Set())).then(reconnect).expect(conns.get(1).serverAlive == false and phaseOf(1) == Ready)
    .then(begin(1)).expect(phaseOf(1) == Superseded)
    .then(send(1)).then(arrive(2)).expect(phaseOf(2) == Ready)
    .then(begin(2)).then(finish(2, false)).then(receive(2)).expect(calls.get(1).outcome == Replied and okSoFar)

  /// `original_running`: the original was running when the session resumed; the next connection's change is held until it finishes.
  run originalRunningTest = init
    .then(start(1, Change, false)).then(send(1)).then(arrive(1)).then(begin(1))
    .then(loseClient(1, Set())).expect(calls.get(1).outcome == Failed)
    .then(reconnect)
    .then(start(2, Change, false)).expect(calls.get(2).endedBefore.contains(1))
    .then(send(2)).then(arrive(2)).expect(phaseOf(2) == Held)
    .then(finish(1, false)).then(drain(2)).then(begin(2)).expect(phaseOf(1) == Finished and okSoFar)

  /// `cancelled`: a change given up on before it began is dropped unrun and answered so; the next change waits for that answer and then runs, with nothing to be held behind.
  run cancelledTest = init
    .then(start(1, Change, false)).then(send(1)).then(arrive(1))
    .then(giveUp(1, false)).expect(conns.get(1).cancels == 1 and reqs.get(1).cancelSent)
    .then(start(2, Change, false)).expect(not(canSend(2)))
    .then(seeCancel(1)).expect(phaseOf(1) == Cancelled and reqs.get(1).answer == Unrun)
    .expect(not(canSend(2)))
    .then(receive(1)).expect(conns.get(1).cancels == 0)
    .then(send(2)).then(arrive(2)).expect(phaseOf(2) == Ready)
    .then(begin(2)).then(finish(2, false)).then(receive(2)).expect(calls.get(2).outcome == Replied and okSoFar)

  /// `cancelled_running`: a change given up on while it ran is fenced; the next change is held behind it and begins only once it has finished.
  run cancelledRunningTest = init
    .then(start(1, Change, false)).then(send(1)).then(arrive(1)).then(begin(1))
    .then(giveUp(1, false)).then(seeCancel(1)).expect(phaseOf(1) == Abandoned and sessions.get(1).abandoned == 1)
    .then(receive(1)).expect(conns.get(1).cancels == 0)
    .then(start(2, Change, false)).then(send(2)).then(arrive(2)).expect(phaseOf(2) == Held)
    .expect(not(canDrain(2)))
    .then(finish(1, false)).expect(sessions.get(1).abandoned == 0 and reqs.get(1).answer == NoAnswer)
    .then(drain(2)).then(begin(2)).expect(phaseOf(1) == Finished and okSoFar)

  /// A takeover: the client reconnects while the server still holds the old connection; what the old one had not decoded goes with it, and the resend runs on the new one.
  run takeoverTest = init
    .then(start(1, Change, true)).then(send(1))
    .then(loseClient(1, Set())).then(reconnect).expect(phaseOf(1) == Dropped and seenTakeover)
    .then(send(1)).then(arrive(2)).then(begin(2)).then(finish(2, false)).then(receive(2)).expect(calls.get(1).outcome == Replied and okSoFar)

  /// A change held behind one given up on can be given up on too, at once, and never runs; a third change goes through once the first has finished.
  run heldGivenUpTest = init
    .then(start(1, Change, false)).then(send(1)).then(arrive(1)).then(begin(1))
    .then(giveUp(1, false)).then(seeCancel(1)).then(receive(1))
    .then(start(2, Change, false)).then(send(2)).then(arrive(2)).expect(phaseOf(2) == Held)
    .then(giveUp(2, false)).expect(conns.get(1).cancels == 1)
    .then(seeCancel(2)).expect(phaseOf(2) == Cancelled)
    .then(receive(2)).expect(conns.get(1).cancels == 0)
    .then(start(3, Change, false)).then(send(3)).then(arrive(3)).expect(phaseOf(3) == Held)
    .then(finish(1, false)).then(drain(3)).then(begin(3)).expect(okSoFar)

  /// An open given up on while it ran: its orphan release lands first and remembers the id, so the open is refused when it finishes and keeps nothing.
  run openGivenUpTest = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1)).expect(reqs.get(1).slot == Taken and pool == 1)
    .then(giveUp(1, false)).expect(client.orphansDue == Set(1))
    .then(seeCancel(1)).then(receive(1))
    .then(start(2, Release(1), true)).expect(client.orphansDue == Set() and not(calls.get(2).interruptible))
    .then(send(2)).then(arrive(2)).expect(phaseOf(2) == Ready)
    .then(begin(2)).then(finish(2, false)).expect(sessions.get(1).released == [1])
    .then(receive(2)).expect(calls.get(2).outcome == Replied)
    .then(finish(1, false)).expect(sessions.get(1).handles.get(1).by == 0 and pool == 0 and quiescent and okSoFar)

  /// The hovering race: a retried open keeps the entry's slot, the entry is released while the retry is open, and the retry is refused rather than kept under a released id.
  run hoveringTest = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1)).then(finish(1, false)).expect(sessions.get(1).handles.get(1).by == 1)
    .then(loseClient(1, Set())).then(loseServer(1)).then(reconnect)
    .then(send(1)).then(arrive(2)).then(begin(2)).expect(reqs.get(2).slot == Kept and pool == 1)
    .then(giveUp(1, false)).then(seeCancel(2)).then(receive(2))
    .then(start(2, Release(1), true)).then(send(2)).expect(reqOf(2) == 3)
    .then(arrive(3)).then(begin(3)).then(finish(3, false)).expect(sessions.get(1).handles.get(1).by == 0 and pool == 0)
    .then(receive(3))
    .then(finish(2, false)).expect(sessions.get(1).handles.get(1).by == 0 and pool == 0 and quiescent and okSoFar)

  /// G3: the original open was kept, its reply lost; the resend fails with an errno, the caller takes that as final, and the original's handle stays. S3 allows for it; S3 without the allowance does not.
  run g3Test = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1))
    .then(loseClient(1, Set())).then(loseServer(1)).then(reconnect)
    .then(send(1)).then(arrive(2)).then(finish(1, false)).expect(sessions.get(1).handles.get(1).by == 1)
    .then(drain(2)).then(begin(2)).expect(reqs.get(2).slot == Kept)
    .then(finish(2, true)).then(receive(2)).expect(calls.get(1).outcome == Errno and client.held.get(1) == 0)
    .expect(quiescent and S3 and not(S3plain) and not(S3noG3) and S3noG4 and okSoFar)

  /// G5: a release times out with its frame reset before the server read it whole; it is owed, and nothing sends it until the session next resumes, while the server holds the handle.
  run g5Test = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1)).then(finish(1, false)).then(receive(1)).expect(client.held.get(1) == 1)
    .then(start(2, Release(1), true)).expect(client.held.get(1) == 0)
    .then(send(2)).then(giveUp(2, true)).expect(phaseOf(2) == Dropped and client.owed == Set(1))
    .expect(quiescent and S3 and not(S3plain) and not(S3noG5) and okSoFar)
    .then(loseClient(1, Set())).then(loseServer(1)).then(reconnect).expect(conns.get(2).owedToSend == Set(1))
    .then(sendOwed(1)).then(arrive(3)).then(begin(3)).then(finish(3, false)).then(receive(3)).expect(client.owed == Set() and sessions.get(1).handles.get(1).by == 0 and quiescent and S3plain and okSoFar)

  /// A new session: the held handle is reopened under its id before the connection is published, and the client expects the server's entry from the reopen.
  run reopenTest = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1)).then(finish(1, false)).then(receive(1))
    .then(loseClient(1, Set())).then(loseServer(1)).then(dropSession(1)).then(newSession).expect(not(conns.get(2).published) and sid == 2)
    .then(start(2, Change, true)).expect(not(canSend(2)))
    .then(sendReopen(1)).expect(client.held.get(1) == 2)
    .then(arrive(2)).then(begin(2)).expect(reqs.get(2).slot == Taken and pool == 2)
    .then(finish(2, false)).then(receive(2)).expect(client.reopened == Set(1) and S3identity)
    .then(publish).expect(canSend(2))
    .then(send(2)).then(arrive(3)).then(begin(3)).then(finish(3, false)).then(receive(3))
    .then(closeSession(1)).expect(pool == 1 and quiescent and okSoFar)
}
