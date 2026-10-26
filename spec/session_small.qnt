// The instance the simulator runs on, and the scenario runs: the disconnect grid's columns and the focused tests as traces (`quint test`). One instance per file: see README.md.
module session_small {
  import session(N = 3, R = 6, MAX_GEN = 3).* from "./session"

  /// `Fault::ReplyLost`: the original ran, its reply went with the connection, and the resend on the next connection waits behind it and then runs once.
  run replyLostTest = init
    .then(start(1, Change, true)).then(send(1)).then(arrive(1)).then(begin(1))
    .then(loseClient(1, Set())).expect(calls.get(1).status == Waiting and calls.get(1).lostOnce and calls.get(1).minGen == 2)
    .then(loseServer(1)).then(reconnect).expect(sessions.get(1).runningOlder == 1)
    .then(send(1)).expect(reqOf(1) == 2).then(arrive(2)).expect(phaseOf(2) == Held)
    .expect(not(canDrain(2)))
    .then(finish(1, false)).expect(sessions.get(1).runningOlder == 0 and reqs.get(1).answer == Lost)
    .then(drain(2)).then(begin(2)).expect(phaseOf(1) == Finished and okSoFar)
    .then(finish(2, false)).then(receive(2)).expect(calls.get(1).outcome == Replied and okSoFar)

  /// `Fault::OriginalLate`: the original had not begun when its connection was lost and the session resumed elsewhere; it is refused by the epoch check, and the call's resend runs alone.
  run originalLateTest = init
    .then(start(1, Change, true)).then(send(1)).then(arrive(1)).expect(phaseOf(1) == Ready)
    .then(loseClient(1, Set())).then(reconnect).expect(conns.get(1).serverAlive == false and phaseOf(1) == Ready and seenTakeover)
    .then(begin(1)).expect(phaseOf(1) == Superseded)
    .then(send(1)).then(arrive(2)).expect(phaseOf(2) == Ready)
    .then(begin(2)).then(finish(2, false)).then(receive(2)).expect(calls.get(1).outcome == Replied and okSoFar)

  /// `Fault::OriginalRunning`: the original was running when the session resumed; the next connection's change is held until it finishes.
  run originalRunningTest = init
    .then(start(1, Change, false)).then(send(1)).then(arrive(1)).then(begin(1))
    .then(loseClient(1, Set())).expect(calls.get(1).outcome == Failed)
    .then(reconnect)
    .then(start(2, Change, false)).expect(calls.get(2).endedBefore.contains(1))
    .then(send(2)).then(arrive(2)).expect(phaseOf(2) == Held)
    .then(finish(1, false)).then(drain(2)).then(begin(2)).expect(phaseOf(1) == Finished and okSoFar)

  /// `Fault::Cancelled`: a change given up on before it began is dropped unrun and answered so; the next change waits for that answer and then runs, with nothing to be held behind.
  run cancelledTest = init
    .then(start(1, Change, false)).then(send(1)).then(arrive(1))
    .then(giveUp(1)).expect(conns.get(1).cancels == 1 and reqs.get(1).cancelSent)
    .then(start(2, Change, false)).expect(not(canSend(2)))
    .then(seeCancel(1)).expect(phaseOf(1) == Cancelled and reqs.get(1).answer == Unrun)
    .expect(not(canSend(2)))
    .then(receive(1)).expect(conns.get(1).cancels == 0)
    .then(send(2)).then(arrive(2)).expect(phaseOf(2) == Ready)
    .then(begin(2)).then(finish(2, false)).then(receive(2)).expect(calls.get(2).outcome == Replied and okSoFar)

  /// `Fault::CancelledRunning`: a change given up on while it ran is fenced; the next change is held behind it and begins only once it has finished.
  run cancelledRunningTest = init
    .then(start(1, Change, false)).then(send(1)).then(arrive(1)).then(begin(1))
    .then(giveUp(1)).then(seeCancel(1)).expect(phaseOf(1) == Abandoned and sessions.get(1).abandoned == 1)
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
    .then(giveUp(1)).then(seeCancel(1)).then(receive(1))
    .then(start(2, Change, false)).then(send(2)).then(arrive(2)).expect(phaseOf(2) == Held)
    .then(giveUp(2)).expect(conns.get(1).cancels == 1)
    .then(seeCancel(2)).expect(phaseOf(2) == Cancelled)
    .then(receive(2)).expect(conns.get(1).cancels == 0)
    .then(start(3, Change, false)).then(send(3)).then(arrive(3)).expect(phaseOf(3) == Held)
    .then(finish(1, false)).then(drain(3)).then(begin(3)).expect(okSoFar)

  /// The hovering race: a retried open finds the original's entry and is given up on while it runs; its orphan release waits behind it, then closes the original's handle.
  run hoveringTest = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1)).then(finish(1, false)).expect(sessions.get(1).handles.get(1).by == 1)
    .then(loseClient(1, Set())).then(loseServer(1)).then(reconnect)
    .then(send(1)).then(arrive(2)).then(begin(2)).expect(reqs.get(2).slot == Kept and pool == 1)
    .then(giveUp(1)).then(seeCancel(2)).then(receive(2))
    .then(orphanSend(1)).expect(reqs.get(3).origin == OrphanRelease(1))
    .then(arrive(3)).expect(phaseOf(3) == Held)
    .then(finish(2, false)).then(drain(3)).then(begin(3)).then(finish(3, false)).then(receive(3))
    .expect(sessions.get(1).handles.get(1).by == 0 and pool == 0 and quiescent and okSoFar)

  /// An open given up on while it ran: its orphan release waits for the cancel's answer, then behind the open, which keeps its handle until the release closes it.
  run openGivenUpTest = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1)).expect(reqs.get(1).slot == Taken and pool == 1)
    .then(giveUp(1)).expect(client.orphansDue == Set(1) and conns.get(1).cancels == 1)
    .expect(not(orphanSendable(1)))
    .then(seeCancel(1)).then(receive(1)).expect(phaseOf(1) == Abandoned and conns.get(1).cancels == 0)
    .then(orphanSend(1)).expect(client.orphansDue == Set() and reqs.get(2).origin == OrphanRelease(1))
    .then(arrive(2)).expect(phaseOf(2) == Held and seenReleaseHeld)
    .then(finish(1, false)).expect(sessions.get(1).handles.get(1).by == 1 and pool == 1)
    .then(drain(2)).then(begin(2)).then(finish(2, false)).then(receive(2))
    .expect(sessions.get(1).handles.get(1).by == 0 and pool == 0 and quiescent and okSoFar)

  /// An open given up on before it began: the server drops it unrun, and only then does its orphan release go out, closing nothing.
  run openUnrunTest = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).expect(phaseOf(1) == Ready)
    .then(giveUp(1)).then(seeCancel(1)).expect(phaseOf(1) == Cancelled)
    .then(receive(1)).then(orphanSend(1)).then(arrive(2)).then(begin(2)).then(finish(2, false)).then(receive(2))
    .expect(pool == 0 and quiescent and okSoFar)

  /// The orphan release times out while it waits behind the open: its cancel is counted and it is owed; the owed release goes once the cancel's answer is in, and waits behind the open in turn.
  run orphanOwedTest = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1))
    .then(giveUp(1)).then(seeCancel(1)).then(receive(1))
    .then(orphanSend(1)).then(arrive(2)).then(orphanSentGiveUp(2)).expect(client.owed == Set(1) and conns.get(1).cancels == 1)
    .then(seeCancel(2)).expect(phaseOf(2) == Cancelled)
    .then(receive(2)).expect(conns.get(1).cancels == 0)
    .then(owedSend(1)).then(arrive(3)).expect(phaseOf(3) == Held)
    .then(finish(1, false)).then(drain(3)).then(begin(3)).then(finish(3, false)).then(receive(3))
    .expect(client.owed == Set() and sessions.get(1).handles.get(1).by == 0 and quiescent and okSoFar)

  /// The original open was kept and its reply lost; the resend finds the original's handle under the id and answers from it, opening nothing (it cannot fail with an errno as opening again could), and the client holds what the server holds.
  run resentOpenTest = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1))
    .then(loseClient(1, Set())).then(loseServer(1)).then(reconnect)
    .then(send(1)).then(arrive(2)).then(finish(1, false)).expect(sessions.get(1).handles.get(1).by == 1)
    .then(drain(2)).then(begin(2)).expect(reqs.get(2).slot == Kept and pool == 1)
    .then(finish(2, false)).then(receive(2)).expect(calls.get(1).outcome == Replied and client.held.get(1) == 2 and sessions.get(1).handles.get(1).by == 1)
    .expect(quiescent and S3 and okSoFar)

  /// A release given up on before its frame was written is owed and sent on the connection it was given up on, with no resume; until then nothing is quiescent.
  run owedLiveTest = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1)).then(finish(1, false)).then(receive(1)).expect(client.held.get(1) == 1)
    .then(start(2, Release(1), true)).expect(client.held.get(1) == 0)
    .then(giveUp(2)).expect(client.owed == Set(1) and calls.get(2).outcome == GaveUp and not(quiescent))
    .then(owedSend(1)).expect(reqs.get(2).conn == 1)
    .then(arrive(2)).then(begin(2)).then(finish(2, false)).then(receive(2)).expect(client.owed == Set() and sessions.get(1).handles.get(1).by == 0 and quiescent and S3 and okSoFar)

  /// An owed release whose connection is lost before the answer stays owed and goes out again on the resumed connection.
  run owedAgainTest = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1)).then(finish(1, false)).then(receive(1))
    .then(start(2, Release(1), true)).then(giveUp(2)).then(owedSend(1)).expect(reqs.get(2).origin == OwedRelease(1))
    .then(loseClient(1, Set())).then(loseServer(1)).expect(phaseOf(2) == Dropped and client.owed == Set(1))
    .then(reconnect).then(owedSend(1)).expect(reqs.get(3).conn == 2)
    .then(arrive(3)).then(begin(3)).then(finish(3, false)).then(receive(3)).expect(client.owed == Set() and quiescent and S3 and okSoFar)

  /// A session dropped twice while a change given up on by losing its connection still runs is resumed both times, and the client's next change waits for that one: S1 across sessions.
  run droppedResumedTest = init
    .then(start(1, Change, false)).then(send(1)).then(arrive(1)).then(begin(1))
    .then(loseClient(1, Set())).expect(calls.get(1).outcome == Failed)
    .then(loseServer(1)).then(dropSession(1)).expect(not(sessions.get(1).live) and resumable(1))
    .then(reconnect).expect(sid == 1 and sessions.get(1).live)
    .then(loseClient(2, Set())).then(loseServer(2)).then(dropSession(1))
    .then(reconnect).expect(sid == 1 and gen == 3 and sessions.get(1).runningOlder == 1)
    .then(start(2, Change, true)).then(send(2)).then(arrive(2)).expect(phaseOf(2) == Held and not(canDrain(2)))
    .then(finish(1, false)).then(drain(2)).then(begin(2)).then(finish(2, false)).then(receive(2))
    .expect(calls.get(2).outcome == Replied and quiescent and S1strong and okSoFar)

  /// A new session: the held handle is reopened under its id before the connection is published, the client expects the server's entry from the reopen, and the old session's handle goes back to the pool when it closes.
  run reopenTest = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1)).then(finish(1, false)).then(receive(1))
    .then(loseClient(1, Set())).then(loseServer(1)).then(dropSession(1)).then(newSession).expect(not(conns.get(2).published) and sid == 2)
    .then(start(2, Change, true)).expect(not(canSend(2)))
    .then(reopenSend(1)).expect(client.held.get(1) == 2)
    .then(arrive(2)).then(begin(2)).expect(reqs.get(2).slot == Taken and pool == 2)
    .then(finish(2, false)).then(receive(2)).expect(client.reopened == Set(1) and S3identity)
    .then(publish).expect(canSend(2) and client.owed == Set())
    .then(send(2)).then(arrive(3)).then(begin(3)).then(finish(3, false)).then(receive(3))
    .then(closeSession(1)).expect(pool == 1 and quiescent and okSoFar)

  /// A new session whose reopen fails: the handle is dead, and its release goes out once the connection is published.
  run reopenKilledTest = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1)).then(finish(1, false)).then(receive(1))
    .then(loseClient(1, Set())).then(loseServer(1)).then(dropSession(1)).then(newSession)
    .then(reopenSend(1)).then(arrive(2)).then(begin(2)).then(finish(2, true)).expect(reqs.get(2).answer == ErrnoReply and pool == 1)
    .then(receive(2)).expect(client.held.get(1) == 0 and client.dead == Set(1) and client.owed == Set(1))
    .then(publish).expect(client.owed == Set(1))
    .then(owedSend(1)).then(arrive(3)).then(begin(3)).then(finish(3, false)).then(receive(3)).expect(client.owed == Set())
    .then(closeSession(1)).expect(pool == 0 and quiescent and okSoFar)

  /// A new session whose reopen is given up on while the server runs it: the connection is published at once, the reopen running on; its cancel is counted, so the release of the dead handle goes out once the server has answered it, and is held behind the reopen until that has kept its handle.
  run reopenGivenUpTest = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1)).then(finish(1, false)).then(receive(1))
    .then(loseClient(1, Set())).then(loseServer(1)).then(dropSession(1)).then(newSession)
    .then(reopenSend(1)).then(arrive(2)).then(begin(2)).then(reopenGiveUp(2)).expect(client.dead == Set(1) and client.owed == Set(1) and conns.get(2).cancels == 1)
    .then(publish).expect(conns.get(2).published and phaseOf(2) == Running and not(owedSendable(1)))
    .then(seeCancel(2)).then(receive(2)).expect(phaseOf(2) == Abandoned and conns.get(2).cancels == 0)
    .then(owedSend(1)).then(arrive(3)).expect(phaseOf(3) == Held)
    .then(finish(2, false)).expect(sessions.get(2).handles.get(1).by == 2)
    .then(drain(3)).then(begin(3)).then(finish(3, false)).then(receive(3)).then(closeSession(1))
    .expect(sessions.get(2).handles.get(1).by == 0 and pool == 0 and quiescent and okSoFar)

  /// A new session whose reopen is still out when the kernel releases the handle: the connection is not published until the reopen has answered, and the handle it keeps is then released as stale.
  run reopenReleasedTest = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1)).then(finish(1, false)).then(receive(1))
    .then(loseClient(1, Set())).then(loseServer(1)).then(dropSession(1)).then(newSession)
    .then(reopenSend(1)).then(start(2, Release(1), true)).expect(client.held.get(1) == 0 and client.reopening == Set(2))
    .then(arrive(2)).then(begin(2)).then(finish(2, false)).expect(sessions.get(2).handles.get(1).by == 2)
    .then(receive(2)).expect(client.owed == Set(1) and client.reopening == Set())
    .then(publish).then(owedSend(1)).then(arrive(3)).then(begin(3)).then(finish(3, false)).then(receive(3))
    .then(send(2)).then(arrive(4)).then(begin(4)).then(finish(4, false)).then(receive(4)).then(closeSession(1))
    .expect(sessions.get(2).handles.get(1).by == 0 and pool == 0 and quiescent and okSoFar)
}
