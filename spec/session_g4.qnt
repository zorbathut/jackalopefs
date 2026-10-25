// The instance that reaches G4; one instance per file, since the checkers take the whole file's compiled form and Apalache refuses one past 20 MB.
/// Room for G4 on one connection, which needs two ids released: a second open replied before the first is given up on (the fence holds every later change behind an abandoned one), the first's orphan release, the second's release evicting that id from the window, and then the first open landing.
module session_g4 {
  import session(N = 4, R = 4, MAX_GEN = 1, RELEASED_KEPT = 1).* from "./session"

  run g4Test = init
    .then(start(1, Open, true)).then(send(1)).then(arrive(1)).then(begin(1))
    .then(start(3, Open, true)).then(send(3)).expect(reqOf(3) == 2).then(arrive(2)).then(begin(2)).then(finish(2, false)).then(receive(2)).expect(client.held.get(3) == 2)
    .then(giveUp(1, false)).then(seeCancel(1)).then(receive(1)).expect(phaseOf(1) == Abandoned)
    .then(start(2, Release(1), true)).then(send(2)).expect(reqOf(2) == 3).then(arrive(3)).then(begin(3)).then(finish(3, false)).then(receive(3)).expect(sessions.get(1).released == [1])
    .then(start(4, Release(3), true)).then(send(4)).expect(reqOf(4) == 4).then(arrive(4)).then(begin(4)).then(finish(4, false)).then(receive(4)).expect(sessions.get(1).released == [3])
    .then(finish(1, false)).expect(sessions.get(1).handles.get(1).by == 1 and sessions.get(1).handles.get(1).releasedBefore and quiescent and S3 and not(S3noG4) and not(S3plain) and S3noG3 and okSoFar)
}
