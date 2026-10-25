# The session protocol, as a Quint model

`session.qnt` is one client's session with the server as `docs/design.md`'s "Failure model" describes it, written in [Quint](https://quint.sh) so that its invariants are checked for every interleaving of a small instance rather than for the ones the disconnect grid stages. It is step 1 of the recommendation in `docs/research-verification.md`.

## What is modelled

The client's calls (`Caller::attempt`, `exchange`, the open and release paths), its connections by generation with `Attached::cancels`, its handle table with the releases owed, and its own traffic: reopens after a new session, orphan releases, owed releases. The server's sessions with their epochs and the counts `running`, `abandoned` and `running_older`, each request from decode through hold, begin and finish with the verdict on a cancel, and each session's `Handles` with the released ids it remembers and the shared pool. The faults: either end losing a connection, the client's give-up, resends, a resume, a takeover, a resume handshake lost after the server resumed, a session dropped with its old connection's requests going on, filesystem work failing with an errno, and the released-id window forgetting an id. Every action's comment names the code it stands for.

Several sessions exist in the model, since a dropped session is followed by a new one; the client holds one at a time. Left out, on purpose: S4 (writeback and durability, a separate model when wanted), liveness, reads and `fsync` (no invariant in scope mentions them; releases stand in for unordered requests), the handshake's internals beyond the lost-Ack case, other clients' sessions (G2), partial requests (G7, G8), G9, file contents, the pool running out, and the kernel releasing a handle a reopen killed (a no-op at the server).

The model is of the code as it is, known gaps included; nothing is switched off. Each invariant is therefore stated in `design.md`'s form, allowing for the known gaps, which must hold, and in a plain form, which must fail with a trace, so that each gap is pinned as well as the invariant is and nothing else hides behind it.

| Must hold | What it says |
|---|---|
| `S1` | No overtaking within one session: for changes a and b with b after a, every request of a that ran finished before any request of b began. A ghost flag set by `begin` whenever a request begins out of order, in either direction. |
| `S2` | A call's request runs at most twice, the second time only as a resend, and for a change on one session only after the first finished. |
| `S3` | At quiescence, the server's handles for the client's session are the client's live ones, apart from an id whose release is owed (G5) and an id released and then forgotten by the window before the open landed (G4). The allowances are per id, which is stronger than `design.md`'s "every owed release sent". |
| `S3identity` | Whatever the client holds under an id, the server's entry under that id was opened by the call the client accepted it from: an open's handle is never replaced by another file's. |
| `countsConsistent` | The attachment's three counts equal what the request phases say, through every resume and takeover. |
| `poolConsistent` | `HandlePool::used` equals the handles every session holds plus the slots of the opens under way that took one. |
| `aliveIsCurrent` | A connection the client still uses carries its session's current epoch (the model's own sanity). |

| Must fail | The gap its trace shows |
|---|---|
| `S1strong` | S1 across the client's sessions: G1, a dropped session's old connection running a change beside the new session's. |
| `S3noG4`, `S3noG5` | S3 with one allowance dropped at a time, so each gap is shown on its own. |

Reachability is checked the same way: for each state the model must be able to reach (a fenced change, a superseded one, a resend that ran, a takeover, an open refused under a released id, an orphan release that ran, and quiescence after a reopen, after an owed release, and while holding a handle on a later connection), its negation is an invariant TLC must find violated. A model that drifts into checking nothing fails those.

Two instances, one per file, because the checkers take a file's whole compiled form and Apalache refuses one past 20 MB:

- `session_tiny.qnt` (2 calls, 3 requests, 2 connections): what TLC explores completely. Every gap, every witness and every mutation is reachable in it; none needs more than three requests.
- `session_small.qnt` (3 calls, 6 requests, 3 connections): the simulator's instance, and the scenario runs: the disconnect grid's columns (`reply_lost`, `original_late`, `original_running`, `cancelled`, `cancelled_running`), the takeover, a change held behind one given up on, an open given up on and refused at `insert`, one refused at `reserve`, the hovering release race with the window remembering and with it forgotten, a new session's reopen succeeding and failing, a resent open answering from its original's handle, and G4 and G5 as traces.

## Running the checks

```
scripts/spec/check.sh          # typecheck, the scenario runs, and TLC finding every gap and witness: about five minutes, most of it the reopen witness's deep trace
FULL=1 scripts/spec/check.sh   # also TLC over the tiny instance's whole state space, and the simulation: about half an hour more
scripts/spec/mutations.sh      # each mutation below, caught by TLC: about a quarter of an hour, most of it the unordered opens' deep trace
```

They need Node and a JDK. The first run installs Quint 0.33.0 into `spec/node_modules` from the lockfile and downloads Apalache 0.62.1, which carries TLC, into `~/.quint`; the simulator fetches its own evaluator binary. TLC runs with an 8 GB heap and every core, and spills its state queue, tens of gigabytes for the full exploration, into `~/.cache/jackalopefs-spec/tmp` (`XDG_CACHE_HOME` respected), since a tmpfs `/tmp` cannot take it. Every outcome is asserted, and a gap that stops being reachable fails the script, which is the cue to move it out of `design.md`'s gap list and out of S3's allowances.

To look at a trace: `spec/node_modules/.bin/quint verify spec/session_tiny.qnt --backend=tlc --invariant=S1strong` prints the shortest one there is; `quint run spec/session_small.qnt --invariant=S3noG5 --max-steps=40 --mbt` prints the shortest the simulator finds, with the action taken at each step.

## What was learned building it

- **Apalache is not usable here, TLC is.** Apalache's bounded symbolic check of an earlier, smaller version of the model to depth 8 had not finished after 32 minutes, and the gaps' traces lie at depths of 14 to 20. TLC's explicit-state search explores `session_tiny` completely in about half an hour (275 million distinct states, a deepest trace of 33 steps) and finds the G1 trace in about 15 s. The 3-call instance is beyond it (over 100 million states found with the search far from done), so that instance gets the simulator and the scenario runs.
- **The simulator is a smoke test.** Random runs miss the fence mutation below in 60,000 traces and reach some witnesses once in 20,000. It stays in the full check for breadth on the larger instance, but nothing rests on it.
- **Order as ghost flags, not timestamps.** S1 and S2 are flags `begin` sets when a request begins out of order, with per-call sets of the calls that had ended; that keeps the state finite for TLC.
- **Mutations.** `scripts/spec/mutations.sh` breaks the model one way at a time and checks TLC on the tiny instance catches each: the fence without `abandoned` (S1); a change sent without waiting for `cancels == 0` (S1); a give-up that never counts the cancel (S1); a resume not zeroing `abandoned` (`countsConsistent`); a resume not moving `running` into `running_older` (S1); `begin` not refusing a stale epoch (S2); opens taken out of the ordering (S3: a resend that begins while its original still runs loses the race to insert and answers with an errno, while the original's handle stays); the released-id window not consulted at `insert` (S3, through the G4 allowance being for a forgotten id and not merely a released one); a resent open opening again instead of answering from the handle its original kept (S3: it fails where the original succeeded, and the original's descriptor stays). Making releases ordered trips nothing: a release held behind the fence and then given up on is owed and resent at the next resume, so what it breaks is L2, which is out of scope.
- **Gaps the model clarified.** G5 needs a release's frame never to reach the server: a give-up before it was written (the only reset `exchange` makes for a release, which finishes its send side right after writing). G4 needs an id released and then forgotten before its open lands; with the fence, a second open can only contribute its release by being given up on while held, or by having replied before the first was given up on.
