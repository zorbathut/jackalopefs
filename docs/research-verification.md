# Verifying jackalopefs: model checking and formal verification options

*Research notes, October 2026. They survey tools and say what each could check here. The failure model they refer to is the "Failure model" section of `design.md`. Of the recommendation at the end, step 1 is built: `spec/` holds the Quint model and `spec/README.md` what was learned building it; the rest is not.*

## What there is to check

The failure model states four invariants: at most once, no overtaking, no leaked descriptors, durability. They are kept by a protocol between client and server (epochs, the resume barrier, cancels answered `unrun` or `fenced`, the client's wait on pending cancels, owed and orphan releases), by a few small state machines in the code (`SessionState`'s counts, `Exchange`'s phase, `Handles` and its released ids, `retry_safe`), and by everything they run on: tokio, quinn, the kernel's FUSE and writeback behaviour, the server's filesystem.

Those are three different targets, and no single tool covers all of them:

1. **The design**: does the protocol keep the invariants under every interleaving of calls, connection losses, resumes, cancels and resends? This is where the bugs of the last few rounds were (overtaking originals, the release leak, the pool count), and it is the cheapest to check exhaustively, because it is small.
2. **The implementation against the design**: does the Rust code do what the model says? A correct model with a drifted implementation is worth little.
3. **The code itself**: the pure pieces (counters, slot accounting, the decoder's limits) proved correct for every input.

The disconnect grid covers part of 2 by hand: a dozen interleavings per request kind, chosen by us. It found real bugs, but it cannot find an interleaving nobody thought to stage, and it said nothing about the pool count bug the final review found by reading. Writing the model down already paid: stating the invariants precisely turned up a regression (an open from a superseded connection replacing a live handle, since fixed) and the gaps the model now lists (G1 to G9), none of which the grid stages.

## The tools

### Design-level model checkers

- **TLA+** (TLC, Apalache). The standard tool for distributed protocols, used at AWS, Azure and MongoDB. You write the protocol as a state machine over sets and functions, state the invariants, and the checker explores every reachable state for a bounded configuration (two connections, three calls, and so on); Apalache does it symbolically with SMT. It has no connection to Rust.
- **Quint** (Informal Systems). TLA's semantics with a typed, programmer's syntax and a simulator, checked with Apalache or TLC. It has a Rust bridge, `quint-connect`: the spec generates traces, and a Rust harness replays each against the real code and compares state at every step. That is model-based testing, which closes part of the gap to target 2. Informal used it on a consensus client and found a memory leak. ([quint-connect](https://docs.rs/quint-connect), [launch post](https://quint-lang.org/posts/quint_connect), [Emerald case study](https://quint-lang.org/posts/quint_connect_emerald))
- **P** (Microsoft, now AWS). Communicating state machines with a model checker and systematic testing; S3 used it for the protocols behind strong consistency. It has a C# heritage and no Rust integration. ([p-org/P](https://github.com/p-org/P))
- **Stateright**. A model checker written in Rust: the model is Rust code (an actor system or a plain state machine), checked exhaustively or by simulation, with a linearizability tester built in. Its actors can run on real UDP, but they use Stateright's own runtime, not tokio or quinn, so our code cannot run under it unchanged. Its pure-logic state machines could be checked directly. ([docs.rs](https://docs.rs/crate/stateright/latest))

### Implementation-level testing (not proof)

- **loom** (tokio's). Exhaustive exploration of thread interleavings and memory orderings for small concurrent code, run with loom's own sync types swapped in. Exact, but only for a handful of threads and operations, and not for async I/O.
- **shuttle** (AWS). Randomized scheduling, including the PCT algorithm with its probabilistic guarantee for bugs of small depth. It is not exhaustive, but it scales far past loom, and it has async support. It needs shuttle's primitives swapped in, as loom does. ([awslabs/shuttle](https://github.com/awslabs/shuttle))
- **Deterministic simulation testing** (FoundationDB's approach; TigerBeetle's VOPR). The whole system runs in one process under one seeded scheduler with simulated time and network, faults are injected from the seed, and every failure replays exactly.
  - **turmoil** is tokio's own simulator: hosts as futures in one thread, simulated TCP and UDP, partitions, holding and releasing messages between hosts, simulated time, and a simulated filesystem with a probability that a write is synced, for crash testing. ([docs.rs](https://docs.rs/turmoil/latest/turmoil/))
  - **madsim** goes further and intercepts libc's time and randomness. ([madsim-rs/madsim](https://github.com/madsim-rs/madsim))
  - S2 and RisingWave use these in production. ([S2](https://s2.dev/blog/dst), [RisingWave](https://risingwave.com/blog/deterministic-simulation-a-new-era-of-distributed-system-testing/))

### Code-level verification

- **Kani** (AWS). A bounded model checker for Rust, built on CBMC: it proves the absence of panics, overflow and undefined behaviour, plus user assertions, for every input up to a bound. Function and loop contracts extend that to unbounded proofs, and it is used on the Rust standard library verification effort. It is good on pure functions and unsafe code, and weak on concurrency and async. ([paper](https://cdn.amazon.science/05/be/d3a0c9c241e1b6ffbf5b2e6eddb4/scipub-approval152129-47347564-kani-a-model-checker-for-rust.pdf))
- **Verus** (Microsoft Research, CMU, VMware and others). SMT-based deductive verification of Rust: specs, proofs and ghost state written next to the code in a `verus!` macro, with linear ghost types for concurrency. It is the most capable option for systems code today, with industrial use at Microsoft and Amazon.
  - Verified systems built with it include IronKV (a distributed key-value store), a memory allocator, Atmosphere (an OS kernel) and Anvil.
  - **Anvil** verifies liveness of Kubernetes controllers by embedding TLA in Verus, so the protocol's temporal properties and the Rust code's Hoare-style proofs live in one tool (OSDI 2024 best paper). That is the closest precedent for "a protocol of actors over an unreliable network, verified down to the Rust code". ([Anvil](https://www.usenix.org/conference/osdi24/presentation/sun-xudong), [Verus projects](https://verus-lang.github.io/verus/publications-and-projects/))
  - Its limits: verified code is written in Verus's subset, with no `async`, and the standard library is specified piecemeal, so tokio, quinn and syscalls stay trusted, modelled by hand-written specs.
  - Its soundness for a significant subset was itself mechanized in Iris/Rocq at PLDI 2026 (VerusBelt). ([PLDI 2026](https://pldi26.sigplan.org/details/pldi-2026-papers/82/VerusBelt-A-Semantic-Foundation-for-Verus-s-Proof-Oriented-Extensions-to-the-Rust-Ty))
- **Aeneas** (Inria, Microsoft). Translates safe Rust into a pure functional model in Lean, where proofs are written, increasingly with AI agents writing them and Lean's kernel checking them. SymCrypt uses it for production Rust cryptography (ML-KEM, SHA-3). It suits sequential, algorithmic code, not concurrent protocol code. ([Microsoft Research](https://www.microsoft.com/en-us/research/blog/verifying-rust-cryptography-in-symcrypt-from-standards-to-code/), [arXiv](https://arxiv.org/pdf/2609.15648))
- **Creusot** (Inria). Deductive verification of safe Rust through Why3, with prophecies for mutable borrows. It is mature on sequential safe Rust, but has no concurrency story to speak of. ([Creusot](https://hal-cnrs.archives-ouvertes.fr/LMF/hal-03526634v1))

### Verified filesystems, for scale

- **FSCQ and DFSCQ** (Coq; crash safety by Crash Hoare Logic) and **Yggdrasil** (push-button with Z3).
- **VeriBetrFS** (Dafny).
- **BilbyFS** (Cogent).
- **DaisyNFS** (MIT PDOS, OSDI 2022), the closest relative of this project. It is a verified crash-safe, concurrent NFS server in Go:
  - each operation is made atomic by a verified transaction layer (GoTxn, proved in Coq with Perennial and Iris), and the operations themselves are verified sequentially in Dafny;
  - the proof is about twice the size of the code;
  - it delivers at least 60% of the throughput of Linux's NFS server on ext4.

  Two of its lessons carry over. The design was shaped so that it could be proved: transactions make every operation atomic, so the spec is a sequential filesystem. And the verification boundary was the server and its disk, not the clients or the network. ([paper](https://pdos.csail.mit.edu/papers/daisy-nfs:osdi22.pdf), [code](https://github.com/mit-pdos/daisy-nfsd))

### bcachefs

Kent Overstreet's project has been doing Verus proofs since early 2026. Its collaborator's site reports 277 properties across three modules (`bpos` ordering, snapshot tree invariants, the eytzinger search tree layout), "zero assumptions", with the stated goal of a fully verified general-purpose filesystem. These are self-reported by a site the bcachefs project runs, and I found no independent confirmation. The modules chosen are pure data structures, which is where Verus is strongest. ([poc.bcachefs.org](https://poc.bcachefs.org/), [The Tree You Can't See](https://poc.bcachefs.org/blog/implicit-trees.html))

## What full verification would mean here, and how far the tools reach

A full proof would show that client, network and server together refine a specification: a POSIX-like filesystem, as seen by processes on the client, with the failure model's outcomes. Its trusted base would still include the Linux FUSE and writeback behaviour, the server's filesystem, quinn's delivery guarantees and tokio's scheduling, each as a hand-written spec. Nothing verifies those today.

Within that base, the realistic ceiling in 2026 is:
- the protocol verified as a model, for every interleaving at bounded size;
- its core state machines verified in Verus for every input and interleaving;
- the implementation tied to the model by model-based testing and deterministic simulation rather than by proof.

That is roughly how Anvil and DaisyNFS draw their lines, the async networking layer being where the proofs stop. Proving the async client and server code itself would mean rewriting them in Verus's subset around a hand-specified quinn and tokio, a research project with no precedent at this size.

## Recommendation

In order, each step useful on its own:

1. **A Quint spec of the session protocol** (days). The spec has these parts:
   - **Actors:** client calls, connections with epochs, server requests with their phases, the client's pending-cancel counts, handles and released ids.
   - **Faults:** connection loss, resume, takeover, give-up, resend.
   - **Invariants:** the failure model's, stated as Quint predicates.

   Apalache checks it for small bounds. This turns `design.md`'s prose into something checkable, finds interleaving bugs before code, and makes every future change answer to the spec. Quint over raw TLA+ for its syntax and for the Rust bridge in step 3; TLA+ is the fallback if Quint's tooling disappoints.
2. **A deterministic simulation harness** (one to two weeks). It runs client and server in one process under turmoil:
   - **quinn on turmoil's UDP:** quinn takes a custom `AsyncUdpSocket` and `Runtime`, so it can run over turmoil's UDP sockets, under its simulated time.
   - **Filesystem work inline:** the server's filesystem work runs inline instead of on the blocking pool, behind a seam, so it stays deterministic. FUSE stays out; the harness drives `Client` as the grid does.
   - **Faults from the seed:** partitions, held messages, give-ups and server restarts.
   - **Checking:** each run is checked against the invariants (the grid's control-comparison oracle generalizes to this).

   This replaces hand-staged interleavings with millions of seeded ones, and it is the step most likely to find the next real bug.
3. **`quint-connect` on top of the harness.** Traces from the spec drive the real code in the simulator, checking it against the model step by step. This is the link from target 1 to target 2.
4. **Proofs where they are cheap and pay** (ongoing):
   - **Kani:** harnesses for the decoder's limits (no panic, bounded allocation on any frame) and for `retry_safe` and `changes` against a stated spec.
   - **Verus, if the appetite is there:** the pure state machines: `SessionState`'s fence counts, `Exchange`'s phases, `Handles` slot accounting with `Released`. These are small, have exactly the bugs found by review, and are where bcachefs is using Verus too.

   Proving the async code itself is not worth attempting yet.

Steps 1 and 2 are where most of the value is; 3 and 4 tighten the joints.
