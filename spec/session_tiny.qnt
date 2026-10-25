// The instance TLC explores completely: two calls, three requests, two connections. Every gap, witness and mutation needs at most three requests. One instance per file: see README.md.
module session_tiny {
  import session(N = 2, R = 3, MAX_GEN = 2).* from "./session"
}
