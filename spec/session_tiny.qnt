// The instance TLC explores completely; one instance per file, since the checkers take the whole file's compiled form and Apalache refuses one past 20 MB.
/// Small enough for TLC to explore completely: two calls, two connections.
module session_tiny {
  import session(N = 2, R = 4, MAX_GEN = 2, RELEASED_KEPT = 1).* from "./session"
}
