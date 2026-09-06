# jackalopefs

Jackalope FS is a client/server network filesystem mount for Linux. It's designed to solve a lot of problems that the author had with existing solutions, specifically including NFS, Samba/CIFS, sshfs, and rclone.

Jackalope FS has been used by exactly one person in exactly one situation. You should probably not be using it in production-critical environments. But if you want to test it, I'd love to keep improving it for, you know, other people.

## That sounds amazing! I am suffering from temporary insanity and don't care about anything else, tell me how to use it.

- Linux 5.6 or later on the server (`openat2`).
- On the client: `/dev/fuse` and `fusermount3` (package `fuse3`). Mounting as a user needs no special configuration; `--allow-other` additionally needs `user_allow_other` in `/etc/fuse.conf`.
- Rust 1.88 or later and the Cap'n Proto compiler (`capnp` 1.0 or later; package `capnproto` on Arch and Debian) to build.

Server:

```
jackalopefs-server --export /srv/share --listen 0.0.0.0:1933 [--token SECRET]
```

On first start it generates a certificate under `$XDG_STATE_HOME/jackalopefs` (or `~/.local/state/jackalopefs`) and logs its fingerprint. The default listen address is loopback, port 1933; anything else without `--token` lets every host that can reach the port read and write the export as the server user. On your own head be it.

Client:

```
jackalopefs-client server[:port] /mnt/share --fingerprint sha256:… [--token SECRET]
```

The server is a host name or an IP address, with or without a port (an IPv6 address with a port in brackets, `[::1]:1933`); the port defaults to 1933. `--fingerprint` pins the server certificate; `--insecure` skips that check (the connection is still encrypted). Other options: `--op-timeout 30s`, `--connect-timeout 10s`, `--entry-timeout 1s`, `--attr-timeout 1s`, `--allow-other`, `--auto-unmount`, `--default-permissions`. The client runs in the foreground and unmounts on `SIGINT`/`SIGTERM`.

`--default-permissions` has the kernel enforce mode bits against the attributes the server reports before it forwards a request. The server only ever checks its own access, so a mount shared through `--allow-other` enforces nothing without it. It costs extra attribute fetches, bounded by `--attr-timeout`, and a `chmod` made on the server side is honoured only after that timeout or the change event. The client warns at startup when `--allow-other` is given without it.

Set `RUST_LOG=debug` (or `trace`) on either side for more detail.

## Wow! That sounds amazing and with absolutely no qualifiers or concerns. Wait, hold on. Don't other solutions exist? Why shouldn't you use them? Claude, write a convicting explanation for why someone should use this crazy thing, make no mistakes.

All the other solutions do exist and I'm gonna be honest, you should probably use them. But here's why I don't like them.

### NFS

NFS comes with the baked-in assumption that all computers are managed by a central authority and have the same user IDs. This makes it very painful to use in any scenario where you don't want that level of central management. NFS handles server failure *very badly*, to the point of near-bricking entire client computers if the connection has issues. It's based on an obsolete Internet protocol (TCP, yep I said it) and essentially impossible to do major improvements on due to its position in the Linux kernel.

I don't want to understate the importance of NFS. NFS is really good. I'm glad we had NFS, and the developers put far more work into it than I did to this, over a far longer amount of time. But it's also old and calcified, and, like TCP, we can do better.

### SAMBA/CIFS

Samba is a reimplementation of Microsoft's SMB/CIFS protocol, originally intended to share files between Windows computers. The consequences of this is that it's fundamentally driven *by Microsoft*; Samba developers can't practically improve the protocol on their own, they are always subject to whatever Microsoft chooses to do. On Linux, it shares the same client stability issues that NFS has.

### sshfs

sshfs is a pretty clever solution - I can't imagine an easier way to implement a filesystem without doing it yourself. Unfortunately, it's fundamentally hamstrung by the requirements of the protocol. There's terrible support for parallel streams, encryption is mandatory by definition, and it requires an SSH login on the server to function. Also, TCP, again. sshfs is *considerably better* at dealing with server failure, but this is compensated for with serious performance problems; quite simply, ssh isn't designed to work as a filesystem exposure layer, and while sshfs does a heroic job of managing it anyway, there's a limit, guys.

### rclone

rclone provides a whole bunch of various mount solutions and the only one I've used is the ssh one. My tl;dr is "another sshfs, but better at some stuff and worse at others".

### Jackalope

Jackalope uses QUIC for better handling of contention and far more transparent parallel transfers. It's designed from the ground up to support its own login semantics (right now it *just* mounts as the user - don't run as root unless you really mean it! - but future versions may add more). It is intended for the server to vanish at any moment without serious stability problems (obviously your file transfers will fail, deal with it). It can in the future support encryptionless connections. It supports *multiple* giant chunky POSIX test suites and 100%'s them aside from the parts that aren't relevant (mostly around stuff like `chown` which is currently not supported at all due to the whole single-user thing.)

There's a lot of "it could, someday" here, and that's intended. I'm not claiming this is the best solution for everyone. I'm claiming that *with enough work, this could, theoretically, be the best solution for everyone*. But it isn't yet.

It probably won't ever be. But that's OK. Maybe it's a better solution for you.

# Okay let's get back to the tech stuff I guess

Be aware that this was mostly Claude-coded. I've been thinking about this general thing for like two years, and then one day Anthropic handed me a quota reset and I realized I had like 24 hours to burn 80% of a 20x Max Fable quota and said, fuck it, let's do this, so ~~I~~ Claude did this. I haven't reviewed it in more than the most cursory detail. YMMV. But there's some stuff Claude wrote about how it works.

## When the server goes away

- A filesystem call blocked on the server fails with `ETIMEDOUT` after `--op-timeout`; a call that was in flight when the connection dropped fails with `EIO` unless it is safe to retry, in which case it is retried once on the next connection.
- The client reconnects with exponential backoff for as long as it is mounted. If the server kept the session (up to 60 s), open files continue exactly where they were; otherwise each open file is reopened by path and verified to be the same inode, and a handle whose file changed underneath it fails with `ESTALE`.
- A server and client built from different protocol revisions refuse each other before any authentication, and both log the two revisions (`jackalopefs-client` exits with them when it is the first connection). While mounted, the client keeps retrying so that a server rollback recovers the mount, but calls fail with `ETIMEDOUT` until one side is rebuilt or the mount is given up as below.
- To give up on a mount: `fusermount3 -uz /mnt/share` detaches the mount point, and killing `jackalopefs-client` fails every pending and future call with `ENOTCONN` immediately. Nothing needs root and nothing can wedge in uninterruptible sleep beyond the operation deadline.

## Semantics

Single client: hardlinks share `st_ino`, `st_ino` is stable, unlink-while-open works, `O_APPEND` appends atomically, `readdir` uses real directory cookies, POSIX and BSD locks are handled by the local kernel. Writes go through immediately (no writeback cache), so a reconnect never loses data, at the cost of one round trip per `write(2)`.

Several clients: each sees the others' changes through server push plus the cache TTL; locks are not shared. See `docs/design.md` for the full list of limitations.

## Building and testing

```
cargo build --release
cargo test --workspace
```

The test suite runs real servers on loopback and, where `/dev/fuse` and `fusermount3` are available, real FUSE mounts; the mount tests skip themselves otherwise.

`scripts/validate/all.sh` runs the external validation suites (pjdfstest, fsx, fsstress, fio) plus resilience and cache-coherence checks of our own against a fresh server and mount; `docs/validation.md` describes them, their prerequisites, and what the results mean.

# Alright shut up claude get me back to the human

## Why Jackalope?

Would you believe I came up with the name along with a big complicated clever explanation for why it was a good name, wrote the name down, and forgot to write down the rationale?

Somehow this feels appropriate.

## Versioning

At the moment, Jackalope requires exact client/server version lockstep. This should be fixed someday. That day is not today.

## License

MIT.
