"""Write as a torrent client does into a multi-file torrent: 16 KiB blocks in random order at offsets that are not page-aligned within the file, from several threads, into a sparse file of fixed size.

    torrent.py FILE SECONDS [THREADS] [BLOCKS_PER_SECOND]

Under the client's writeback cache each such block costs the kernel a read of the partial pages it touches, so this exercises small reads and writes at once. BLOCKS_PER_SECOND, summed over the threads, throttles it to a light load; 0 or absent is as fast as it goes.
"""
import os
import random
import sys
import threading
import time

BLOCK = 16384
# Where a block starts within its 16 KiB slot: anything off a page boundary.
SHIFT = 1234
SIZE = 4 << 30

path = sys.argv[1]
seconds = float(sys.argv[2])
threads = int(sys.argv[3]) if len(sys.argv) > 3 else 8
rate = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0

fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
os.ftruncate(fd, SIZE)
data = os.urandom(BLOCK)
order = list(range(SIZE // BLOCK - 1))
random.shuffle(order)
blocks = iter(order)
lock = threading.Lock()
written = 0
start = time.monotonic()
end = start + seconds


def work():
    global written
    n = 0
    while time.monotonic() < end:
        with lock:
            # Every block written once; a long run stops when the file is full.
            block = next(blocks, None)
        if block is None:
            break
        os.pwrite(fd, data, block * BLOCK + SHIFT)
        n += 1
        if rate:
            time.sleep(threads / rate)
    with lock:
        written += n


workers = [threading.Thread(target=work) for _ in range(threads)]
for w in workers:
    w.start()
for w in workers:
    w.join()
elapsed = time.monotonic() - start
os.close(fd)
print(f"torrent: {written} blocks, {written / elapsed:.0f}/s")
