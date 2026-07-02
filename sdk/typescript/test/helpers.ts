/** A pushable async iterable of Buffers — an in-memory stand-in for a byte stream. */
export function pushableStream(): {
  iterable: AsyncIterable<Buffer>;
  push: (b: Buffer) => void;
  close: () => void;
} {
  const queue: Buffer[] = [];
  let resolveNext: (() => void) | null = null;
  let done = false;

  const wake = (): void => {
    if (resolveNext) {
      const r = resolveNext;
      resolveNext = null;
      r();
    }
  };

  const iterable: AsyncIterable<Buffer> = {
    async *[Symbol.asyncIterator]() {
      while (true) {
        while (queue.length > 0) {
          yield queue.shift() as Buffer;
        }
        if (done) return;
        await new Promise<void>((resolve) => {
          resolveNext = resolve;
        });
      }
    },
  };

  return {
    iterable,
    push: (b: Buffer): void => {
      queue.push(b);
      wake();
    },
    close: (): void => {
      done = true;
      wake();
    },
  };
}
