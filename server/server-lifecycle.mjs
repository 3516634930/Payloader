const closeWithCallback = server => new Promise((resolveClose, rejectClose) => {
  server.close(error => error ? rejectClose(error) : resolveClose());
});

export const closeHttpServer = async (server, options = {}) => {
  if (!server?.listening) return;
  const timeoutMs = Number(options.timeoutMs || 10_000);
  let timer;
  try {
    await Promise.race([
      closeWithCallback(server),
      new Promise((_, rejectTimeout) => {
        timer = setTimeout(() => rejectTimeout(new Error('HTTP server shutdown timed out.')), timeoutMs);
        timer.unref?.();
      }),
    ]);
  } catch (error) {
    server.closeAllConnections?.();
    if (server.listening) throw error;
  } finally {
    clearTimeout(timer);
  }
};

export const createShutdownController = ({ server, closeResources, timeoutMs = 10_000 }) => {
  let shutdownPromise;
  const shutdown = reason => {
    if (shutdownPromise) return shutdownPromise;
    shutdownPromise = (async () => {
      console.log(`Payloader shutdown requested: ${reason}`);
      await closeHttpServer(server, { timeoutMs });
      await closeResources?.();
    })();
    return shutdownPromise;
  };
  return Object.freeze({ shutdown });
};
