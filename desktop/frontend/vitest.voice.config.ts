import { defineConfig } from 'vitest/config';

/**
 * SPEC-03 §10.1 voice integration tests (I and I+HRP): headless clients
 * (`tests/voice/hc.ts`) against the real relay through the hostile relay
 * proxy (`tests/voice/hrp.ts`). Run with `npm run test:voice`; set
 * ACCORD_SERVER_BIN to a built `accord-server`, or have `cargo` on the PATH.
 * Node environment, files run one after another, 120 s per test.
 *
 * §10.1 asks for 64 KiB receive buffers on HRP's sockets. Node cannot set
 * them per socket, so the CI job caps the kernel's TCP receive buffers with
 * `sysctl`, leaves send buffers large (a 4 MiB maximum, so that only the
 * relay's TCP_NOTSENT_LOWAT of amendment A2 bounds the relay's unsent data,
 * which T-51 and RG-SCR-8 then check) and sets ACCORD_VOICE_TCP_CAP=required;
 * locally, run inside a user and network namespace with the same settings,
 * for example
 *   unshare -rn sh -c 'ip link set lo up &&
 *     echo "4096 65536 65536" > /proc/sys/net/ipv4/tcp_rmem &&
 *     echo "4096 16384 4194304" > /proc/sys/net/ipv4/tcp_wmem &&
 *     ACCORD_VOICE_TCP_CAP=required npm run test:voice'
 * Without the cap, T-51 runs its fallback form (a lossy link instead of a
 * throttled one, since the kernel's receive buffer is then unknown) and
 * RG-SCR-8 checks the 2 s age per fragment instead of a byte bound; T-47
 * runs the same way in both. The relay's TCP_NOTSENT_LOWAT (A2) keeps the
 * uncapped loopback from holding megabytes on the relay's side.
 */
export default defineConfig({
  test: {
    environment: 'node',
    setupFiles: ['./tests/voice/setup.ts'],
    globals: true,
    include: ['tests/voice/**/*.test.ts'],
    testTimeout: 120_000,
    hookTimeout: 900_000,
    fileParallelism: false,
    sequence: { concurrent: false },
  },
});
