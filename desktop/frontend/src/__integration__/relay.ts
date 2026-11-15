/**
 * Starts the real relay for the two-client tests (SPEC-02 §10.1):
 *
 *   accord-server --host 127.0.0.1 --port <p> --no-tls --no-admin
 *                 --database <tmp>/relay.db --attachments-dir <tmp>/attachments
 *
 * in its own temporary directory, which is also its working directory, so the
 * legacy file directory (`./data/files`) lands there too.
 *
 * The binary is `ACCORD_SERVER_BIN` when set (CI builds it first). Otherwise,
 * when `cargo` is on the PATH, the relay is started with `cargo run`, which
 * builds it on first use. With neither, the suite is skipped.
 */

import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

// Vitest runs from desktop/frontend.
export const REPO_ROOT = path.resolve(process.cwd(), '../..');

interface Command {
  readonly cmd: string;
  readonly args: readonly string[];
}

function resolveCommand(): Command | null {
  const bin = process.env.ACCORD_SERVER_BIN;
  if (bin) return { cmd: bin, args: [] };
  const cargo = spawnSync('cargo', ['--version'], { stdio: 'ignore' });
  if (cargo.status !== 0) return null;
  return {
    cmd: 'cargo',
    args: ['run', '-q', '--manifest-path', path.join(REPO_ROOT, 'Cargo.toml'), '-p', 'accord-server', '--bin', 'accord-server', '--'],
  };
}

const COMMAND = resolveCommand();

/** False when neither `ACCORD_SERVER_BIN` nor `cargo` is available. */
export const RELAY_AVAILABLE = COMMAND !== null;

const live = new Set<ChildProcess>();
process.on('exit', () => {
  for (const p of live) p.kill('SIGKILL');
});

async function freePort(): Promise<number> {
  const srv = net.createServer();
  await new Promise<void>(resolve => srv.listen(0, '127.0.0.1', resolve));
  const port = (srv.address() as net.AddressInfo).port;
  await new Promise<void>(resolve => srv.close(() => resolve()));
  return port;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export class RelayProcess {
  readonly dir: string;
  readonly dbPath: string;
  readonly attachmentsDir: string;
  /** The legacy file directory, `./data/files` relative to the working directory. */
  readonly legacyDir: string;
  /** Everything the relay wrote to stdout and stderr, across restarts. */
  readonly log: string[] = [];
  port = 0;
  private child: ChildProcess | null = null;

  private constructor(private readonly extraArgs: readonly string[]) {
    this.dir = mkdtempSync(path.join(os.tmpdir(), 'accord-spec02-'));
    this.dbPath = path.join(this.dir, 'relay.db');
    this.attachmentsDir = path.join(this.dir, 'attachments');
    this.legacyDir = path.join(this.dir, 'data', 'files');
  }

  static async start(extraArgs: readonly string[] = []): Promise<RelayProcess> {
    const relay = new RelayProcess(extraArgs);
    relay.port = await freePort();
    await relay.launch();
    return relay;
  }

  get baseUrl(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  private async launch(): Promise<void> {
    if (!COMMAND) throw new Error('no relay binary: set ACCORD_SERVER_BIN or put cargo on the PATH');
    const args = [
      ...COMMAND.args,
      '--host', '127.0.0.1',
      '--port', String(this.port),
      '--no-tls',
      '--no-admin',
      '--database', this.dbPath,
      '--attachments-dir', this.attachmentsDir,
      '--cors-origins', '*',
      ...this.extraArgs,
    ];
    const child = spawn(COMMAND.cmd, args, {
      cwd: this.dir,
      env: { ...process.env, NO_COLOR: '1', RUST_LOG: process.env.RUST_LOG ?? 'info' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    this.child = child;
    live.add(child);
    child.stdout!.on('data', (d: Buffer) => this.log.push(d.toString('utf8')));
    child.stderr!.on('data', (d: Buffer) => this.log.push(d.toString('utf8')));
    let exited = false;
    child.on('exit', () => {
      exited = true;
      live.delete(child);
    });

    // `cargo run` may compile first.
    const deadline = Date.now() + 600_000;
    while (Date.now() < deadline) {
      if (exited) throw new Error(`relay exited during startup:\n${this.log.join('').slice(-4000)}`);
      try {
        const r = await fetch(`${this.baseUrl}/health`);
        if (r.ok) return;
      } catch {
        // not up yet
      }
      await sleep(250);
    }
    throw new Error('relay did not start in time');
  }

  async stop(): Promise<void> {
    const child = this.child;
    if (!child || child.exitCode !== null) return;
    const done = new Promise<void>(resolve => child.once('exit', () => resolve()));
    child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 10_000);
    await done;
    clearTimeout(timer);
    this.child = null;
  }

  /** Stop the relay and delete its temporary directory. */
  async dispose(): Promise<void> {
    await this.stop();
    rmSync(this.dir, { recursive: true, force: true });
  }

  /** Stop and start again on the same directory, database and port. */
  async restart(): Promise<void> {
    await this.stop();
    await this.launch();
  }

  /** The relay's log, without ANSI colour codes. */
  logText(): string {
    // eslint-disable-next-line no-control-regex
    return this.log.join('').replace(/\u001b\[[0-9;]*m/g, '');
  }

  /** Every regular file under `dir`, recursively (database, WAL, blobs, legacy files). */
  static filesUnder(dir: string): string[] {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return [];
    }
    return entries.flatMap(name => {
      const p = path.join(dir, name);
      const st = statSync(p, { throwIfNoEntry: false });
      if (!st) return [];
      if (st.isDirectory()) return RelayProcess.filesUnder(p);
      return st.isFile() ? [p] : [];
    });
  }

  /** The database file and its WAL and shared-memory files. */
  databaseBytes(): Buffer[] {
    return [this.dbPath, `${this.dbPath}-wal`, `${this.dbPath}-shm`].flatMap(p => {
      try {
        return [readFileSync(p)];
      } catch {
        return [];
      }
    });
  }

  /**
   * Run one SQL statement on the relay's database, as an operator with file
   * access could (A1), in a child Node process (`node:sqlite`; the test
   * environment cannot load built-in modules that browsers lack). The relay
   * may be running: its database is in WAL mode, and both sides wait up to
   * 5 s for a lock.
   */
  sql(statement: string, params: ReadonlyArray<string | number | Uint8Array>): void {
    const script = [
      "const { DatabaseSync } = require('node:sqlite');",
      'const input = JSON.parse(process.argv[1]);',
      'const db = new DatabaseSync(input.db);',
      "db.exec('PRAGMA busy_timeout = 5000');",
      "const params = input.params.map(p => (p && typeof p === 'object' && 'hex' in p ? Buffer.from(p.hex, 'hex') : p));",
      'db.prepare(input.sql).run(...params);',
      'db.close();',
    ].join('\n');
    const params2 = params.map(p => (p instanceof Uint8Array ? { hex: Buffer.from(p).toString('hex') } : p));
    const r = spawnSync(process.execPath, ['--no-warnings', '-e', script, JSON.stringify({ db: this.dbPath, sql: statement, params: params2 })], {
      encoding: 'utf8',
    });
    if (r.status !== 0) throw new Error(`sql failed: ${r.stderr}`);
  }

  /** The names of the version-2 blobs on disk (not the marker or `.tmp`). */
  blobNames(): string[] {
    try {
      return readdirSync(this.attachmentsDir).filter(n => /^[0-9a-f-]{36}$/.test(n));
    } catch {
      return [];
    }
  }
}
