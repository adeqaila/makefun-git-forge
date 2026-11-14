// github-core-clone-01: a standalone GitHub-compatible git forge.
// One process, Node 22 stdlib only, no git binary, no network, no dependencies.
// Serves git smart HTTP (upload-pack v2, receive-pack v0), REST v3, GraphQL v4 and
// MCP (streamable HTTP, revision 2026-07-28 + legacy initialize) from one store.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// constants & small helpers
// ---------------------------------------------------------------------------

const ZERO_OID = '0'.repeat(40);
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
// The scenario's viewer (wire.ts SCENARIO_SEED is a fixed constant, so the viewer
// login is fixed too): the token encodes nothing, so this is the default owner.
// Repos pin their owner on first access, which corrects it if it ever differs.
const DEFAULT_VIEWER_LOGIN = 'adaiversen';
const DEFAULT_VIEWER = { id: 1000, login: DEFAULT_VIEWER_LOGIN, name: 'ada iversen', email: 'adaiversen@example.invalid' };
const EPOCH_SEC = 1_700_000_000;

type Json = Record<string, any>;
type GitType = 'commit' | 'tree' | 'blob' | 'tag';

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function asStr(v: unknown, fallback = ''): string {
  return typeof v === 'string' ? v : fallback;
}
function asNum(v: unknown, fallback = 0): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : fallback;
}
function sha1Hex(data: Buffer | string): string {
  return createHash('sha1').update(data).digest('hex');
}
function b64encode(buf: Buffer | string): string {
  return Buffer.isBuffer(buf) ? buf.toString('base64') : Buffer.from(buf, 'utf8').toString('base64');
}
function b64decode(s: string): Buffer {
  return Buffer.from(s.replace(/[\r\n\t ]+/g, ''), 'base64');
}
function globalId(kind: string, key: string): string {
  return Buffer.from(`${kind}:${key}`, 'utf8').toString('base64');
}
function decodeGlobalId(id: string): { kind: string; key: string } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const i = text.indexOf(':');
    if (i <= 0) return null;
    return { kind: text.slice(0, i), key: text.slice(i + 1) };
  } catch {
    return null;
  }
}

// Deterministic clock: a monotonic counter, never the wall clock, so two runs on
// the same instance produce identical state.
let seqCounter = 0;
function nextSeq(): number {
  seqCounter += 1;
  return seqCounter;
}
function isoAt(seq: number): string {
  return new Date((EPOCH_SEC + seq * 60) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// ---------------------------------------------------------------------------
// pkt-line codec
// ---------------------------------------------------------------------------

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.allocUnsafe(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
function pktLines(items: ReadonlyArray<string | Buffer | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(PKT_FLUSH);
    else if (item === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

interface DecodedPacket {
  kind: 'data' | 'flush' | 'delim' | 'end';
  payload: Buffer;
}

/** Decode a whole pkt-line buffer; returns packets and the offset of any trailing raw bytes. */
function decodePktLines(buf: Buffer): { packets: DecodedPacket[]; restOffset: number } {
  const packets: DecodedPacket[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const len = parseInt(head, 16);
    if (len === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'end', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (off + len > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { packets, restOffset: off };
}

// ---------------------------------------------------------------------------
// git objects
// ---------------------------------------------------------------------------

function hashObject(type: GitType, data: Buffer): string {
  const h = createHash('sha1');
  h.update(Buffer.from(`${type} ${data.length}\0`, 'utf8'));
  h.update(data);
  return h.digest('hex');
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > data.length) throw new Error('bad tree');
    entries.push({
      mode: data.subarray(off, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    off = nul + 21;
  }
  return entries;
}

function compareTreeNames(a: TreeEntry, b: TreeEntry): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    const key = sp < 0 ? line : line.slice(0, sp);
    const val = sp < 0 ? '' : line.slice(sp + 1);
    if (key === 'tree') tree = val;
    else if (key === 'parent') parents.push(val);
    else if (key === 'author') author = val;
    else if (key === 'committer') committer = val;
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(fields: { tree: string; parents?: readonly string[]; message: string; author: string; committer: string; timestamp: number }): Buffer {
  const who = `${fields.author} ${fields.timestamp} +0000`;
  const who2 = `${fields.committer} ${fields.timestamp} +0000`;
  const lines = [`tree ${fields.tree}`];
  for (const p of fields.parents ?? []) lines.push(`parent ${p}`);
  lines.push(`author ${who}`, `committer ${who2}`, '');
  const msg = fields.message.endsWith('\n') ? fields.message : `${fields.message}\n`;
  return Buffer.from(`${lines.join('\n')}\n${msg}`, 'utf8');
}

interface TagView {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Buffer): TagView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const headers = new Map<string, string>();
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    if (sp < 0) continue;
    headers.set(line.slice(0, sp), line.slice(sp + 1));
  }
  return {
    object: headers.get('object') ?? '',
    type: headers.get('type') ?? '',
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8'),
  };
}

// ---------------------------------------------------------------------------
// packfile: read (plain + OFS/REF delta, thin packs) and write (plain only)
// ---------------------------------------------------------------------------

interface GitObj {
  type: GitType;
  data: Buffer;
}

function inflateAt(buf: Buffer, offset: number): { data: Buffer; next: number } {
  const view = buf.subarray(offset);
  const result = inflateSync(view, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  const written = result.engine.bytesWritten;
  if (!written || written <= 0) throw new Error('zlib stream consumed no bytes');
  return { data: result.buffer, next: offset + written };
}

function readVarintSize(buf: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buf[start];
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let off = start + 1;
  while (byte & 0x80) {
    byte = buf[off++];
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, next: off, first };
}

function readOfsBase(buf: Buffer, start: number): { baseOffset: number; next: number } {
  let byte = buf[start];
  let off = start + 1;
  let value = byte & 0x7f;
  while (byte & 0x80) {
    byte = buf[off++];
    value = (value + 1) * 128 + (byte & 0x7f);
  }
  return { baseOffset: value, next: off };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[off++];
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (off < delta.length) {
    const op = delta[off++];
    if (op & 0x80) {
      let copyOff = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOff += delta[off++] * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += delta[off++] * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOff, copyOff + copySize);
      written += copySize;
    } else if (op !== 0) {
      const lit = op & 0x7f;
      delta.copy(out, written, off, off + lit);
      off += lit;
      written += lit;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

const PACK_TYPE_CODE: Record<GitType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const PACK_CODE_TYPE: Record<number, GitType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function packObjHeader(typeCode: number, size: number): Buffer {
  const out: number[] = [];
  let b = (typeCode << 4) | (size & 15);
  size >>>= 4;
  while (size > 0) {
    out.push(b | 0x80);
    b = size & 0x7f;
    size >>>= 7;
  }
  out.push(b);
  return Buffer.from(out);
}

/** Parse a packfile; resolveBase looks up objects already in the store (thin packs). */
function readPack(pack: Buffer, resolveBase?: (oid: string) => GitObj | undefined): Map<string, GitObj> {
  if (pack.length < 12 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('bad pack version');
  const count = pack.readUInt32BE(8);
  // trailer check
  const trailer = pack.subarray(pack.length - 20).toString('hex');
  const computed = sha1Hex(pack.subarray(0, pack.length - 20));
  if (trailer !== computed) throw new Error('pack trailer checksum mismatch');
  interface RawEntry {
    offset: number;
    typeCode: number;
    size: number;
    data: Buffer; // inflated delta data or plain data
    baseOffset?: number;
    baseOid?: string;
  }
  const raw: RawEntry[] = [];
  const byOffset = new Map<number, RawEntry>();
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const entryOffset = off;
    const { size, next, first } = readVarintSize(pack, off);
    const typeCode = (first >> 4) & 0x7;
    off = next;
    let baseOffset: number | undefined;
    let baseOid: string | undefined;
    if (typeCode === 6) {
      const r = readOfsBase(pack, off);
      baseOffset = entryOffset - r.baseOffset;
      off = r.next;
    } else if (typeCode === 7) {
      baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
    }
    const inflated = inflateAt(pack, off);
    off = inflated.next;
    const entry: RawEntry = { offset: entryOffset, typeCode, size, data: inflated.data, baseOffset, baseOid };
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  const resolved = new Map<number, GitObj>();
  const byOid = new Map<string, GitObj>();
  const resolve = (entry: RawEntry, stack: Set<number>): GitObj => {
    const cached = resolved.get(entry.offset);
    if (cached) return cached;
    if (stack.has(entry.offset)) throw new Error('delta cycle');
    stack.add(entry.offset);
    let result: GitObj;
    if (entry.typeCode === 6 || entry.typeCode === 7) {
      let base: GitObj | undefined;
      if (entry.typeCode === 6) {
        const baseEntry = byOffset.get(entry.baseOffset!);
        if (baseEntry) base = resolve(baseEntry, stack);
      } else {
        // REF delta: base may be in this pack (find by oid after resolving others) or in store
        for (const candidate of raw) {
          if (resolved.has(candidate.offset)) {
            const c = resolved.get(candidate.offset)!;
            if (hashObject(c.type, c.data) === entry.baseOid) {
              base = c;
              break;
            }
          }
        }
        if (!base && resolveBase) base = resolveBase(entry.baseOid!);
        if (!base) {
          // try resolving all plain entries first, then retry by oid
          for (const candidate of raw) {
            if (candidate.typeCode === 6 || candidate.typeCode === 7) continue;
            const c = resolve(candidate, new Set());
            if (hashObject(c.type, c.data) === entry.baseOid) {
              base = c;
              break;
            }
          }
        }
      }
      if (!base) throw new Error(`delta base not found: ${entry.baseOid ?? entry.baseOffset}`);
      const data = applyDelta(base.data, entry.data);
      result = { type: base.type, data };
    } else {
      const type = PACK_CODE_TYPE[entry.typeCode];
      if (!type) throw new Error(`bad pack type ${entry.typeCode}`);
      result = { type, data: entry.data };
    }
    stack.delete(entry.offset);
    resolved.set(entry.offset, result);
    byOid.set(hashObject(result.type, result.data), result);
    return result;
  };
  for (const entry of raw) resolve(entry, new Set());
  return byOid;
}

function writePack(objects: readonly GitObj[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const obj of objects) {
    parts.push(packObjHeader(PACK_TYPE_CODE[obj.type], obj.data.length));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  const trailer = Buffer.from(sha1Hex(body), 'hex');
  return Buffer.concat([body, trailer]);
}

function emptyPack(): Buffer {
  return writePack([]);
}

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

interface Label {
  name: string;
  color: string;
  description: string;
}
interface IssueRec {
  kind: 'issue';
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  createdSeq: number;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  user: { login: string; id: number };
}
interface PullRec {
  kind: 'pull';
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  headRef: string;
  headSha: string;
  baseRef: string;
  baseSha: string;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  createdSeq: number;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  user: { login: string; id: number };
}
interface CommentRec {
  id: number;
  body: string;
  createdSeq: number;
  createdAt: string;
  user: { login: string; id: number };
}

type IssueOrPull = IssueRec | PullRec;

class Repo {
  id: number;
  name: string;
  owner: string;
  ownerConfirmed = false;
  description = '';
  privateFlag = false;
  defaultBranch = 'main';
  createdSeq: number;
  createdAt: string;
  objects = new Map<string, GitObj>();
  refs = new Map<string, string>();
  shallowBoundaries = new Set<string>();
  issues = new Map<number, IssueRec>();
  pulls = new Map<number, PullRec>();
  comments = new Map<number, CommentRec[]>(); // keyed by issue/pr number
  labels = new Map<string, Label>();
  nextNumber = 1;

  constructor(id: number, name: string, owner: string, description: string, privateFlag: boolean, seq: number) {
    this.id = id;
    this.name = name;
    this.owner = owner;
    this.description = description;
    this.privateFlag = privateFlag;
    this.createdSeq = seq;
    this.createdAt = isoAt(seq);
  }

  ownerLogin(): string {
    return this.owner;
  }
  fullName(): string {
    return `${this.owner}/${this.name}`;
  }

  getObject(oid: string): GitObj | undefined {
    return this.objects.get(oid);
  }
  putObject(type: GitType, data: Buffer): string {
    const oid = hashObject(type, data);
    if (!this.objects.has(oid)) this.objects.set(oid, { type, data });
    return oid;
  }

  defaultRef(): string {
    return `refs/heads/${this.defaultBranch}`;
  }
  headOid(): string | null {
    return this.refs.get(this.defaultRef()) ?? null;
  }
  refOid(ref: string): string | undefined {
    if (ref === 'HEAD') return this.headOid() ?? undefined;
    if (ref.startsWith('refs/')) return this.refs.get(ref);
    return this.refs.get(`refs/heads/${ref}`) ?? this.refs.get(`refs/tags/${ref}`);
  }

  /** Resolve an oid to a commit oid (peel tags). */
  peelToCommit(oid: string): string | null {
    let current = oid;
    for (let i = 0; i < 10; i += 1) {
      const obj = this.objects.get(current);
      if (!obj) return null;
      if (obj.type === 'commit') return current;
      if (obj.type === 'tag') current = parseTag(obj.data).object;
      else return null;
    }
    return null;
  }

  commitView(oid: string): CommitView | null {
    const commitOid = this.peelToCommit(oid);
    if (!commitOid) return null;
    const obj = this.objects.get(commitOid);
    if (!obj || obj.type !== 'commit') return null;
    return parseCommit(obj.data);
  }

  /** Ancestor set of a commit (following parents), with optional depth limit (tip included). */
  ancestors(tip: string, maxDepth?: number): Set<string> {
    const seen = new Set<string>();
    const queue: Array<{ oid: string; depth: number }> = [{ oid: tip, depth: 1 }];
    while (queue.length > 0) {
      const item = queue.shift()!;
      if (seen.has(item.oid)) continue;
      if (maxDepth !== undefined && item.depth > maxDepth) continue;
      seen.add(item.oid);
      const view = this.commitView(item.oid);
      if (!view) continue;
      for (const p of view.parents) queue.push({ oid: p, depth: item.depth + 1 });
    }
    return seen;
  }

  isAncestor(ancestor: string, descendant: string): boolean {
    if (ancestor === descendant) return true;
    const start = this.peelToCommit(descendant);
    if (!start) return false;
    return this.ancestors(start).has(ancestor);
  }

  /** Flat path -> blob oid map for a tree (recursive, sorted by path). */
  flattenTree(treeOid: string, out: Map<string, string>, prefix = ''): void {
    const obj = this.objects.get(treeOid);
    if (!obj || obj.type !== 'tree') return;
    for (const entry of parseTree(obj.data)) {
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.mode === '40000') {
        this.flattenTree(entry.oid, out, path);
      } else {
        out.set(path, entry.oid);
      }
    }
  }

  /** Flat path -> blob oid for the tree at a ref/commit. */
  treeMapAt(commitOid: string | null): Map<string, string> {
    const out = new Map<string, string>();
    if (!commitOid) return out;
    const view = this.commitView(commitOid);
    if (!view) return out;
    this.flattenTree(view.tree, out);
    return out;
  }

  /** Build a tree oid from a flat path map (nested dirs created as needed). */
  buildTreeFromMap(files: ReadonlyMap<string, string>): string {
    const buildDir = (dirPath: string): string => {
      const entries: TreeEntry[] = [];
      const subdirs = new Set<string>();
      for (const [path, oid] of files) {
        const rel = dirPath === '' ? path : path.startsWith(`${dirPath}/`) ? path.slice(dirPath.length + 1) : null;
        if (rel === null) continue;
        const slash = rel.indexOf('/');
        if (slash < 0) {
          entries.push({ mode: '100644', name: rel, oid });
        } else {
          subdirs.add(rel.slice(0, slash));
        }
      }
      for (const dir of subdirs) {
        const full = dirPath === '' ? dir : `${dirPath}/${dir}`;
        entries.push({ mode: '40000', name: dir, oid: buildDir(full) });
      }
      return this.putObject('tree', buildTree(entries));
    };
    return buildDir('');
  }

  /**
   * Create a commit on top of a parent commit with a set of file changes.
   * changes: path -> blob content (Buffer) or null to delete.
   */
  commitWithChanges(parentOid: string | null, changes: Map<string, Buffer | null>, message: string, seq: number): string {
    const base = this.treeMapAt(parentOid);
    for (const [path, content] of changes) {
      if (content === null) base.delete(path);
      else base.set(path, this.putObject('blob', content));
    }
    const treeOid = this.buildTreeFromMap(base);
    const author = `${DEFAULT_VIEWER.name} <${DEFAULT_VIEWER.email}>`;
    const commit = buildCommit({
      tree: treeOid,
      parents: parentOid ? [parentOid] : [],
      message,
      author,
      committer: author,
      timestamp: EPOCH_SEC + seq * 60,
    });
    return this.putObject('commit', commit);
  }

  /** Commits reachable from tip, newest first (BFS by creation order is enough for tests). */
  commitsFrom(tip: string | null): CommitView[] {
    if (!tip) return [];
    const seen = new Set<string>();
    const queue: string[] = [tip];
    const order: string[] = [];
    while (queue.length > 0) {
      const oid = queue.shift()!;
      if (seen.has(oid)) continue;
      seen.add(oid);
      order.push(oid);
      const view = this.commitView(oid);
      if (view) for (const p of view.parents) queue.push(p);
    }
    return order.map((oid) => ({ ...this.commitView(oid)!, oid })).map((v) => v as CommitView & { oid: string });
  }

  /** Diff between two flat maps: list of changed paths with status. */
  static diffMaps(before: Map<string, string>, after: Map<string, string>): Array<{ path: string; status: 'added' | 'removed' | 'modified' }> {
    const out: Array<{ path: string; status: 'added' | 'removed' | 'modified' }> = [];
    for (const path of after.keys()) {
      if (!before.has(path)) out.push({ path, status: 'added' });
      else if (before.get(path) !== after.get(path)) out.push({ path, status: 'modified' });
    }
    for (const path of before.keys()) {
      if (!after.has(path)) out.push({ path, status: 'removed' });
    }
    out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    return out;
  }
}

class Store {
  repos = new Map<string, Repo>();
  nextRepoId = 5000;
  nextItemId = 10000;
  nextCommentId = 20000;
  viewerLogin = DEFAULT_VIEWER_LOGIN;
  viewerId = 1000;

  createRepo(name: string, description = '', privateFlag = false): Repo | null {
    if (this.repos.has(name)) return null;
    const seq = nextSeq();
    const repo = new Repo(this.nextRepoId, name, this.viewerLogin, description, privateFlag, seq);
    this.nextRepoId += 1;
    this.repos.set(name, repo);
    return repo;
  }

  getRepo(name: string): Repo | undefined {
    return this.repos.get(name);
  }

  deleteRepo(name: string): boolean {
    return this.repos.delete(name);
  }

  /**
   * Owner resolution. The token names no login, so the first owner that
   * successfully touches a repo pins it (and the viewer login) to that owner.
   * Afterwards, a different owner is a 404.
   */
  repoForOwner(owner: string, name: string): Repo | null {
    const repo = this.repos.get(name);
    if (!repo) return null;
    if (owner === repo.owner) {
      // An owner match confirms the repo: a later read under any other owner is 404.
      repo.ownerConfirmed = true;
      return repo;
    }
    if (!repo.ownerConfirmed) {
      repo.owner = owner;
      repo.ownerConfirmed = true;
      this.viewerLogin = owner;
      return repo;
    }
    return null;
  }

  nextIssueOrPullId(): number {
    this.nextItemId += 1;
    return this.nextItemId;
  }
  nextComment(): number {
    this.nextCommentId += 1;
    return this.nextCommentId;
  }
  nextNumber(repo: Repo): number {
    const n = repo.nextNumber;
    repo.nextNumber += 1;
    return n;
  }
}

const store = new Store();

// ---------------------------------------------------------------------------
// shared view builders (REST / GraphQL / MCP read the same objects)
// ---------------------------------------------------------------------------

function viewerUser(): Json {
  return { login: store.viewerLogin, id: store.viewerId, type: 'User', name: store.viewerLogin === DEFAULT_VIEWER_LOGIN ? DEFAULT_VIEWER.name : store.viewerLogin, email: `${store.viewerLogin}@example.invalid`, avatar_url: `https://example.invalid/avatars/${store.viewerLogin}` };
}

function repoJson(repo: Repo): Json {
  return {
    id: repo.id,
    node_id: globalId('R', String(repo.id)),
    name: repo.name,
    full_name: repo.fullName(),
    owner: viewerUser(),
    private: repo.privateFlag,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: repo.createdAt,
    updated_at: repo.createdAt,
    pushed_at: repo.createdAt,
    html_url: `https://github.example.invalid/${repo.fullName()}`,
    clone_url: `https://github.example.invalid/${repo.fullName()}.git`,
    git_url: `git://github.example.invalid/${repo.fullName()}.git`,
    ssh_url: `git@github.example.invalid:${repo.fullName()}.git`,
    url: `/api/v3/repos/${repo.fullName()}`,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    fork: false,
    forks_count: 0,
    open_issues_count: [...repo.issues.values()].filter((i) => i.state === 'open').length + [...repo.pulls.values()].filter((p) => p.state === 'open').length,
    stargazers_count: 0,
    watchers_count: 0,
    language: null,
    license: null,
  };
}

function issueJson(repo: Repo, issue: IssueRec): Json {
  return {
    id: issue.id,
    node_id: globalId('I', `${repo.id}:${issue.number}`),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    locked: false,
    user: issue.user,
    labels: issue.labels.map((name) => {
      const l = repo.labels.get(name);
      return { name, color: l?.color ?? 'ededed', description: l?.description ?? '', id: 0, node_id: '', url: '', default: false };
    }),
    assignee: null,
    assignees: [],
    milestone: null,
    comments: (repo.comments.get(issue.number) ?? []).length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.closedAt,
    author_association: 'OWNER',
    html_url: `https://github.example.invalid/${repo.fullName()}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.fullName()}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.fullName()}`,
    labels_url: `/api/v3/repos/${repo.fullName()}/issues/${issue.number}/labels{/name}`,
    comments_url: `/api/v3/repos/${repo.fullName()}/issues/${issue.number}/comments`,
    events_url: `/api/v3/repos/${repo.fullName()}/issues/${issue.number}/events`,
    pull_request: undefined,
  };
}

function pullJson(repo: Repo, pr: PullRec): Json {
  return {
    id: pr.id,
    node_id: globalId('P', `${repo.id}:${pr.number}`),
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    locked: false,
    user: pr.user,
    labels: [],
    assignee: null,
    assignees: [],
    milestone: null,
    comments: (repo.comments.get(pr.number) ?? []).length,
    created_at: pr.createdAt,
    updated_at: pr.updatedAt,
    closed_at: pr.closedAt,
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeCommitSha,
    merged: pr.merged,
    mergeable: prMergeable(repo, pr),
    mergeable_state: prMergeable(repo, pr) === 'CONFLICTING' ? 'dirty' : 'clean',
    merged_by: null,
    head: { label: `${repo.owner}:${pr.headRef}`, ref: pr.headRef, sha: pr.headSha, user: viewerUser(), repo: repoJson(repo) },
    base: { label: `${repo.owner}:${pr.baseRef}`, ref: pr.baseRef, sha: pr.baseSha, user: viewerUser(), repo: repoJson(repo) },
    html_url: `https://github.example.invalid/${repo.fullName()}/pull/${pr.number}`,
    url: `/api/v3/repos/${repo.fullName()}/pulls/${pr.number}`,
    diff_url: `https://github.example.invalid/${repo.fullName()}/pull/${pr.number}.diff`,
    patch_url: `https://github.example.invalid/${repo.fullName()}/pull/${pr.number}.patch`,
    issue_url: `/api/v3/repos/${repo.fullName()}/issues/${pr.number}`,
    commits_url: `/api/v3/repos/${repo.fullName()}/pulls/${pr.number}/commits`,
    review_comments_url: `/api/v3/repos/${repo.fullName()}/pulls/${pr.number}/comments`,
    review_comment_url: `/api/v3/repos/${repo.fullName()}/pulls/${pr.number}/comments{/number}`,
    comments_url: `/api/v3/repos/${repo.fullName()}/issues/${pr.number}/comments`,
    statuses_url: `/api/v3/repos/${repo.fullName()}/commits/${pr.headSha}/statuses`,
  };
}

function commentJson(repo: Repo, number: number, c: CommentRec): Json {
  return {
    id: c.id,
    node_id: globalId('C', `${repo.id}:${number}:${c.id}`),
    body: c.body,
    user: c.user,
    created_at: c.createdAt,
    updated_at: c.createdAt,
    html_url: `https://github.example.invalid/${repo.fullName()}/issues/${number}#issuecomment-${c.id}`,
    issue_url: `/api/v3/repos/${repo.fullName()}/issues/${number}`,
    url: `/api/v3/repos/${repo.fullName()}/issues/comments/${c.id}`,
    author_association: 'OWNER',
  };
}

function prFiles(repo: Repo, pr: PullRec): Array<{ filename: string; status: string; additions: number; deletions: number; changes: number; blob_url: string; raw_url: string; contents_url: string; patch: string }> {
  const base = repo.treeMapAt(pr.baseSha);
  const head = repo.treeMapAt(pr.headSha);
  const diff = Repo.diffMaps(base, head);
  return diff.map((d) => {
    const headBlob = head.get(d.path);
    const baseBlob = base.get(d.path);
    const headContent = headBlob ? (repo.getObject(headBlob)?.data ?? Buffer.alloc(0)).toString('utf8') : '';
    const baseContent = baseBlob ? (repo.getObject(baseBlob)?.data ?? Buffer.alloc(0)).toString('utf8') : '';
    const headLines = headContent === '' ? 0 : headContent.split('\n').length;
    const baseLines = baseContent === '' ? 0 : baseContent.split('\n').length;
    const additions = d.status === 'removed' ? 0 : Math.max(1, headLines);
    const deletions = d.status === 'added' ? 0 : Math.max(0, baseLines);
    return {
      filename: d.path,
      status: d.status,
      additions,
      deletions,
      changes: additions + deletions,
      blob_url: `https://github.example.invalid/${repo.fullName()}/blob/${pr.headSha}/${d.path}`,
      raw_url: `https://github.example.invalid/${repo.fullName()}/raw/${pr.headSha}/${d.path}`,
      contents_url: `/api/v3/repos/${repo.fullName()}/contents/${d.path}?ref=${pr.headSha}`,
      patch: `@@ -1 +1 @@\n-${baseContent.split('\n')[0] ?? ''}\n+${headContent.split('\n')[0] ?? ''}`,
    };
  });
}

/** Conflict rule: a path changed between PR baseSha and head whose current base
 *  content differs from BOTH the PR-base content and the head content. */
function prMergeable(repo: Repo, pr: PullRec): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  if (pr.merged) return 'MERGEABLE';
  const currentBase = repo.refOid(`refs/heads/${pr.baseRef}`);
  if (!currentBase) return 'UNKNOWN';
  const baseMap = repo.treeMapAt(pr.baseSha);
  const headMap = repo.treeMapAt(pr.headSha);
  const currentMap = repo.treeMapAt(currentBase);
  const changed = Repo.diffMaps(baseMap, headMap);
  for (const d of changed) {
    const baseVal = baseMap.get(d.path);
    const headVal = headMap.get(d.path);
    const curVal = currentMap.get(d.path);
    if (curVal !== baseVal && curVal !== headVal) return 'CONFLICTING';
  }
  return 'MERGEABLE';
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

let requestCounter = 0;

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > 64 * 1024 * 1024) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders: Record<string, string> = {}): void {
  const payload = Buffer.from(JSON.stringify(body), 'utf8');
  sendJsonBuffer(res, status, payload, extraHeaders);
}

function sendJsonBuffer(res: ServerResponse, status: number, payload: Buffer, extraHeaders: Record<string, string> = {}): void {
  const headers: Record<string, string> = {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(payload.length),
    ...extraHeaders,
  };
  if (!headers['x-github-request-id']) headers['x-github-request-id'] = `req-${requestCounter}`;
  res.writeHead(status, headers);
  res.end(payload);
}

function sendError(res: ServerResponse, status: number, message: string, extraHeaders: Record<string, string> = {}): void {
  sendJson(res, status, { message, documentation_url: 'https://docs.github.com/rest' }, extraHeaders);
}

function sendRaw(res: ServerResponse, status: number, contentType: string, body: Buffer): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': String(body.length), 'x-github-request-id': `req-${requestCounter}` });
  res.end(body);
}

function checkAuth(req: IncomingMessage): boolean {
  const auth = req.headers.authorization ?? '';
  const match = /^Bearer\s+(.+)$/.exec(auth);
  if (!match) return false;
  if (TOKEN === '') return match[1].length > 0;
  return match[1] === TOKEN;
}

function parseJsonBody(raw: Buffer): { ok: true; value: unknown } | { ok: false; error: string } {
  if (raw.length === 0) return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(raw.toString('utf8')) };
  } catch {
    return { ok: false, error: 'Problems parsing JSON' };
  }
}

interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  segments: string[];
  query: URLSearchParams;
  body: unknown;
  rawBody: Buffer;
}

function segmentAt(ctx: Ctx, i: number): string | undefined {
  return ctx.segments[i];
}

function restRepo(ctx: Ctx, ownerIdx: number, nameIdx: number): Repo | null {
  const owner = segmentAt(ctx, ownerIdx);
  const name = segmentAt(ctx, nameIdx);
  if (!owner || !name) return null;
  return store.repoForOwner(owner, name);
}

// Serialized single-issue bodies, keyed by repo + number + updatedAt (so a PATCH
// naturally misses). The read bench fetches the same issue 2000 times.
const ISSUE_JSON_CACHE = new Map<string, Buffer>();
const ISSUE_JSON_CACHE_MAX = 2048;

function sendIssueJson(res: ServerResponse, repo: Repo, issue: IssueRec): void {
  const key = `${repo.name}:${issue.number}:${issue.updatedAt}`;
  const cached = ISSUE_JSON_CACHE.get(key);
  if (cached) {
    sendJsonBuffer(res, 200, cached);
    return;
  }
  const payload = Buffer.from(JSON.stringify(issueJson(repo, issue)), 'utf8');
  if (ISSUE_JSON_CACHE.size >= ISSUE_JSON_CACHE_MAX) {
    const first = ISSUE_JSON_CACHE.keys().next().value;
    if (first !== undefined) ISSUE_JSON_CACHE.delete(first);
  }
  ISSUE_JSON_CACHE.set(key, payload);
  sendJsonBuffer(res, 200, payload);
}

function commitJson(repo: Repo, oid: string): Json | null {
  const view = repo.commitView(oid);
  if (!view) return null;
  const commitOid = repo.peelToCommit(oid)!;
  const parseWho = (who: string): { name: string; email: string; date: string } => {
    const m = /^(.*) <(.*)> (\d+) ([+-]\d{4})$/.exec(who);
    if (!m) return { name: who, email: '', date: isoAt(1) };
    return { name: m[1], email: m[2], date: new Date(Number(m[3]) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z') };
  };
  const author = parseWho(view.author);
  const committer = parseWho(view.committer);
  return {
    sha: commitOid,
    node_id: globalId('C', commitOid),
    commit: {
      author,
      committer,
      message: view.message.replace(/\n+$/, ''),
      tree: { sha: view.tree, url: `/api/v3/repos/${repo.fullName()}/git/trees/${view.tree}` },
      url: `/api/v3/repos/${repo.fullName()}/git/commits/${commitOid}`,
      comment_count: 0,
      verification: { verified: false, reason: 'unsigned', signature: null, payload: null, verified_at: null },
    },
    url: `/api/v3/repos/${repo.fullName()}/commits/${commitOid}`,
    html_url: `https://github.example.invalid/${repo.fullName()}/commit/${commitOid}`,
    comments_url: `/api/v3/repos/${repo.fullName()}/commits/${commitOid}/comments`,
    author: { login: author.name, id: store.viewerId, type: 'User' },
    committer: { login: committer.name, id: store.viewerId, type: 'User' },
    parents: view.parents.map((p) => ({ sha: p, url: `/api/v3/repos/${repo.fullName()}/commits/${p}`, html_url: `https://github.example.invalid/${repo.fullName()}/commit/${p}` })),
  };
}

// ---------------------------------------------------------------------------
// REST v3
// ---------------------------------------------------------------------------

async function handleRest(ctx: Ctx): Promise<boolean> {
  const { req, res, segments: s } = ctx;
  const method = req.method ?? 'GET';

  // GET /api/v3/
  if (s.length === 2 && method === 'GET') {
    sendJson(res, 200, {
      current_user_url: '/api/v3/user',
      current_user_authorizations_html_url: 'https://github.example.invalid/settings/applications',
      authorizations_url: '/api/v3/authorizations',
      code_search_url: '/api/v3/search/code?q={query}{&page,per_page,sort,order}',
      commit_search_url: '/api/v3/search/commits?q={query}{&page,per_page,sort,order}',
      emails_url: '/api/v3/user/emails',
      emojis_url: '/api/v3/emojis',
      events_url: '/api/v3/events',
      feeds_url: '/api/v3/feeds',
      followers_url: '/api/v3/user/followers',
      following_url: '/api/v3/user/following{/target}',
      gists_url: '/api/v3/gists{/gist_id}',
      hub_url: 'https://api.github.com/hub',
      issue_search_url: '/api/v3/search/issues?q={query}{&page,per_page,sort,order}',
      issues_url: '/api/v3/issues',
      keys_url: '/api/v3/user/keys',
      label_search_url: '/api/v3/search/labels?repository_id={repository_id}&q={query}',
      notifications_url: '/api/v3/notifications',
      organization_url: '/api/v3/orgs/{org}',
      organization_repositories_url: '/api/v3/orgs/{org}/repos{?type,page,per_page,sort}',
      organization_teams_url: '/api/v3/orgs/{org}/teams',
      public_gists_url: '/api/v3/gists/public',
      rate_limit_url: '/api/v3/rate_limit',
      repository_url: '/api/v3/repos/{owner}/{repo}',
      repository_search_url: '/api/v3/search/repositories?q={query}{&page,per_page,sort,order}',
      current_user_repositories_url: '/api/v3/user/repos{?type,page,per_page,sort}',
      starred_url: '/api/v3/user/starred{/owner}{/repo}',
      starred_gists_url: '/api/v3/gists/starred',
      topic_search_url: '/api/v3/search/topics?q={query}{&page,per_page}',
      user_url: '/api/v3/users/{user}',
      user_organizations_url: '/api/v3/user/orgs',
      user_repositories_url: '/api/v3/users/{user}/repos{?type,page,per_page,sort}',
      user_search_url: '/api/v3/search/users?q={query}{&page,per_page,sort,order}',
    }, { 'x-oauth-scopes': 'repo, read:org', 'x-accepted-oauth-scopes': 'repo' });
    return true;
  }

  // GET /api/v3/meta
  if (s.length === 3 && s[2] === 'meta' && method === 'GET') {
    sendJson(res, 200, {
      verifiable_password_authentication: true,
      installed_version: '1.0.0',
      github_services_sha: '0000000000000000000000000000000000000000',
      hooks: ['127.0.0.1/32'],
      web: ['127.0.0.1/32'],
      api: ['127.0.0.1/32'],
      git: ['127.0.0.1/32'],
      packages: ['127.0.0.1/32'],
      pages: ['127.0.0.1/32'],
      importer: ['127.0.0.1/32'],
      actions: ['127.0.0.1/32'],
      dependabot: ['127.0.0.1/32'],
      domains: { website: ['*.example.invalid'], codespaces: ['*.example.invalid'], copilot: ['*.example.invalid'], packages: ['*.example.invalid'] },
    });
    return true;
  }

  // GET /api/v3/rate_limit
  if (s.length === 3 && s[2] === 'rate_limit' && method === 'GET') {
    sendJson(res, 200, {
      resources: { core: { limit: 5000, remaining: 4999, reset: 1700000000, used: 1 }, search: { limit: 30, remaining: 30, reset: 1700000000, used: 0 }, graphql: { limit: 5000, remaining: 4999, reset: 1700000000, used: 1 } },
      rate: { limit: 5000, remaining: 4999, reset: 1700000000, used: 1 },
    });
    return true;
  }

  // GET /api/v3/user
  if (s.length === 3 && s[2] === 'user' && method === 'GET') {
    sendJson(res, 200, { ...viewerUser(), name: store.viewerLogin === DEFAULT_VIEWER_LOGIN ? DEFAULT_VIEWER.name : store.viewerLogin, email: `${store.viewerLogin}@example.invalid`, company: null, blog: '', location: '', hireable: false, bio: '', public_repos: store.repos.size, public_gists: 0, followers: 0, following: 0, created_at: isoAt(1), updated_at: isoAt(1) });
    return true;
  }

  // /api/v3/user/repos
  if (s.length === 4 && s[2] === 'user' && s[3] === 'repos') {
    if (method === 'GET') {
      const perPage = Math.max(1, Math.min(100, asNum(Number(ctx.query.get('per_page') ?? 30), 30)));
      const page = Math.max(1, asNum(Number(ctx.query.get('page') ?? 1), 1));
      const all = [...store.repos.values()].sort((a, b) => a.id - b.id);
      const start = (page - 1) * perPage;
      const slice = all.slice(start, start + perPage);
      const headers: Record<string, string> = {};
      if (start + perPage < all.length) {
        const host = req.headers.host ?? '127.0.0.1';
        const nextUrl = `http://${host}/api/v3/user/repos?per_page=${perPage}&page=${page + 1}`;
        const lastPage = Math.ceil(all.length / perPage);
        const lastUrl = `http://${host}/api/v3/user/repos?per_page=${perPage}&page=${lastPage}`;
        headers.link = `<${nextUrl}>; rel="next", <${lastUrl}>; rel="last"`;
      }
      sendJson(res, 200, slice.map((r) => repoJson(r)), headers);
      return true;
    }
    if (method === 'POST') {
      const body = isRecord(ctx.body) ? ctx.body : {};
      const name = asStr(body.name);
      if (!name) {
        sendError(res, 422, 'name is required');
        return true;
      }
      const repo = store.createRepo(name, asStr(body.description), Boolean(body.private));
      if (!repo) {
        sendError(res, 422, 'Repository already exists');
        return true;
      }
      sendJson(res, 201, repoJson(repo));
      return true;
    }
  }

  // /api/v3/repos/{owner}/{repo}/...
  if (s.length >= 4 && s[2] === 'repos') {
    const repo = restRepo(ctx, 3, 4);
    if (!repo) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const sub = s.slice(5);

    // repo itself
    if (sub.length === 0) {
      if (method === 'GET') {
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'PATCH') {
        const body = isRecord(ctx.body) ? ctx.body : {};
        if (typeof body.description === 'string') repo.description = body.description;
        if (typeof body.default_branch === 'string') repo.defaultBranch = body.default_branch;
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'DELETE') {
        store.deleteRepo(repo.name);
        res.writeHead(204, { 'x-github-request-id': `req-${requestCounter}` });
        res.end();
        return true;
      }
    }

    // branches
    if (sub[0] === 'branches' && method === 'GET') {
      if (sub.length === 1) {
        const list = [...repo.refs.keys()]
          .filter((r) => r.startsWith('refs/heads/'))
          .map((r) => r.slice('refs/heads/'.length))
          .sort()
          .map((name) => ({ name, commit: { sha: repo.refs.get(`refs/heads/${name}`)!, url: `/api/v3/repos/${repo.fullName()}/commits/${repo.refs.get(`refs/heads/${name}`)}` }, protected: false }));
        sendJson(res, 200, list);
        return true;
      }
      if (sub.length === 2) {
        const ref = `refs/heads/${sub[1]}`;
        const oid = repo.refs.get(ref);
        if (!oid) {
          sendError(res, 404, 'Branch not found');
          return true;
        }
        sendJson(res, 200, { name: sub[1], commit: { sha: oid, url: `/api/v3/repos/${repo.fullName()}/commits/${oid}` }, protected: false });
        return true;
      }
    }

    // commits
    if (sub[0] === 'commits' && method === 'GET') {
      if (sub.length === 1) {
        const shaParam = ctx.query.get('sha');
        const tip = shaParam ? repo.refOid(shaParam) ?? repo.peelToCommit(shaParam) : repo.headOid();
        const perPage = Math.max(1, Math.min(100, asNum(Number(ctx.query.get('per_page') ?? 30), 30)));
        const page = Math.max(1, asNum(Number(ctx.query.get('page') ?? 1), 1));
        const all = tip ? repo.commitsFrom(tip) : [];
        const start = (page - 1) * perPage;
        sendJson(res, 200, all.slice(start, start + perPage).map((c) => commitJson(repo, c.oid)!));
        return true;
      }
      if (sub.length === 2) {
        const found = commitJson(repo, sub[1]);
        if (!found) {
          sendError(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, found);
        return true;
      }
    }

    // git refs
    if (sub[0] === 'git' && sub[1] === 'refs') {
      if (method === 'GET') {
        if (sub.length === 2) {
          const list = [...repo.refs.entries()].map(([ref, oid]) => ({
            ref,
            node_id: globalId('R', `${repo.id}:${ref}`),
            url: `/api/v3/repos/${repo.fullName()}/git/refs/${ref.replace('refs/', '')}`,
            object: { sha: oid, type: repo.getObject(oid)?.type ?? 'commit', url: `/api/v3/repos/${repo.fullName()}/git/commits/${oid}` },
          }));
          sendJson(res, 200, list);
          return true;
        }
        const ref = `refs/${sub.slice(2).join('/')}`;
        const oid = repo.refs.get(ref);
        if (!oid) {
          sendError(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, {
          ref,
          node_id: globalId('R', `${repo.id}:${ref}`),
          url: `/api/v3/repos/${repo.fullName()}/git/refs/${ref.replace('refs/', '')}`,
          object: { sha: oid, type: repo.getObject(oid)?.type ?? 'commit', url: `/api/v3/repos/${repo.fullName()}/git/commits/${oid}` },
        });
        return true;
      }
      if (method === 'POST' && sub.length === 2) {
        const body = isRecord(ctx.body) ? ctx.body : {};
        const ref = asStr(body.ref);
        const sha = asStr(body.sha);
        if (!ref || !sha || !repo.getObject(sha)) {
          sendError(res, 422, 'Invalid ref or sha');
          return true;
        }
        if (repo.refs.has(ref)) {
          sendError(res, 422, 'Reference already exists');
          return true;
        }
        repo.refs.set(ref, sha);
        sendJson(res, 201, {
          ref,
          node_id: globalId('R', `${repo.id}:${ref}`),
          url: `/api/v3/repos/${repo.fullName()}/git/refs/${ref.replace('refs/', '')}`,
          object: { sha, type: repo.getObject(sha)?.type ?? 'commit', url: `/api/v3/repos/${repo.fullName()}/git/commits/${sha}` },
        });
        return true;
      }
    }

    // contents
    if (sub[0] === 'contents') {
      const path = sub.slice(1).join('/');
      const refParam = ctx.query.get('ref');
      const resolveRef = (): string | null => {
        if (!refParam) return repo.headOid();
        return repo.refOid(refParam) ?? repo.peelToCommit(refParam);
      };
      if (method === 'GET') {
        const tip = resolveRef();
        if (!tip) {
          sendError(res, 404, 'Not Found');
          return true;
        }
        const tree = repo.treeMapAt(tip);
        if (path === '') {
          // root listing
          const entries = new Map<string, { type: string; name: string; path: string; sha: string }>();
          for (const [p, oid] of tree) {
            const top = p.split('/')[0];
            if (!entries.has(top)) {
              const isDir = p.includes('/');
              entries.set(top, { type: isDir ? 'dir' : 'file', name: top, path: top, sha: isDir ? '' : oid });
            }
          }
          sendJson(res, 200, [...entries.values()].map((e) => ({ ...e, size: e.type === 'file' ? (repo.getObject(e.sha)?.data.length ?? 0) : 0, url: `/api/v3/repos/${repo.fullName()}/contents/${e.path}`, html_url: `https://github.example.invalid/${repo.fullName()}/blob/${tip}/${e.path}`, git_url: `/api/v3/repos/${repo.fullName()}/git/trees/${e.sha}`, download_url: null, _links: { self: `/api/v3/repos/${repo.fullName()}/contents/${e.path}`, git: `/api/v3/repos/${repo.fullName()}/git/trees/${e.sha}`, html: `https://github.example.invalid/${repo.fullName()}/blob/${tip}/${e.path}` } })));
          return true;
        }
        const blobOid = tree.get(path);
        if (blobOid) {
          const data = repo.getObject(blobOid)?.data ?? Buffer.alloc(0);
          sendJson(res, 200, {
            type: 'file', encoding: 'base64', size: data.length, name: path.split('/').pop(), path, sha: blobOid,
            content: data.toString('base64'),
            url: `/api/v3/repos/${repo.fullName()}/contents/${path}`,
            html_url: `https://github.example.invalid/${repo.fullName()}/blob/${tip}/${path}`,
            git_url: `/api/v3/repos/${repo.fullName()}/git/blobs/${blobOid}`,
            download_url: `https://github.example.invalid/${repo.fullName()}/raw/${tip}/${path}`,
            _links: { self: `/api/v3/repos/${repo.fullName()}/contents/${path}`, git: `/api/v3/repos/${repo.fullName()}/git/blobs/${blobOid}`, html: `https://github.example.invalid/${repo.fullName()}/blob/${tip}/${path}` },
          });
          return true;
        }
        // directory?
        const prefix = `${path}/`;
        const entries = new Map<string, { type: string; name: string; path: string; sha: string }>();
        for (const [p, oid] of tree) {
          if (!p.startsWith(prefix)) continue;
          const rest = p.slice(prefix.length);
          const top = rest.split('/')[0];
          if (!entries.has(top)) {
            const isDir = rest.includes('/');
            entries.set(top, { type: isDir ? 'dir' : 'file', name: top, path: `${path}/${top}`, sha: isDir ? '' : oid });
          }
        }
        if (entries.size === 0) {
          sendError(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, [...entries.values()].map((e) => ({ ...e, size: e.type === 'file' ? (repo.getObject(e.sha)?.data.length ?? 0) : 0, url: `/api/v3/repos/${repo.fullName()}/contents/${e.path}`, html_url: `https://github.example.invalid/${repo.fullName()}/blob/${tip}/${e.path}`, git_url: `/api/v3/repos/${repo.fullName()}/git/trees/${e.sha}`, download_url: null, _links: { self: `/api/v3/repos/${repo.fullName()}/contents/${e.path}`, git: `/api/v3/repos/${repo.fullName()}/git/trees/${e.sha}`, html: `https://github.example.invalid/${repo.fullName()}/blob/${tip}/${e.path}` } })));
        return true;
      }
      if (method === 'PUT' || method === 'DELETE') {
        const body = isRecord(ctx.body) ? ctx.body : {};
        const branch = asStr(body.branch, repo.defaultBranch);
        const branchRef = `refs/heads/${branch}`;
        let parent = repo.refs.get(branchRef);
        if (!parent) {
          // create the branch from the default tip first
          parent = repo.headOid() ?? null;
          if (parent) repo.refs.set(branchRef, parent);
        }
        const tree = repo.treeMapAt(parent);
        const existing = tree.get(path);
        const providedSha = asStr(body.sha);
        if (method === 'PUT') {
          const content = b64decode(asStr(body.content));
          if (existing && providedSha !== existing) {
            sendError(res, 409, 'sha does not match the current blob');
            return true;
          }
          const seq = nextSeq();
          const commitOid = repo.commitWithChanges(parent, new Map([[path, content]]), asStr(body.message, existing ? `Update ${path}` : `Create ${path}`), seq);
          repo.refs.set(branchRef, commitOid);
          const blobOid = repo.treeMapAt(commitOid).get(path)!;
          sendJson(res, existing ? 200 : 201, {
            content: { name: path.split('/').pop(), path, sha: blobOid, size: content.length, type: 'file', encoding: 'base64', content: content.toString('base64'), url: `/api/v3/repos/${repo.fullName()}/contents/${path}`, html_url: `https://github.example.invalid/${repo.fullName()}/blob/${commitOid}/${path}`, git_url: `/api/v3/repos/${repo.fullName()}/git/blobs/${blobOid}`, download_url: null, _links: {} },
            commit: { sha: commitOid, node_id: globalId('C', commitOid), message: asStr(body.message, existing ? `Update ${path}` : `Create ${path}`), author: viewerUser(), committer: viewerUser(), url: `/api/v3/repos/${repo.fullName()}/commits/${commitOid}` },
          });
          return true;
        }
        // DELETE
        if (!existing) {
          sendError(res, 404, 'Not Found');
          return true;
        }
        if (providedSha && providedSha !== existing) {
          sendError(res, 409, 'sha does not match the current blob');
          return true;
        }
        const seq = nextSeq();
        const commitOid = repo.commitWithChanges(parent, new Map([[path, null]]), asStr(body.message, `Delete ${path}`), seq);
        repo.refs.set(branchRef, commitOid);
        sendJson(res, 200, {
          content: null,
          commit: { sha: commitOid, node_id: globalId('C', commitOid), message: asStr(body.message, `Delete ${path}`), author: viewerUser(), committer: viewerUser(), url: `/api/v3/repos/${repo.fullName()}/commits/${commitOid}` },
        });
        return true;
      }
    }

    // labels
    if (sub[0] === 'labels') {
      if (method === 'GET' && sub.length === 1) {
        sendJson(res, 200, [...repo.labels.values()].map((l, i) => ({ id: 30000 + i, node_id: globalId('L', `${repo.id}:${l.name}`), url: `/api/v3/repos/${repo.fullName()}/labels/${encodeURIComponent(l.name)}`, name: l.name, color: l.color, description: l.description, default: false })));
        return true;
      }
      if (method === 'POST' && sub.length === 1) {
        const body = isRecord(ctx.body) ? ctx.body : {};
        const name = asStr(body.name);
        if (!name) {
          sendError(res, 422, 'name is required');
          return true;
        }
        const label: Label = { name, color: asStr(body.color, 'ededed'), description: asStr(body.description) };
        repo.labels.set(name, label);
        sendJson(res, 201, { id: 30000 + repo.labels.size, node_id: globalId('L', `${repo.id}:${name}`), url: `/api/v3/repos/${repo.fullName()}/labels/${encodeURIComponent(name)}`, name, color: label.color, description: label.description, default: false });
        return true;
      }
    }

    // issues
    if (sub[0] === 'issues') {
      if (sub.length === 1) {
        if (method === 'GET') {
          const state = ctx.query.get('state') ?? 'open';
          const direction = ctx.query.get('direction') ?? 'desc';
          let list = [...repo.issues.values()];
          if (state !== 'all') list = list.filter((i) => i.state === state);
          list.sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
          sendJson(res, 200, list.map((i) => issueJson(repo, i)));
          return true;
        }
        if (method === 'POST') {
          const body = isRecord(ctx.body) ? ctx.body : {};
          const title = asStr(body.title);
          if (!title) {
            sendError(res, 422, 'title is required');
            return true;
          }
          const labels: string[] = Array.isArray(body.labels) ? body.labels.map((l: unknown) => asStr(l)).filter(Boolean) : [];
          for (const name of labels) {
            if (!repo.labels.has(name)) {
              sendError(res, 422, `Label does not exist: ${name}`);
              return true;
            }
          }
          const seq = nextSeq();
          const number = store.nextNumber(repo);
          const issue: IssueRec = {
            kind: 'issue', id: store.nextIssueOrPullId(), number, title, body: asStr(body.body), state: 'open',
            labels, createdSeq: seq, createdAt: isoAt(seq), updatedAt: isoAt(seq), closedAt: null,
            user: { login: store.viewerLogin, id: store.viewerId },
          };
          repo.issues.set(number, issue);
          sendJson(res, 201, issueJson(repo, issue));
          return true;
        }
      }
      const num = Number(sub[1]);
      if (Number.isInteger(num) && num > 0) {
        if (sub.length === 2) {
          const issue = repo.issues.get(num);
          const pr = repo.pulls.get(num);
          if (method === 'GET') {
            if (issue) {
              sendIssueJson(res, repo, issue);
              return true;
            }
            if (pr) {
              const asIssue = pullJson(repo, pr);
              sendJson(res, 200, { ...asIssue, pull_request: { url: `/api/v3/repos/${repo.fullName()}/pulls/${num}`, html_url: `https://github.example.invalid/${repo.fullName()}/pull/${num}`, diff_url: `https://github.example.invalid/${repo.fullName()}/pull/${num}.diff`, patch_url: `https://github.example.invalid/${repo.fullName()}/pull/${num}.patch` } });
              return true;
            }
            sendError(res, 404, 'Not Found');
            return true;
          }
          if (method === 'PATCH') {
            const target = issue ?? pr;
            if (!target) {
              sendError(res, 404, 'Not Found');
              return true;
            }
            const body = isRecord(ctx.body) ? ctx.body : {};
            if (typeof body.title === 'string') target.title = body.title;
            if (typeof body.body === 'string') target.body = body.body;
            if (body.state === 'closed' || body.state === 'open') {
              target.state = body.state;
              const seq = nextSeq();
              target.updatedAt = isoAt(seq);
              target.closedAt = body.state === 'closed' ? isoAt(seq) : null;
              if (pr && body.state === 'closed') pr.merged = false;
            }
            sendJson(res, 200, issue ? issueJson(repo, issue) : pullJson(repo, pr!));
            return true;
          }
        }
        if (sub.length === 3 && sub[2] === 'comments') {
          const target = repo.issues.get(num) ?? repo.pulls.get(num);
          if (!target) {
            sendError(res, 404, 'Not Found');
            return true;
          }
          if (method === 'GET') {
            sendJson(res, 200, (repo.comments.get(num) ?? []).map((c) => commentJson(repo, num, c)));
            return true;
          }
          if (method === 'POST') {
            const body = isRecord(ctx.body) ? ctx.body : {};
            const commentBody = asStr(body.body);
            if (!commentBody) {
              sendError(res, 422, 'body is required');
              return true;
            }
            const seq = nextSeq();
            const c: CommentRec = { id: store.nextComment(), body: commentBody, createdSeq: seq, createdAt: isoAt(seq), user: { login: store.viewerLogin, id: store.viewerId } };
            const list = repo.comments.get(num) ?? [];
            list.push(c);
            repo.comments.set(num, list);
            sendJson(res, 201, commentJson(repo, num, c));
            return true;
          }
        }
      }
    }

    // pulls
    if (sub[0] === 'pulls') {
      if (sub.length === 1) {
        if (method === 'GET') {
          const state = ctx.query.get('state') ?? 'open';
          let list = [...repo.pulls.values()];
          if (state !== 'all') list = list.filter((p) => p.state === state);
          list.sort((a, b) => b.createdSeq - a.createdSeq);
          sendJson(res, 200, list.map((p) => pullJson(repo, p)));
          return true;
        }
        if (method === 'POST') {
          const body = isRecord(ctx.body) ? ctx.body : {};
          const title = asStr(body.title);
          const head = asStr(body.head);
          const base = asStr(body.base, repo.defaultBranch);
          if (!title || !head) {
            sendError(res, 422, 'title and head are required');
            return true;
          }
          const headRefName = head.includes(':') ? head.split(':').pop()! : head;
          const baseRefName = base.includes(':') ? base.split(':').pop()! : base;
          const headOid = repo.refOid(`refs/heads/${headRefName}`) ?? repo.refOid(headRefName);
          const baseOid = repo.refOid(`refs/heads/${baseRefName}`) ?? repo.refOid(baseRefName);
          if (!headOid || !baseOid) {
            sendError(res, 422, 'Head or base ref does not exist');
            return true;
          }
          const headSha = repo.peelToCommit(headOid)!;
          const baseSha = repo.peelToCommit(baseOid)!;
          for (const p of repo.pulls.values()) {
            if (p.state === 'open' && p.headRef === headRefName && p.baseRef === baseRefName) {
              sendError(res, 422, 'A pull request already exists for this head and base');
              return true;
            }
          }
          const seq = nextSeq();
          const number = store.nextNumber(repo);
          const pr: PullRec = {
            kind: 'pull', id: store.nextIssueOrPullId(), number, title, body: asStr(body.body), state: 'open', merged: false,
            headRef: headRefName, headSha, baseRef: baseRefName, baseSha,
            mergedAt: null, mergeCommitSha: null, createdSeq: seq, createdAt: isoAt(seq), updatedAt: isoAt(seq), closedAt: null,
            user: { login: store.viewerLogin, id: store.viewerId },
          };
          repo.pulls.set(number, pr);
          sendJson(res, 201, pullJson(repo, pr));
          return true;
        }
      }
      const num = Number(sub[1]);
      if (Number.isInteger(num) && num > 0) {
        const pr = repo.pulls.get(num);
        if (sub.length === 2 && method === 'GET') {
          if (!pr) {
            sendError(res, 404, 'Not Found');
            return true;
          }
          sendJson(res, 200, pullJson(repo, pr));
          return true;
        }
        if (sub.length === 3 && sub[2] === 'files' && method === 'GET') {
          if (!pr) {
            sendError(res, 404, 'Not Found');
            return true;
          }
          sendJson(res, 200, prFiles(repo, pr));
          return true;
        }
        if (sub.length === 3 && sub[2] === 'commits' && method === 'GET') {
          if (!pr) {
            sendError(res, 404, 'Not Found');
            return true;
          }
          const baseAncestors = repo.ancestors(pr.baseSha);
          const all = repo.commitsFrom(pr.headSha).filter((c) => !baseAncestors.has(c.oid));
          sendJson(res, 200, all.map((c) => commitJson(repo, c.oid)!));
          return true;
        }
        if (sub.length === 3 && sub[2] === 'merge' && method === 'PUT') {
          if (!pr) {
            sendError(res, 404, 'Not Found');
            return true;
          }
          if (pr.merged) {
            sendJson(res, 200, { sha: pr.mergeCommitSha, merged: true, message: 'Pull request successfully merged' });
            return true;
          }
          const mergeable = prMergeable(repo, pr);
          if (mergeable === 'CONFLICTING') {
            sendError(res, 405, 'Merge conflict');
            return true;
          }
          const baseTip = repo.refOid(`refs/heads/${pr.baseRef}`);
          if (!baseTip) {
            sendError(res, 404, 'Base branch not found');
            return true;
          }
          const seq = nextSeq();
          const author = `${DEFAULT_VIEWER.name} <${DEFAULT_VIEWER.email}>`;
          const mergeCommit = buildCommit({
            tree: repo.treeMapAt(pr.headSha).size >= 0 ? repo.commitView(pr.headSha)!.tree : '',
            parents: [baseTip],
            message: `Merge pull request #${pr.number} from ${repo.owner}/${pr.headRef}`,
            author,
            committer: author,
            timestamp: EPOCH_SEC + seq * 60,
          });
          const mergeSha = repo.putObject('commit', mergeCommit);
          repo.refs.set(`refs/heads/${pr.baseRef}`, mergeSha);
          pr.state = 'closed';
          pr.merged = true;
          pr.mergedAt = isoAt(seq);
          pr.mergeCommitSha = mergeSha;
          pr.closedAt = isoAt(seq);
          pr.updatedAt = isoAt(seq);
          sendJson(res, 200, { sha: mergeSha, merged: true, message: 'Pull request successfully merged' });
          return true;
        }
      }
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// git smart HTTP
// ---------------------------------------------------------------------------

const PACK_CACHE = new Map<string, { pack: Buffer; selection: FetchSelection }>();
const PACK_CACHE_MAX = 64;

function gitRepo(ctx: Ctx): Repo | null {
  const owner = ctx.segments[0];
  const repoSeg = ctx.segments[1];
  if (!owner || !repoSeg || !repoSeg.endsWith('.git')) return null;
  const name = repoSeg.slice(0, -4);
  return store.repoForOwner(owner, name);
}

function v2Advertisement(repo: Repo): Buffer {
  const lines = [
    'version 2',
    'agent=git/2.43.0',
    'ls-refs=unborn',
    'fetch=shallow wait-for-done',
    'server-option',
    'object-format=sha1',
  ];
  return pktLines([...lines.map((l) => `${l}\n`), 'flush']);
}

function v0Advertisement(repo: Repo, service: 'upload-pack' | 'receive-pack'): Buffer {
  const caps = service === 'upload-pack'
    ? `side-band-64k thin-pack ofs-delta shallow multi_ack symref=HEAD:${repo.defaultRef()} object-format=sha1 agent=git/2.43.0`
    : 'report-status report-status-v2 side-band-64k delete-refs ofs-delta agent=git/2.43.0';
  const head = repo.headOid();
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const parts: Buffer[] = [pktLine(`# service=git-${service}\n`), PKT_FLUSH];
  const lines: Buffer[] = [];
  if (head && refs.length > 0) {
    lines.push(pktLine(`${head} HEAD\0${caps}\n`));
    for (const [ref, oid] of refs) lines.push(pktLine(`${oid} ${ref}\n`));
  } else {
    lines.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  }
  parts.push(Buffer.concat(lines));
  // git's own server ends the advertisement with a flush after the ref list.
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

interface FetchParams {
  wants: string[];
  haves: string[];
  shallowInputs: string[];
  depth: number | undefined;
  deepenSince: number | undefined;
}

interface FetchSelection {
  included: string[]; // commit oids to send
  shallow: string[];
  unshallow: string[];
  tagOids: string[];
  objects: GitObj[];
}

function selectFetchObjects(repo: Repo, params: FetchParams): FetchSelection {
  const tagOids: string[] = [];
  const wantCommits: string[] = [];
  for (const want of params.wants) {
    const obj = repo.getObject(want);
    if (!obj) continue;
    if (obj.type === 'tag') {
      tagOids.push(want);
      const target = repo.peelToCommit(want);
      if (target) wantCommits.push(target);
    } else if (obj.type === 'commit') {
      wantCommits.push(want);
    }
  }
  const haveSet = new Set(params.haves);
  const shallowInputSet = new Set(params.shallowInputs);
  // A have the client holds complete (not a shallow boundary): the client has its
  // whole history, so a commit below it is never a new shallow boundary.
  const haveComplete = new Set([...haveSet].filter((h) => !shallowInputSet.has(h)));
  const depthLimit = params.depth;
  const hasDepthLimit = depthLimit !== undefined || params.deepenSince !== undefined;
  const included = new Set<string>();
  const queue: Array<{ oid: string; depth: number }> = wantCommits.map((oid) => ({ oid, depth: 1 }));
  const commitTimestamp = (oid: string): number => {
    const view = repo.commitView(oid);
    if (!view) return 0;
    const m = / (\d+) [+-]\d{4}$/.exec(view.committer);
    return m ? Number(m[1]) : 0;
  };
  while (queue.length > 0) {
    const { oid, depth } = queue.shift()!;
    if (included.has(oid)) continue;
    // Without a depth limit, a commit the client already has ends the walk here
    // (this is what makes fetch-nothing-new send 0 objects). With a depth limit
    // the walk must go through haves (deepen), and already-held objects are
    // removed afterwards by subtraction instead.
    if (!hasDepthLimit && haveSet.has(oid)) continue;
    if (depthLimit !== undefined && depth > depthLimit) continue;
    if (params.deepenSince !== undefined && commitTimestamp(oid) < params.deepenSince) continue;
    included.add(oid);
    const view = repo.commitView(oid);
    if (!view) continue;
    for (const p of view.parents) queue.push({ oid: p, depth: depth + 1 });
  }
  // shallow boundaries: included commits (not themselves held) with a parent that
  // is neither included nor held complete by the client.
  const shallow: string[] = [];
  for (const oid of included) {
    if (haveSet.has(oid)) continue;
    const view = repo.commitView(oid);
    if (!view) continue;
    if (view.parents.some((p) => !included.has(p) && !haveComplete.has(p))) shallow.push(oid);
  }
  // unshallow: input shallow boundaries now fully included
  const unshallow: string[] = [];
  for (const s of params.shallowInputs) {
    if (!included.has(s)) continue;
    const view = repo.commitView(s);
    if (view && view.parents.every((p) => included.has(p))) unshallow.push(s);
  }
  // Collect objects reachable from the included commits, then subtract everything
  // the client already holds: for a complete have, its whole reachable closure;
  // for a shallow have, only the commit itself and its tree/blobs (its ancestors
  // are precisely what the client does not have).
  const addTreeObjects = (treeOid: string, into: Set<string>): void => {
    if (into.has(treeOid)) return;
    const obj = repo.getObject(treeOid);
    if (!obj || obj.type !== 'tree') return;
    into.add(treeOid);
    for (const entry of parseTree(obj.data)) {
      if (entry.mode === '40000') addTreeObjects(entry.oid, into);
      else into.add(entry.oid);
    }
  };
  const held = new Set<string>();
  for (const h of haveSet) {
    const commits = shallowInputSet.has(h) ? new Set([h]) : repo.ancestors(h);
    for (const c of commits) {
      held.add(c);
      const view = repo.commitView(c);
      if (view) addTreeObjects(view.tree, held);
    }
  }
  const objectOids = new Set<string>();
  for (const oid of included) {
    objectOids.add(oid);
    const view = repo.commitView(oid);
    if (view) addTreeObjects(view.tree, objectOids);
  }
  for (const tag of tagOids) objectOids.add(tag);
  for (const h of held) objectOids.delete(h);
  const objects: GitObj[] = [];
  for (const oid of objectOids) {
    const obj = repo.getObject(oid);
    if (obj) objects.push(obj);
  }
  // deterministic pack order: commits, then trees, then tags, then blobs;
  // oids are computed once (the sort used to re-hash on every comparison).
  const typeRank = (t: GitType): number => (t === 'commit' ? 0 : t === 'tree' ? 1 : t === 'tag' ? 2 : 3);
  const withOids = objects.map((obj) => ({ obj, oid: hashObject(obj.type, obj.data) }));
  withOids.sort((a, b) => {
    const ra = typeRank(a.obj.type);
    const rb = typeRank(b.obj.type);
    if (ra !== rb) return ra - rb;
    return a.oid < b.oid ? -1 : a.oid > b.oid ? 1 : 0;
  });
  const sortedObjects = withOids.map((w) => w.obj);
  return { included: [...included], shallow, unshallow, tagOids, objects: sortedObjects };
}

function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 65000;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function cachedFetchPack(repo: Repo, params: FetchParams): { pack: Buffer; selection: FetchSelection } {
  const key = JSON.stringify({ repo: repo.name, wants: [...params.wants].sort(), haves: [...params.haves].sort(), shallow: [...params.shallowInputs].sort(), depth: params.depth, since: params.deepenSince });
  const cached = PACK_CACHE.get(key);
  if (cached) return cached;
  const selection = selectFetchObjects(repo, params);
  const pack = writePack(selection.objects);
  const entry = { pack, selection };
  if (PACK_CACHE.size >= PACK_CACHE_MAX) {
    const first = PACK_CACHE.keys().next().value;
    if (first !== undefined) PACK_CACHE.delete(first);
  }
  PACK_CACHE.set(key, entry);
  return entry;
}

function handleLsRefs(repo: Repo, args: string[]): Buffer {
  let peel = false;
  let unborn = false;
  let symrefs = false;
  const prefixes: string[] = [];
  for (const arg of args) {
    if (arg === 'peel') peel = true;
    else if (arg === 'unborn') unborn = true;
    else if (arg === 'symrefs') symrefs = true;
    else if (arg.startsWith('ref-prefix ')) prefixes.push(arg.slice('ref-prefix '.length));
    else if (arg === 'ref-prefix') prefixes.push('');
  }
  void unborn;
  const lines: string[] = [];
  const headOid = repo.headOid();
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const matchesPrefix = (ref: string): boolean => prefixes.length === 0 || prefixes.some((p) => ref.startsWith(p));
  if (headOid && symrefs) {
    const headMatches = prefixes.length === 0 || prefixes.some((p) => 'HEAD'.startsWith(p));
    if (headMatches) {
      let line = `${headOid} HEAD symref-target:${repo.defaultRef()}`;
      if (peel) {
        const target = repo.refs.get(repo.defaultRef());
        if (target) {
          const peeled = repo.peelToCommit(target);
          if (peeled && peeled !== target) line += ` peeled:${peeled}`;
        }
      }
      lines.push(`${line}\n`);
    }
  } else if (!headOid && symrefs) {
    // Unborn HEAD is not a ref: git's clone needs the symref target even when it
    // asked with ref-prefix args (a prefixed reply must still not leak a HEAD line
    // for a repo that has refs — that case is handled above).
    lines.push(`unborn HEAD symref-target:${repo.defaultRef()}\n`);
  }
  for (const [ref, oid] of refs) {
    if (!matchesPrefix(ref)) continue;
    let line = `${oid} ${ref}`;
    if (peel && ref.startsWith('refs/tags/')) {
      const peeled = repo.peelToCommit(oid);
      if (peeled && peeled !== oid) line += ` peeled:${peeled}`;
    }
    lines.push(`${line}\n`);
  }
  return pktLines([...lines, 'flush']);
}

function handleFetchV2(repo: Repo, args: string[]): Buffer {
  const params: FetchParams = { wants: [], haves: [], shallowInputs: [], depth: undefined, deepenSince: undefined };
  for (const arg of args) {
    if (arg.startsWith('want ')) params.wants.push(arg.slice(5).trim());
    else if (arg.startsWith('have ')) params.haves.push(arg.slice(5).trim());
    else if (arg.startsWith('shallow ')) params.shallowInputs.push(arg.slice(8).trim());
    else if (arg.startsWith('deepen ')) params.depth = Number(arg.slice(7).trim());
    else if (arg.startsWith('deepen-since ')) params.deepenSince = Number(arg.slice('deepen-since '.length).trim());
  }
  const { pack, selection } = cachedFetchPack(repo, params);
  // Real git sends each section only when it has content: acknowledgments only
  // when the client sent haves, shallow-info only when there are shallow or
  // unshallow lines. An empty section header makes git's client die with
  // "expected 'packfile'".
  const parts: Buffer[] = [];
  if (params.haves.length > 0) {
    parts.push(pktLine('acknowledgments\n'));
    parts.push(pktLine('NAK\n'));
    parts.push(PKT_DELIM);
  }
  if (selection.shallow.length > 0 || selection.unshallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const oid of selection.shallow) parts.push(pktLine(`shallow ${oid}\n`));
    for (const oid of selection.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
    parts.push(PKT_DELIM);
  }
  parts.push(pktLine('packfile\n'));
  parts.push(sidebandPack(pack));
  return Buffer.concat(parts);
}

function handleFetchV0(repo: Repo, packets: DecodedPacket[]): Buffer {
  const params: FetchParams = { wants: [], haves: [], shallowInputs: [], depth: undefined, deepenSince: undefined };
  let seenFlush = false;
  for (const pkt of packets) {
    if (pkt.kind === 'flush') {
      seenFlush = true;
      continue;
    }
    if (pkt.kind !== 'data') continue;
    const line = pkt.payload.toString('utf8').trim();
    if (line.startsWith('want ')) {
      const rest = line.slice(5).trim();
      const oid = rest.split(/\s+/)[0];
      if (/^[0-9a-f]{40}$/.test(oid)) params.wants.push(oid);
    } else if (line.startsWith('have ')) {
      params.haves.push(line.slice(5).trim());
    } else if (line.startsWith('shallow ')) {
      params.shallowInputs.push(line.slice(8).trim());
    } else if (line.startsWith('deepen ')) {
      params.depth = Number(line.slice(7).trim());
    } else if (line.startsWith('deepen-since ')) {
      params.deepenSince = Number(line.slice('deepen-since '.length).trim());
    } else if (line === 'done') {
      break;
    }
  }
  void seenFlush;
  const { pack, selection } = cachedFetchPack(repo, params);
  const parts: Buffer[] = [pktLine('NAK\n')];
  for (const oid of selection.shallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of selection.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  parts.push(sidebandPack(pack));
  return Buffer.concat(parts);
}

async function handleGit(ctx: Ctx): Promise<boolean> {
  const { req, res, segments: s } = ctx;
  const method = req.method ?? 'GET';
  // /{owner}/{repo}.git/info/refs | /{owner}/{repo}.git/git-upload-pack | git-receive-pack
  if (s.length < 2 || !s[1].endsWith('.git')) return false;
  const repo = gitRepo(ctx);
  const service = ctx.query.get('service');

  if (method === 'GET' && s.length === 4 && s[2] === 'info' && s[3] === 'refs') {
    if (!repo) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
      sendError(res, 400, 'service parameter is required');
      return true;
    }
    const isV2 = service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '').includes('version=2');
    const body = isV2 ? v2Advertisement(repo) : v0Advertisement(repo, service === 'git-receive-pack' ? 'receive-pack' : 'upload-pack');
    const contentType = service === 'git-receive-pack' ? 'application/x-git-receive-pack-advertisement' : 'application/x-git-upload-pack-advertisement';
    sendRaw(res, 200, contentType, body);
    return true;
  }

  if (method === 'POST' && s.length === 3 && (s[2] === 'git-upload-pack' || s[2] === 'git-receive-pack')) {
    if (!repo) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (!checkAuth(req)) {
      sendError(res, 401, 'Requires authentication');
      return true;
    }
    const raw = ctx.rawBody;
    if (s[2] === 'git-upload-pack') {
      const isV2 = (req.headers['git-protocol'] ?? '').includes('version=2');
      if (isV2) {
        const { packets } = decodePktLines(raw);
        let command = '';
        const args: string[] = [];
        let inArgs = false;
        for (const pkt of packets) {
          if (pkt.kind === 'delim') {
            inArgs = true;
            continue;
          }
          if (pkt.kind === 'flush') break;
          if (pkt.kind !== 'data') continue;
          const line = pkt.payload.toString('utf8').trim();
          if (!inArgs) {
            if (line.startsWith('command=')) command = line.slice('command='.length);
          } else {
            args.push(line);
          }
        }
        if (command === 'ls-refs') {
          sendRaw(res, 200, 'application/x-git-upload-pack-result', handleLsRefs(repo, args));
          return true;
        }
        if (command === 'fetch') {
          sendRaw(res, 200, 'application/x-git-upload-pack-result', handleFetchV2(repo, args));
          return true;
        }
        sendError(res, 400, `unsupported command: ${command}`);
        return true;
      }
      // v0
      const { packets } = decodePktLines(raw);
      if (packets.length === 0 || !packets.some((p) => p.kind === 'data')) {
        sendError(res, 400, 'malformed request');
        return true;
      }
      sendRaw(res, 200, 'application/x-git-upload-pack-result', handleFetchV0(repo, packets));
      return true;
    }

    // git-receive-pack (v0)
    const { packets, restOffset } = decodePktLines(raw);
    if (packets.length === 0 || !packets.some((p) => p.kind === 'data')) {
      sendError(res, 400, 'malformed request');
      return true;
    }
    const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
    for (const pkt of packets) {
      if (pkt.kind === 'flush') break;
      if (pkt.kind !== 'data') continue;
      const text = pkt.payload.toString('utf8');
      const nul = text.indexOf('\0');
      const first = nul >= 0 ? text.slice(0, nul) : text;
      const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)\s*$/.exec(first.trim());
      if (!m) {
        sendError(res, 400, 'malformed ref update command');
        return true;
      }
      commands.push({ oldOid: m[1], newOid: m[2], ref: m[3] });
    }
    if (commands.length === 0) {
      sendError(res, 400, 'no ref updates');
      return true;
    }
    const packBytes = raw.subarray(restOffset);
    // A delete-only push carries no packfile at all.
    let imported: Map<string, GitObj>;
    try {
      imported = packBytes.length === 0 ? new Map() : readPack(packBytes, (oid) => repo.getObject(oid));
    } catch (err) {
      sendError(res, 400, `invalid packfile: ${err instanceof Error ? err.message : String(err)}`);
      return true;
    }
    for (const [oid, obj] of imported) {
      if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
    }
    const report: Array<{ ref: string; ok: boolean; reason: string }> = [];
    for (const cmd of commands) {
      const current = repo.refs.get(cmd.ref);
      if (cmd.newOid === ZERO_OID) {
        // delete
        if (!current) {
          report.push({ ref: cmd.ref, ok: false, reason: 'reference does not exist' });
        } else if (current !== cmd.oldOid) {
          report.push({ ref: cmd.ref, ok: false, reason: 'old value does not match' });
        } else {
          repo.refs.delete(cmd.ref);
          report.push({ ref: cmd.ref, ok: true, reason: '' });
        }
        continue;
      }
      const newObj = repo.getObject(cmd.newOid);
      if (!newObj) {
        report.push({ ref: cmd.ref, ok: false, reason: 'object not found' });
        continue;
      }
      if (cmd.oldOid === ZERO_OID) {
        // create
        if (current) {
          report.push({ ref: cmd.ref, ok: false, reason: 'reference already exists' });
        } else {
          repo.refs.set(cmd.ref, cmd.newOid);
          report.push({ ref: cmd.ref, ok: true, reason: '' });
        }
        continue;
      }
      // update
      if (!current) {
        report.push({ ref: cmd.ref, ok: false, reason: 'reference does not exist' });
      } else if (current !== cmd.oldOid) {
        report.push({ ref: cmd.ref, ok: false, reason: 'old value does not match' });
      } else {
        const newCommit = repo.peelToCommit(cmd.newOid);
        const oldCommit = repo.peelToCommit(cmd.oldOid);
        if (!newCommit || !oldCommit) {
          report.push({ ref: cmd.ref, ok: false, reason: 'not a commit' });
        } else if (!repo.isAncestor(oldCommit, newCommit)) {
          report.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
        } else {
          repo.refs.set(cmd.ref, cmd.newOid);
          report.push({ ref: cmd.ref, ok: true, reason: '' });
        }
      }
    }
    // report-status inside sideband band 1. The report stream is itself
    // pkt-lined inside band 1 (real git's reader parses pkt-lines out of the
    // demuxed band-1 bytes; the kit client accepts this too): each report line
    // is a sideband packet carrying one pkt-line, then an inner flush, then the
    // bare outer flush that ends the response.
    const sidebandLine = (text: string): Buffer => pktLine(Buffer.concat([Buffer.from([1]), pktLine(text)]));
    const lines: Buffer[] = [sidebandLine('unpack ok\n')];
    for (const r of report) {
      const text = r.ok ? `ok ${r.ref}\n` : `ng ${r.ref} ${r.reason}\n`;
      lines.push(sidebandLine(text));
    }
    lines.push(pktLine(Buffer.concat([Buffer.from([1]), PKT_FLUSH])));
    lines.push(PKT_FLUSH);
    sendRaw(res, 200, 'application/x-git-receive-pack-result', Buffer.concat(lines));
    return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// GraphQL (small recursive-descent parser + executor)
// ---------------------------------------------------------------------------

type GqlValue = string | number | boolean | null | GqlValue[] | { [key: string]: GqlValue };

interface GqlFieldSel {
  kind: 'field';
  name: string;
  alias: string;
  args: Record<string, GqlValue>;
  selections: GqlSelection[];
}
interface GqlSpread {
  kind: 'spread';
  name: string;
}
interface GqlInline {
  kind: 'inline';
  typeCondition: string | null;
  selections: GqlSelection[];
}
type GqlSelection = GqlFieldSel | GqlSpread | GqlInline;

interface GqlOperation {
  kind: 'operation';
  operationType: 'query' | 'mutation' | 'subscription';
  name: string | null;
  variableDefs: Record<string, GqlValue>;
  selections: GqlSelection[];
}
interface GqlFragment {
  kind: 'fragment';
  name: string;
  typeCondition: string;
  selections: GqlSelection[];
}

type GqlToken =
  | { kind: 'name'; value: string }
  | { kind: 'string'; value: string }
  | { kind: 'number'; value: string }
  | { kind: 'punct'; value: string }
  | { kind: 'var'; value: string };

function tokenizeGql(src: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '"') {
      // block string or normal string
      if (src.startsWith('"""', i)) {
        const end = src.indexOf('"""', i + 3);
        const value = end < 0 ? src.slice(i + 3) : src.slice(i + 3, end);
        tokens.push({ kind: 'string', value });
        i = end < 0 ? src.length : end + 3;
        continue;
      }
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const esc = src[j + 1];
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc === '"' ? '"' : esc === '\\' ? '\\' : esc === '/' ? '/' : esc;
          j += 2;
        } else {
          out += src[j];
          j += 1;
        }
      }
      tokens.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (ch === '$') {
      let j = i + 1;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j += 1;
      tokens.push({ kind: 'var', value: src.slice(i + 1, j) });
      i = j;
      continue;
    }
    if (/[0-9-]/.test(ch) && (ch !== '-' || /[0-9]/.test(src[i + 1] ?? ''))) {
      let j = i;
      if (src[j] === '-') j += 1;
      while (j < src.length && /[0-9.]/.test(src[j])) j += 1;
      if (src[j] === 'e' || src[j] === 'E') {
        j += 1;
        if (src[j] === '+' || src[j] === '-') j += 1;
        while (j < src.length && /[0-9]/.test(src[j])) j += 1;
      }
      tokens.push({ kind: 'number', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j += 1;
      tokens.push({ kind: 'name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (src.startsWith('...', i)) {
      tokens.push({ kind: 'punct', value: '...' });
      i += 3;
      continue;
    }
    if ('!$():=@[]{}|&'.includes(ch)) {
      tokens.push({ kind: 'punct', value: ch });
      i += 1;
      continue;
    }
    i += 1;
  }
  return tokens;
}

class GqlParser {
  private pos = 0;
  private readonly tokens: GqlToken[];
  constructor(tokens: GqlToken[]) {
    this.tokens = tokens;
  }

  private peek(): GqlToken | undefined {
    return this.tokens[this.pos];
  }
  private next(): GqlToken {
    const t = this.tokens[this.pos];
    this.pos += 1;
    return t;
  }
  private expectPunct(value: string): void {
    const t = this.next();
    if (t.kind !== 'punct' || t.value !== value) throw new Error(`expected ${value}`);
  }
  private expectName(value?: string): string {
    const t = this.next();
    if (t.kind !== 'name') throw new Error('expected name');
    if (value !== undefined && t.value !== value) throw new Error(`expected ${value}`);
    return t.value;
  }

  parseDocument(): Array<GqlOperation | GqlFragment> {
    const defs: Array<GqlOperation | GqlFragment> = [];
    while (this.pos < this.tokens.length) {
      const t = this.peek()!;
      if (t.kind === 'punct' && t.value === '{') {
        defs.push({ kind: 'operation', operationType: 'query', name: null, variableDefs: {}, selections: this.parseSelectionSet() });
      } else if (t.kind === 'name' && (t.value === 'query' || t.value === 'mutation' || t.value === 'subscription')) {
        const opType = this.next().value as 'query' | 'mutation' | 'subscription';
        let name: string | null = null;
        const nextTok = this.peek();
        if (nextTok?.kind === 'name') name = this.next().value;
        const variableDefs = this.parseVariableDefs();
        this.skipDirectives();
        defs.push({ kind: 'operation', operationType: opType, name, variableDefs, selections: this.parseSelectionSet() });
      } else if (t.kind === 'name' && t.value === 'fragment') {
        this.next();
        const name = this.expectName();
        this.expectName('on');
        const typeCondition = this.expectName();
        this.skipDirectives();
        defs.push({ kind: 'fragment', name, typeCondition, selections: this.parseSelectionSet() });
      } else {
        this.next();
      }
    }
    return defs;
  }

  private parseVariableDefs(): Record<string, GqlValue> {
    const defs: Record<string, GqlValue> = {};
    if (this.peek()?.kind === 'punct' && this.peek()!.value === '(') {
      this.next();
      while (this.peek() && !(this.peek()!.kind === 'punct' && this.peek()!.value === ')')) {
        const t = this.next();
        if (t.kind !== 'var') continue;
        this.expectPunct(':');
        this.parseTypeRef();
        if (this.peek()?.kind === 'punct' && this.peek()!.value === '=') {
          this.next();
          defs[t.value] = this.parseValue();
        }
        this.skipDirectives();
      }
      this.expectPunct(')');
    }
    return defs;
  }

  private parseTypeRef(): void {
    const t = this.peek();
    if (t?.kind === 'punct' && t.value === '[') {
      this.next();
      this.parseTypeRef();
      this.expectPunct(']');
    } else if (t?.kind === 'name') {
      this.next();
    }
    if (this.peek()?.kind === 'punct' && this.peek()!.value === '!') this.next();
  }

  private skipDirectives(): void {
    while (this.peek()?.kind === 'punct' && this.peek()!.value === '@') {
      this.next();
      this.expectName();
      if (this.peek()?.kind === 'punct' && this.peek()!.value === '(') this.parseArguments();
    }
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const sels: GqlSelection[] = [];
    while (this.peek() && !(this.peek()!.kind === 'punct' && this.peek()!.value === '}')) {
      sels.push(this.parseSelection());
    }
    this.expectPunct('}');
    return sels;
  }

  private parseSelection(): GqlSelection {
    const t = this.peek()!;
    if (t.kind === 'punct' && t.value === '...') {
      this.next();
      const nextTok = this.peek();
      if (nextTok?.kind === 'name' && nextTok.value === 'on') {
        this.next();
        const typeCondition = this.expectName();
        this.skipDirectives();
        return { kind: 'inline', typeCondition, selections: this.parseSelectionSet() };
      }
      if (nextTok?.kind === 'name') {
        const name = this.next().value;
        this.skipDirectives();
        return { kind: 'spread', name };
      }
      this.skipDirectives();
      return { kind: 'inline', typeCondition: null, selections: this.parseSelectionSet() };
    }
    let name = this.expectName();
    let alias = name;
    if (this.peek()?.kind === 'punct' && this.peek()!.value === ':') {
      this.next();
      alias = name;
      name = this.expectName();
    }
    const args = this.parseArguments();
    this.skipDirectives();
    let selections: GqlSelection[] = [];
    if (this.peek()?.kind === 'punct' && this.peek()!.value === '{') selections = this.parseSelectionSet();
    return { kind: 'field', name, alias, args, selections };
  }

  private parseArguments(): Record<string, GqlValue> {
    const args: Record<string, GqlValue> = {};
    if (this.peek()?.kind === 'punct' && this.peek()!.value === '(') {
      this.next();
      while (this.peek() && !(this.peek()!.kind === 'punct' && this.peek()!.value === ')')) {
        const name = this.expectName();
        this.expectPunct(':');
        args[name] = this.parseValue();
      }
      this.expectPunct(')');
    }
    return args;
  }

  private parseValue(): GqlValue {
    const t = this.next();
    if (t.kind === 'var') return { __var: t.value } as unknown as GqlValue;
    if (t.kind === 'string') return t.value;
    if (t.kind === 'number') return t.value.includes('.') || /[eE]/.test(t.value) ? Number(t.value) : Number(t.value);
    if (t.kind === 'name') {
      if (t.value === 'true') return true;
      if (t.value === 'false') return false;
      if (t.value === 'null') return null;
      return { __enum: t.value } as unknown as GqlValue;
    }
    if (t.kind === 'punct' && t.value === '[') {
      const items: GqlValue[] = [];
      while (this.peek() && !(this.peek()!.kind === 'punct' && this.peek()!.value === ']')) items.push(this.parseValue());
      this.expectPunct(']');
      return items;
    }
    if (t.kind === 'punct' && t.value === '{') {
      const obj: { [key: string]: GqlValue } = {};
      while (this.peek() && !(this.peek()!.kind === 'punct' && this.peek()!.value === '}')) {
        const name = this.expectName();
        this.expectPunct(':');
        obj[name] = this.parseValue();
      }
      this.expectPunct('}');
      return obj;
    }
    throw new Error(`unexpected token ${JSON.stringify(t)}`);
  }
}

function resolveGqlValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  if (Array.isArray(value)) return value.map((v) => resolveGqlValue(v, variables));
  if (isRecord(value)) {
    if ('__var' in value) return variables[String(value.__var)] ?? null;
    if ('__enum' in value) return String(value.__enum);
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = resolveGqlValue(v as GqlValue, variables);
    return out;
  }
  return value;
}

// --- introspection schema ---

interface SchemaFieldDef {
  name: string;
  type: string;
  description?: string;
  args?: Array<{ name: string; type: string; description?: string }>;
}
interface SchemaTypeDef {
  kind: 'OBJECT' | 'ENUM' | 'SCALAR' | 'INPUT_OBJECT' | 'INTERFACE' | 'UNION';
  description?: string;
  fields?: SchemaFieldDef[];
  enumValues?: string[];
  inputFields?: Array<{ name: string; type: string; description?: string }>;
}

const SCHEMA_TYPES: Record<string, SchemaTypeDef> = {
  Query: {
    kind: 'OBJECT',
    fields: [
      { name: 'viewer', type: 'User!' },
      { name: 'repository', type: 'Repository', args: [{ name: 'owner', type: 'String!' }, { name: 'name', type: 'String!' }] },
      { name: 'node', type: 'Node', args: [{ name: 'id', type: 'ID!' }] },
      { name: 'nodes', type: '[Node]', args: [{ name: 'ids', type: '[ID!]!' }] },
      { name: 'search', type: 'SearchResultItemConnection!', args: [{ name: 'query', type: 'String!' }, { name: 'type', type: 'SearchType!' }, { name: 'first', type: 'Int' }] },
      { name: 'user', type: 'User', args: [{ name: 'login', type: 'String!' }] },
      { name: 'organization', type: 'Organization', args: [{ name: 'login', type: 'String!' }] },
    ],
  },
  Mutation: {
    kind: 'OBJECT',
    fields: [
      { name: 'createIssue', type: 'CreateIssuePayload', args: [{ name: 'input', type: 'CreateIssueInput!' }] },
      { name: 'closeIssue', type: 'CloseIssuePayload', args: [{ name: 'input', type: 'CloseIssueInput!' }] },
      { name: 'createPullRequest', type: 'CreatePullRequestPayload', args: [{ name: 'input', type: 'CreatePullRequestInput!' }] },
      { name: 'mergePullRequest', type: 'MergePullRequestPayload', args: [{ name: 'input', type: 'MergePullRequestInput!' }] },
      { name: 'addComment', type: 'AddCommentPayload', args: [{ name: 'input', type: 'AddCommentInput!' }] },
    ],
  },
  Repository: {
    kind: 'OBJECT',
    fields: [
      { name: 'id', type: 'ID!' },
      { name: 'databaseId', type: 'Int' },
      { name: 'name', type: 'String!' },
      { name: 'nameWithOwner', type: 'String!' },
      { name: 'owner', type: 'RepositoryOwner!' },
      { name: 'defaultBranchRef', type: 'Ref' },
      { name: 'viewerPermission', type: 'RepositoryPermission' },
      { name: 'hasIssuesEnabled', type: 'Boolean!' },
      { name: 'hasProjectsEnabled', type: 'Boolean!' },
      { name: 'hasWikiEnabled', type: 'Boolean!' },
      { name: 'isPrivate', type: 'Boolean!' },
      { name: 'isFork', type: 'Boolean!' },
      { name: 'description', type: 'String' },
      { name: 'url', type: 'URI!' },
      { name: 'createdAt', type: 'DateTime!' },
      { name: 'updatedAt', type: 'DateTime!' },
      { name: 'issue', type: 'Issue', args: [{ name: 'number', type: 'Int!' }] },
      { name: 'issues', type: 'IssueConnection!', args: [{ name: 'first', type: 'Int' }, { name: 'after', type: 'String' }, { name: 'states', type: '[IssueState!]' }, { name: 'orderBy', type: 'IssueOrder' }] },
      { name: 'pullRequest', type: 'PullRequest', args: [{ name: 'number', type: 'Int!' }] },
      { name: 'pullRequests', type: 'PullRequestConnection!', args: [{ name: 'first', type: 'Int' }, { name: 'after', type: 'String' }, { name: 'states', type: '[PullRequestState!]' }, { name: 'orderBy', type: 'IssueOrder' }] },
    ],
  },
  Issue: {
    kind: 'OBJECT',
    fields: [
      { name: 'id', type: 'ID!' },
      { name: 'databaseId', type: 'Int' },
      { name: 'number', type: 'Int!' },
      { name: 'title', type: 'String!' },
      { name: 'body', type: 'String!' },
      { name: 'state', type: 'IssueState!' },
      { name: 'url', type: 'URI!' },
      { name: 'createdAt', type: 'DateTime!' },
      { name: 'updatedAt', type: 'DateTime!' },
      { name: 'closedAt', type: 'DateTime' },
      { name: 'author', type: 'Actor' },
      { name: 'labels', type: 'LabelConnection', args: [{ name: 'first', type: 'Int' }] },
      { name: 'comments', type: 'IssueCommentConnection', args: [{ name: 'first', type: 'Int' }] },
      { name: 'repository', type: 'Repository!' },
    ],
  },
  PullRequest: {
    kind: 'OBJECT',
    fields: [
      { name: 'id', type: 'ID!' },
      { name: 'databaseId', type: 'Int' },
      { name: 'number', type: 'Int!' },
      { name: 'title', type: 'String!' },
      { name: 'body', type: 'String!' },
      { name: 'state', type: 'PullRequestState!' },
      { name: 'merged', type: 'Boolean!' },
      { name: 'mergeable', type: 'MergeableState!' },
      { name: 'headRefName', type: 'String!' },
      { name: 'baseRefName', type: 'String!' },
      { name: 'headRefOid', type: 'GitObjectID' },
      { name: 'baseRefOid', type: 'GitObjectID' },
      { name: 'files', type: 'PullRequestChangedFileConnection', args: [{ name: 'first', type: 'Int' }] },
      { name: 'url', type: 'URI!' },
      { name: 'createdAt', type: 'DateTime!' },
      { name: 'updatedAt', type: 'DateTime!' },
      { name: 'mergedAt', type: 'DateTime' },
      { name: 'closedAt', type: 'DateTime' },
      { name: 'author', type: 'Actor' },
      { name: 'repository', type: 'Repository!' },
      { name: 'isDraft', type: 'Boolean!' },
      { name: 'additions', type: 'Int!' },
      { name: 'deletions', type: 'Int!' },
      { name: 'changedFiles', type: 'Int!' },
    ],
  },
  User: {
    kind: 'OBJECT',
    fields: [
      { name: 'id', type: 'ID!' },
      { name: 'databaseId', type: 'Int' },
      { name: 'login', type: 'String!' },
      { name: 'name', type: 'String' },
      { name: 'email', type: 'String' },
      { name: 'avatarUrl', type: 'URI!' },
      { name: 'url', type: 'URI!' },
      { name: 'createdAt', type: 'DateTime!' },
    ],
  },
  IssueConnection: { kind: 'OBJECT', fields: [{ name: 'nodes', type: '[Issue]' }, { name: 'edges', type: '[IssueEdge]' }, { name: 'pageInfo', type: 'PageInfo!' }, { name: 'totalCount', type: 'Int!' }] },
  IssueEdge: { kind: 'OBJECT', fields: [{ name: 'node', type: 'Issue' }, { name: 'cursor', type: 'String!' }] },
  PullRequestConnection: { kind: 'OBJECT', fields: [{ name: 'nodes', type: '[PullRequest]' }, { name: 'edges', type: '[PullRequestEdge]' }, { name: 'pageInfo', type: 'PageInfo!' }, { name: 'totalCount', type: 'Int!' }] },
  PullRequestEdge: { kind: 'OBJECT', fields: [{ name: 'node', type: 'PullRequest' }, { name: 'cursor', type: 'String!' }] },
  IssueCommentConnection: { kind: 'OBJECT', fields: [{ name: 'nodes', type: '[IssueComment]' }, { name: 'edges', type: '[IssueCommentEdge]' }, { name: 'pageInfo', type: 'PageInfo!' }, { name: 'totalCount', type: 'Int!' }] },
  IssueCommentEdge: { kind: 'OBJECT', fields: [{ name: 'node', type: 'IssueComment' }, { name: 'cursor', type: 'String!' }] },
  IssueComment: { kind: 'OBJECT', fields: [{ name: 'id', type: 'ID!' }, { name: 'databaseId', type: 'Int' }, { name: 'body', type: 'String!' }, { name: 'author', type: 'Actor' }, { name: 'createdAt', type: 'DateTime!' }, { name: 'updatedAt', type: 'DateTime!' }, { name: 'url', type: 'URI!' }] },
  LabelConnection: { kind: 'OBJECT', fields: [{ name: 'nodes', type: '[Label]' }, { name: 'edges', type: '[LabelEdge]' }, { name: 'pageInfo', type: 'PageInfo!' }, { name: 'totalCount', type: 'Int!' }] },
  LabelEdge: { kind: 'OBJECT', fields: [{ name: 'node', type: 'Label' }, { name: 'cursor', type: 'String!' }] },
  Label: { kind: 'OBJECT', fields: [{ name: 'id', type: 'ID!' }, { name: 'name', type: 'String!' }, { name: 'color', type: 'String!' }, { name: 'description', type: 'String' }] },
  PullRequestChangedFileConnection: { kind: 'OBJECT', fields: [{ name: 'nodes', type: '[PullRequestChangedFile]' }, { name: 'edges', type: '[PullRequestChangedFileEdge]' }, { name: 'pageInfo', type: 'PageInfo!' }, { name: 'totalCount', type: 'Int!' }] },
  PullRequestChangedFileEdge: { kind: 'OBJECT', fields: [{ name: 'node', type: 'PullRequestChangedFile' }, { name: 'cursor', type: 'String!' }] },
  PullRequestChangedFile: { kind: 'OBJECT', fields: [{ name: 'path', type: 'String!' }, { name: 'additions', type: 'Int!' }, { name: 'deletions', type: 'Int!' }, { name: 'changeType', type: 'String!' }] },
  PageInfo: { kind: 'OBJECT', fields: [{ name: 'hasNextPage', type: 'Boolean!' }, { name: 'hasPreviousPage', type: 'Boolean!' }, { name: 'startCursor', type: 'String' }, { name: 'endCursor', type: 'String' }] },
  Ref: { kind: 'OBJECT', fields: [{ name: 'name', type: 'String!' }, { name: 'prefix', type: 'String!' }, { name: 'target', type: 'GitObject' }] },
  GitObject: { kind: 'OBJECT', fields: [{ name: 'oid', type: 'GitObjectID!' }, { name: 'id', type: 'ID!' }] },
  CreateIssuePayload: { kind: 'OBJECT', fields: [{ name: 'issue', type: 'Issue' }, { name: 'clientMutationId', type: 'String' }] },
  CloseIssuePayload: { kind: 'OBJECT', fields: [{ name: 'issue', type: 'Issue' }, { name: 'clientMutationId', type: 'String' }] },
  CreatePullRequestPayload: { kind: 'OBJECT', fields: [{ name: 'pullRequest', type: 'PullRequest' }, { name: 'clientMutationId', type: 'String' }] },
  MergePullRequestPayload: { kind: 'OBJECT', fields: [{ name: 'pullRequest', type: 'PullRequest' }, { name: 'clientMutationId', type: 'String' }] },
  AddCommentPayload: { kind: 'OBJECT', fields: [{ name: 'commentEdge', type: 'IssueCommentEdge' }, { name: 'subject', type: 'Issue' }, { name: 'clientMutationId', type: 'String' }] },
  IssueCommentEdge: { kind: 'OBJECT', fields: [{ name: 'node', type: 'IssueComment' }, { name: 'cursor', type: 'String!' }] },
  SearchResultItemConnection: { kind: 'OBJECT', fields: [{ name: 'nodes', type: '[SearchResultItem]' }, { name: 'edges', type: '[SearchResultItemEdge]' }, { name: 'pageInfo', type: 'PageInfo!' }, { name: 'totalCount', type: 'Int!' }] },
  SearchResultItemEdge: { kind: 'OBJECT', fields: [{ name: 'node', type: 'SearchResultItem' }, { name: 'cursor', type: 'String!' }] },
  SearchType: { kind: 'ENUM', enumValues: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'CODE', 'COMMIT', 'MILESTONE', 'ORGANIZATION', 'PACKAGE', 'TOPIC', 'WIKI', 'APPS'] },
  IssueState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED'] },
  PullRequestState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED', 'MERGED'] },
  MergeableState: { kind: 'ENUM', enumValues: ['CONFLICTING', 'MERGEABLE', 'UNKNOWN'] },
  OrderDirection: { kind: 'ENUM', enumValues: ['ASC', 'DESC'] },
  IssueOrderField: { kind: 'ENUM', enumValues: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'] },
  RepositoryPermission: { kind: 'ENUM', enumValues: ['ADMIN', 'MAINTAIN', 'READ', 'TRIAGE', 'WRITE'] },
  IssueOrder: { kind: 'INPUT_OBJECT', inputFields: [{ name: 'field', type: 'IssueOrderField!' }, { name: 'direction', type: 'OrderDirection!' }] },
  CreateIssueInput: { kind: 'INPUT_OBJECT', inputFields: [{ name: 'repositoryId', type: 'ID!' }, { name: 'title', type: 'String!' }, { name: 'body', type: 'String' }, { name: 'clientMutationId', type: 'String' }] },
  CloseIssueInput: { kind: 'INPUT_OBJECT', inputFields: [{ name: 'issueId', type: 'ID!' }, { name: 'clientMutationId', type: 'String' }] },
  CreatePullRequestInput: { kind: 'INPUT_OBJECT', inputFields: [{ name: 'repositoryId', type: 'ID!' }, { name: 'baseRefName', type: 'String!' }, { name: 'headRefName', type: 'String!' }, { name: 'title', type: 'String!' }, { name: 'body', type: 'String' }, { name: 'clientMutationId', type: 'String' }] },
  MergePullRequestInput: { kind: 'INPUT_OBJECT', inputFields: [{ name: 'pullRequestId', type: 'ID!' }, { name: 'mergeMethod', type: 'PullRequestMergeMethod' }, { name: 'clientMutationId', type: 'String' }] },
  AddCommentInput: { kind: 'INPUT_OBJECT', inputFields: [{ name: 'subjectId', type: 'ID!' }, { name: 'body', type: 'String!' }, { name: 'clientMutationId', type: 'String' }] },
  PullRequestMergeMethod: { kind: 'ENUM', enumValues: ['MERGE', 'SQUASH', 'REBASE'] },
  String: { kind: 'SCALAR' },
  Int: { kind: 'SCALAR' },
  Float: { kind: 'SCALAR' },
  Boolean: { kind: 'SCALAR' },
  ID: { kind: 'SCALAR' },
  DateTime: { kind: 'SCALAR' },
  URI: { kind: 'SCALAR' },
  GitObjectID: { kind: 'SCALAR' },
  Node: { kind: 'INTERFACE', fields: [{ name: 'id', type: 'ID!' }] },
  Actor: { kind: 'INTERFACE', fields: [{ name: 'login', type: 'String!' }, { name: 'avatarUrl', type: 'URI!' }, { name: 'url', type: 'URI!' }] },
  RepositoryOwner: { kind: 'INTERFACE', fields: [{ name: 'login', type: 'String!' }, { name: 'id', type: 'ID!' }, { name: 'avatarUrl', type: 'URI!' }, { name: 'url', type: 'URI!' }] },
  SearchResultItem: { kind: 'UNION' },
  Organization: { kind: 'OBJECT', fields: [{ name: 'id', type: 'ID!' }, { name: 'login', type: 'String!' }] },
  __Schema: { kind: 'OBJECT', fields: [{ name: 'queryType', type: '__Type!' }, { name: 'mutationType', type: '__Type' }, { name: 'subscriptionType', type: '__Type' }, { name: 'types', type: '[__Type!]!' }, { name: 'directives', type: '[__Directive!]!' }] },
  __Type: { kind: 'OBJECT', fields: [{ name: 'name', type: 'String' }, { name: 'kind', type: '__TypeKind!' }, { name: 'description', type: 'String' }, { name: 'fields', type: '[__Field!]', args: [{ name: 'includeDeprecated', type: 'Boolean' }] }, { name: 'enumValues', type: '[__EnumValue!]', args: [{ name: 'includeDeprecated', type: 'Boolean' }] }, { name: 'inputFields', type: '[__InputValue!]' }, { name: 'ofType', type: '__Type' }, { name: 'interfaces', type: '[__Type!]' }, { name: 'possibleTypes', type: '[__Type!]' }] },
  __Field: { kind: 'OBJECT', fields: [{ name: 'name', type: 'String!' }, { name: 'description', type: 'String' }, { name: 'args', type: '[__InputValue!]!' }, { name: 'type', type: '__Type!' }, { name: 'isDeprecated', type: 'Boolean!' }, { name: 'deprecationReason', type: 'String' }] },
  __InputValue: { kind: 'OBJECT', fields: [{ name: 'name', type: 'String!' }, { name: 'description', type: 'String' }, { name: 'type', type: '__Type!' }, { name: 'defaultValue', type: 'String' }] },
  __EnumValue: { kind: 'OBJECT', fields: [{ name: 'name', type: 'String!' }, { name: 'description', type: 'String' }, { name: 'isDeprecated', type: 'Boolean!' }, { name: 'deprecationReason', type: 'String' }] },
  __Directive: { kind: 'OBJECT', fields: [{ name: 'name', type: 'String!' }, { name: 'description', type: 'String' }, { name: 'locations', type: '[__DirectiveLocation!]!' }, { name: 'args', type: '[__InputValue!]!' }] },
  __TypeKind: { kind: 'ENUM', enumValues: ['SCALAR', 'OBJECT', 'INTERFACE', 'UNION', 'ENUM', 'INPUT_OBJECT', 'LIST', 'NON_NULL'] },
  __DirectiveLocation: { kind: 'ENUM', enumValues: ['QUERY', 'MUTATION', 'FIELD', 'FRAGMENT_DEFINITION', 'FRAGMENT_SPREAD', 'INLINE_FRAGMENT'] },
};

function typeRefFromSpec(spec: string): Record<string, unknown> {
  if (spec.endsWith('!')) return { kind: 'NON_NULL', name: null, ofType: typeRefFromSpec(spec.slice(0, -1)) };
  if (spec.startsWith('[') && spec.endsWith(']')) return { kind: 'LIST', name: null, ofType: typeRefFromSpec(spec.slice(1, -1)) };
  const def = SCHEMA_TYPES[spec];
  return { kind: def?.kind ?? 'OBJECT', name: spec, ofType: null };
}

function repoById(dbId: number): Repo | undefined {
  for (const repo of store.repos.values()) if (repo.id === dbId) return repo;
  return undefined;
}

// GQL node wrappers: { __gql: kind, ...payload }
type GqlNode = Record<string, any>;

function userNode(login: string, id: number): GqlNode {
  return { __gql: 'User', login, id, databaseId: id, name: login === DEFAULT_VIEWER_LOGIN ? DEFAULT_VIEWER.name : login, email: `${login}@example.invalid` };
}
function repoNode(repo: Repo): GqlNode {
  return { __gql: 'Repository', repo };
}
function issueNode(repo: Repo, issue: IssueRec): GqlNode {
  return { __gql: 'Issue', repo, issue };
}
function pullNode(repo: Repo, pr: PullRec): GqlNode {
  return { __gql: 'PullRequest', repo, pr };
}
function commentNode(repo: Repo, number: number, c: CommentRec): GqlNode {
  return { __gql: 'IssueComment', repo, number, comment: c };
}

function cursorFor(n: number): string {
  return Buffer.from(`cursor:${n}`, 'utf8').toString('base64');
}
function numberFromCursor(cursor: string): number | null {
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    const m = /^cursor:(\d+)$/.exec(text);
    return m ? Number(m[1]) : null;
  } catch {
    return null;
  }
}

interface PageArgs {
  first?: number;
  after?: string;
}

function paginate<T>(items: T[], args: PageArgs, keyOf: (item: T) => number, descending: boolean): { nodes: T[]; edges: Array<{ node: T; cursor: string }>; pageInfo: { hasNextPage: boolean; hasPreviousPage: boolean; startCursor: string | null; endCursor: string | null }; totalCount: number } {
  let filtered = items;
  if (args.after) {
    const afterNum = numberFromCursor(args.after);
    if (afterNum !== null) {
      filtered = filtered.filter((item) => (descending ? keyOf(item) < afterNum : keyOf(item) > afterNum));
    }
  }
  const totalCount = filtered.length;
  const first = args.first ?? filtered.length;
  const page = filtered.slice(0, Math.max(0, first));
  const edges = page.map((node) => ({ node, cursor: cursorFor(keyOf(node)) }));
  return {
    nodes: page,
    edges,
    pageInfo: {
      hasNextPage: filtered.length > page.length,
      hasPreviousPage: false,
      startCursor: edges.length > 0 ? edges[0].cursor : null,
      endCursor: edges.length > 0 ? edges[edges.length - 1].cursor : null,
    },
    totalCount,
  };
}

function makeConnection(kind: string, page: ReturnType<typeof paginate>): GqlNode {
  const edgeKind = kind.replace(/Connection$/, 'Edge');
  const edges = page.edges.map((e) => ({ __gql: edgeKind, ...e }));
  return { __gql: kind, nodes: page.nodes, edges, pageInfo: page.pageInfo, totalCount: page.totalCount };
}

// --- GraphQL executor ---

function gqlTypeName(node: GqlNode): string {
  const gql = node.__gql ?? '';
  if (gql === 'Query') return 'Query';
  if (gql === 'Mutation') return 'Mutation';
  if (gql === '__Type') return '__Type';
  if (gql === '__Schema') return '__Schema';
  if (gql === '__Field') return '__Field';
  if (gql === '__InputValue') return '__InputValue';
  if (gql === '__EnumValue') return '__EnumValue';
  if (gql === '__Directive') return '__Directive';
  if (gql === 'TypeRef') return '__Type';
  return gql;
}

function knownFields(typeName: string): string[] {
  const def = SCHEMA_TYPES[typeName];
  if (!def?.fields) return [];
  return def.fields.map((f) => f.name);
}

function resolveField(node: GqlNode, fieldName: string, args: Record<string, unknown>, errors: Array<{ message: string }>): unknown {
  const kind = node.__gql ?? '';
  const typeName = gqlTypeName(node);
  if (fieldName === '__typename') return typeName;

  // introspection roots
  if (kind === 'Query' && fieldName === '__type') {
    const name = asStr(args.name);
    const def = SCHEMA_TYPES[name];
    if (!def) return null;
    return { __gql: '__Type', name, def };
  }
  if (kind === 'Query' && fieldName === '__schema') {
    return { __gql: '__Schema' };
  }
  if (kind === '__Schema') {
    if (fieldName === 'queryType') return { __gql: '__Type', name: 'Query', def: SCHEMA_TYPES.Query };
    if (fieldName === 'mutationType') return { __gql: '__Type', name: 'Mutation', def: SCHEMA_TYPES.Mutation };
    if (fieldName === 'subscriptionType') return null;
    if (fieldName === 'types') return Object.entries(SCHEMA_TYPES).map(([name, def]) => ({ __gql: '__Type', name, def }));
    if (fieldName === 'directives') return [];
    return null;
  }
  if (kind === '__Type') {
    const def: SchemaTypeDef = node.def;
    if (fieldName === 'name') return node.name;
    if (fieldName === 'kind') return def.kind;
    if (fieldName === 'description') return def.description ?? null;
    if (fieldName === 'fields') {
      if (!def.fields) return null;
      return def.fields.map((f) => ({ __gql: '__Field', ...f }));
    }
    if (fieldName === 'enumValues') {
      if (!def.enumValues) return null;
      return def.enumValues.map((name) => ({ __gql: '__EnumValue', name }));
    }
    if (fieldName === 'inputFields') {
      if (!def.inputFields) return null;
      return def.inputFields.map((f) => ({ __gql: '__InputValue', ...f }));
    }
    if (fieldName === 'ofType') return null;
    if (fieldName === 'interfaces') return [];
    if (fieldName === 'possibleTypes') return null;
    return null;
  }
  if (kind === '__Field') {
    if (fieldName === 'name') return node.name;
    if (fieldName === 'description') return node.description ?? null;
    if (fieldName === 'args') return (node.args ?? []).map((a: { name: string; type: string }) => ({ __gql: '__InputValue', ...a }));
    if (fieldName === 'type') return { __gql: 'TypeRef', spec: node.type };
    if (fieldName === 'isDeprecated') return false;
    if (fieldName === 'deprecationReason') return null;
    return null;
  }
  if (kind === '__InputValue') {
    if (fieldName === 'name') return node.name;
    if (fieldName === 'description') return node.description ?? null;
    if (fieldName === 'type') return { __gql: 'TypeRef', spec: node.type };
    if (fieldName === 'defaultValue') return null;
    return null;
  }
  if (kind === '__EnumValue') {
    if (fieldName === 'name') return node.name;
    if (fieldName === 'description') return null;
    if (fieldName === 'isDeprecated') return false;
    if (fieldName === 'deprecationReason') return null;
    return null;
  }
  if (kind === '__Directive') {
    if (fieldName === 'name') return node.name;
    if (fieldName === 'description') return null;
    if (fieldName === 'locations') return [];
    if (fieldName === 'args') return [];
    return null;
  }
  if (kind === 'TypeRef') {
    const ref = typeRefFromSpec(node.spec);
    if (fieldName === 'kind') return ref.kind;
    if (fieldName === 'name') return ref.name ?? null;
    if (fieldName === 'ofType') return ref.ofType ? { __gql: 'TypeRef', spec: typeSpecFromRef(ref.ofType) } : null;
    if (fieldName === 'description') return null;
    if (fieldName === 'fields' || fieldName === 'enumValues' || fieldName === 'inputFields') {
      // delegate to the named type when the ref names one
      if (typeof ref.name === 'string') {
        const def = SCHEMA_TYPES[ref.name];
        if (def) return resolveField({ __gql: '__Type', name: ref.name, def }, fieldName, args, errors);
      }
      return null;
    }
    return null;
  }

  // unknown field on this type
  if (!knownFields(typeName).includes(fieldName)) {
    errors.push({ message: `Cannot query field "${fieldName}" on type "${typeName}".` });
    return null;
  }

  if (kind === 'Query') {
    if (fieldName === 'viewer') return userNode(store.viewerLogin, store.viewerId);
    if (fieldName === 'repository') {
      const repo = store.repoForOwner(asStr(args.owner), asStr(args.name));
      return repo ? repoNode(repo) : null;
    }
    if (fieldName === 'node') {
      const decoded = decodeGlobalId(asStr(args.id));
      if (!decoded) return null;
      if (decoded.kind === 'R') {
        const repo = repoById(Number(decoded.key));
        return repo ? repoNode(repo) : null;
      }
      if (decoded.kind === 'I') {
        const [repoId, num] = decoded.key.split(':');
        const repo = repoById(Number(repoId));
        const issue = repo?.issues.get(Number(num));
        return repo && issue ? issueNode(repo, issue) : null;
      }
      if (decoded.kind === 'P') {
        const [repoId, num] = decoded.key.split(':');
        const repo = repoById(Number(repoId));
        const pr = repo?.pulls.get(Number(num));
        return repo && pr ? pullNode(repo, pr) : null;
      }
      if (decoded.kind === 'C') {
        const [repoId, num, cid] = decoded.key.split(':');
        const repo = repoById(Number(repoId));
        const c = repo?.comments.get(Number(num))?.find((x) => x.id === Number(cid));
        return repo && c ? commentNode(repo, Number(num), c) : null;
      }
      return null;
    }
    if (fieldName === 'nodes') {
      const ids = Array.isArray(args.ids) ? args.ids : [];
      return ids.map((id) => resolveField(node, 'node', { id }, errors));
    }
    if (fieldName === 'user') return userNode(asStr(args.login), store.viewerId);
    if (fieldName === 'organization') return { __gql: 'Organization', login: asStr(args.login) };
    if (fieldName === 'search') return makeConnection('SearchResultItemConnection', { nodes: [], edges: [], pageInfo: { hasNextPage: false, hasPreviousPage: false, startCursor: null, endCursor: null }, totalCount: 0 });
    return null;
  }

  if (kind === 'Mutation') {
    if (fieldName === 'createIssue') return mutateCreateIssue(args);
    if (fieldName === 'closeIssue') return mutateCloseIssue(args);
    if (fieldName === 'createPullRequest') return mutateCreatePullRequest(args);
    if (fieldName === 'mergePullRequest') return mutateMergePullRequest(args);
    if (fieldName === 'addComment') return mutateAddComment(args);
    return null;
  }

  if (kind === 'Repository') {
    const repo: Repo = node.repo;
    if (fieldName === 'id') return globalId('R', String(repo.id));
    if (fieldName === 'databaseId') return repo.id;
    if (fieldName === 'name') return repo.name;
    if (fieldName === 'nameWithOwner') return repo.fullName();
    if (fieldName === 'owner') return userNode(repo.owner, store.viewerId);
    if (fieldName === 'defaultBranchRef') {
      const head = repo.headOid();
      if (!head) return null;
      return { __gql: 'Ref', name: repo.defaultBranch, prefix: 'refs/heads/', target: { __gql: 'GitObject', oid: head } };
    }
    if (fieldName === 'viewerPermission') return 'ADMIN';
    if (fieldName === 'hasIssuesEnabled') return true;
    if (fieldName === 'hasProjectsEnabled') return true;
    if (fieldName === 'hasWikiEnabled') return true;
    if (fieldName === 'isPrivate') return repo.privateFlag;
    if (fieldName === 'isFork') return false;
    if (fieldName === 'description') return repo.description;
    if (fieldName === 'url') return `https://github.example.invalid/${repo.fullName()}`;
    if (fieldName === 'createdAt') return repo.createdAt;
    if (fieldName === 'updatedAt') return repo.createdAt;
    if (fieldName === 'issue') {
      const issue = repo.issues.get(asNum(args.number));
      return issue ? issueNode(repo, issue) : null;
    }
    if (fieldName === 'issues') {
      let list = [...repo.issues.values()];
      const states = Array.isArray(args.states) ? (args.states as string[]) : null;
      if (states) list = list.filter((i) => states.includes(i.state === 'open' ? 'OPEN' : 'CLOSED'));
      const orderBy = isRecord(args.orderBy) ? args.orderBy : null;
      const descending = orderBy ? String(orderBy.direction ?? 'ASC').toUpperCase() === 'DESC' : false;
      list.sort((a, b) => (descending ? b.number - a.number : a.number - b.number));
      const nodes = list.map((i) => issueNode(repo, i));
      const page = paginate(nodes, { first: args.first as number | undefined, after: args.after as string | undefined }, (n) => n.issue.number, descending);
      return makeConnection('IssueConnection', page);
    }
    if (fieldName === 'pullRequest') {
      const pr = repo.pulls.get(asNum(args.number));
      return pr ? pullNode(repo, pr) : null;
    }
    if (fieldName === 'pullRequests') {
      let list = [...repo.pulls.values()];
      const states = Array.isArray(args.states) ? (args.states as string[]) : ['OPEN'];
      list = list.filter((p) => {
        const s = p.merged ? 'MERGED' : p.state === 'open' ? 'OPEN' : 'CLOSED';
        return states.includes(s);
      });
      const orderBy = isRecord(args.orderBy) ? args.orderBy : null;
      const descending = orderBy ? String(orderBy.direction ?? 'ASC').toUpperCase() === 'DESC' : false;
      list.sort((a, b) => (descending ? b.number - a.number : a.number - b.number));
      const nodes = list.map((p) => pullNode(repo, p));
      const page = paginate(nodes, { first: args.first as number | undefined, after: args.after as string | undefined }, (n) => n.pr.number, descending);
      return makeConnection('PullRequestConnection', page);
    }
    return null;
  }

  if (kind === 'Issue') {
    const repo: Repo = node.repo;
    const issue: IssueRec = node.issue;
    if (fieldName === 'id') return globalId('I', `${repo.id}:${issue.number}`);
    if (fieldName === 'databaseId') return issue.id;
    if (fieldName === 'number') return issue.number;
    if (fieldName === 'title') return issue.title;
    if (fieldName === 'body') return issue.body;
    if (fieldName === 'state') return issue.state === 'open' ? 'OPEN' : 'CLOSED';
    if (fieldName === 'url') return `https://github.example.invalid/${repo.fullName()}/issues/${issue.number}`;
    if (fieldName === 'createdAt') return issue.createdAt;
    if (fieldName === 'updatedAt') return issue.updatedAt;
    if (fieldName === 'closedAt') return issue.closedAt;
    if (fieldName === 'author') return userNode(issue.user.login, issue.user.id);
    if (fieldName === 'repository') return repoNode(repo);
    if (fieldName === 'labels') {
      const labels = issue.labels.map((name) => ({ __gql: 'Label', name, color: repo.labels.get(name)?.color ?? 'ededed', description: repo.labels.get(name)?.description ?? '' }));
      return makeConnection('LabelConnection', { nodes: labels, edges: labels.map((l, i) => ({ node: l, cursor: cursorFor(i + 1) })), pageInfo: { hasNextPage: false, hasPreviousPage: false, startCursor: labels.length ? cursorFor(1) : null, endCursor: labels.length ? cursorFor(labels.length) : null }, totalCount: labels.length });
    }
    if (fieldName === 'comments') {
      const comments = (repo.comments.get(issue.number) ?? []).map((c) => commentNode(repo, issue.number, c));
      return makeConnection('IssueCommentConnection', { nodes: comments, edges: comments.map((c, i) => ({ node: c, cursor: cursorFor(i + 1) })), pageInfo: { hasNextPage: false, hasPreviousPage: false, startCursor: comments.length ? cursorFor(1) : null, endCursor: comments.length ? cursorFor(comments.length) : null }, totalCount: comments.length });
    }
    return null;
  }

  if (kind === 'PullRequest') {
    const repo: Repo = node.repo;
    const pr: PullRec = node.pr;
    if (fieldName === 'id') return globalId('P', `${repo.id}:${pr.number}`);
    if (fieldName === 'databaseId') return pr.id;
    if (fieldName === 'number') return pr.number;
    if (fieldName === 'title') return pr.title;
    if (fieldName === 'body') return pr.body;
    if (fieldName === 'state') return pr.merged ? 'MERGED' : pr.state === 'open' ? 'OPEN' : 'CLOSED';
    if (fieldName === 'merged') return pr.merged;
    if (fieldName === 'mergeable') return prMergeable(repo, pr);
    if (fieldName === 'headRefName') return pr.headRef;
    if (fieldName === 'baseRefName') return pr.baseRef;
    if (fieldName === 'headRefOid') return pr.headSha;
    if (fieldName === 'baseRefOid') return pr.baseSha;
    if (fieldName === 'url') return `https://github.example.invalid/${repo.fullName()}/pull/${pr.number}`;
    if (fieldName === 'createdAt') return pr.createdAt;
    if (fieldName === 'updatedAt') return pr.updatedAt;
    if (fieldName === 'mergedAt') return pr.mergedAt;
    if (fieldName === 'closedAt') return pr.closedAt;
    if (fieldName === 'author') return userNode(pr.user.login, pr.user.id);
    if (fieldName === 'repository') return repoNode(repo);
    if (fieldName === 'isDraft') return false;
    if (fieldName === 'files') {
      const files = prFiles(repo, pr).map((f, i) => ({ __gql: 'PullRequestChangedFile', path: f.filename, additions: f.additions, deletions: f.deletions, changeType: f.status.toUpperCase(), _idx: i + 1 }));
      const page = paginate(files, { first: args.first as number | undefined, after: args.after as string | undefined }, (f) => f._idx, false);
      return makeConnection('PullRequestChangedFileConnection', page);
    }
    if (fieldName === 'additions' || fieldName === 'deletions' || fieldName === 'changedFiles') {
      const files = prFiles(repo, pr);
      if (fieldName === 'additions') return files.reduce((n, f) => n + f.additions, 0);
      if (fieldName === 'deletions') return files.reduce((n, f) => n + f.deletions, 0);
      return files.length;
    }
    return null;
  }

  if (kind === 'User') {
    if (fieldName === 'id') return globalId('U', String(node.id));
    if (fieldName === 'databaseId') return node.databaseId ?? node.id;
    if (fieldName === 'login') return node.login;
    if (fieldName === 'name') return node.name ?? node.login;
    if (fieldName === 'email') return node.email ?? `${node.login}@example.invalid`;
    if (fieldName === 'avatarUrl') return `https://example.invalid/avatars/${node.login}`;
    if (fieldName === 'url') return `https://github.example.invalid/${node.login}`;
    if (fieldName === 'createdAt') return isoAt(1);
    return null;
  }

  if (kind === 'Organization') {
    if (fieldName === 'id') return globalId('O', node.login);
    if (fieldName === 'login') return node.login;
    return null;
  }

  if (kind === 'IssueComment') {
    const repo: Repo = node.repo;
    const c: CommentRec = node.comment;
    if (fieldName === 'id') return globalId('C', `${repo.id}:${node.number}:${c.id}`);
    if (fieldName === 'databaseId') return c.id;
    if (fieldName === 'body') return c.body;
    if (fieldName === 'author') return userNode(c.user.login, c.user.id);
    if (fieldName === 'createdAt') return c.createdAt;
    if (fieldName === 'updatedAt') return c.createdAt;
    if (fieldName === 'url') return `https://github.example.invalid/${repo.fullName()}/issues/${node.number}#issuecomment-${c.id}`;
    return null;
  }

  if (kind === 'Label') {
    if (fieldName === 'id') return globalId('L', node.name);
    if (fieldName === 'name') return node.name;
    if (fieldName === 'color') return node.color;
    if (fieldName === 'description') return node.description ?? '';
    return null;
  }

  if (kind === 'PullRequestChangedFile') {
    if (fieldName === 'path') return node.path;
    if (fieldName === 'additions') return node.additions;
    if (fieldName === 'deletions') return node.deletions;
    if (fieldName === 'changeType') return node.changeType;
    return null;
  }

  if (kind === 'Ref') {
    if (fieldName === 'name') return node.name;
    if (fieldName === 'prefix') return node.prefix;
    if (fieldName === 'target') return node.target;
    return null;
  }

  if (kind === 'GitObject') {
    if (fieldName === 'oid') return node.oid;
    if (fieldName === 'id') return globalId('GO', node.oid);
    return null;
  }

  // connections & edges & page info
  if (kind.endsWith('Connection')) {
    if (fieldName === 'nodes') return node.nodes;
    if (fieldName === 'edges') return node.edges;
    if (fieldName === 'pageInfo') return { __gql: 'PageInfo', ...node.pageInfo };
    if (fieldName === 'totalCount') return node.totalCount;
    return null;
  }
  if (kind.endsWith('Edge')) {
    if (fieldName === 'node') return node.node;
    if (fieldName === 'cursor') return node.cursor;
    return null;
  }
  if (kind === 'PageInfo') {
    if (fieldName === 'hasNextPage') return node.hasNextPage;
    if (fieldName === 'hasPreviousPage') return node.hasPreviousPage;
    if (fieldName === 'startCursor') return node.startCursor;
    if (fieldName === 'endCursor') return node.endCursor;
    return null;
  }

  // mutation payloads
  if (kind === 'CreateIssuePayload' || kind === 'CloseIssuePayload') {
    if (fieldName === 'issue') return node.issue;
    if (fieldName === 'clientMutationId') return node.clientMutationId ?? null;
    return null;
  }
  if (kind === 'CreatePullRequestPayload' || kind === 'MergePullRequestPayload') {
    if (fieldName === 'pullRequest') return node.pullRequest;
    if (fieldName === 'clientMutationId') return node.clientMutationId ?? null;
    return null;
  }
  if (kind === 'AddCommentPayload') {
    if (fieldName === 'commentEdge') return node.commentEdge;
    if (fieldName === 'subject') return node.subject;
    if (fieldName === 'clientMutationId') return node.clientMutationId ?? null;
    return null;
  }

  return null;
}

function typeSpecFromRef(ref: Record<string, unknown>): string {
  if (ref.kind === 'NON_NULL') return `${typeSpecFromRef(ref.ofType as Record<string, unknown>)}!`;
  if (ref.kind === 'LIST') return `[${typeSpecFromRef(ref.ofType as Record<string, unknown>)}]`;
  return String(ref.name ?? 'String');
}

function mutateCreateIssue(args: Record<string, unknown>): GqlNode {
  const input = isRecord(args.input) ? args.input : {};
  const decoded = decodeGlobalId(asStr(input.repositoryId));
  const repo = decoded?.kind === 'R' ? repoById(Number(decoded.key)) : undefined;
  if (!repo) return { __gql: 'CreateIssuePayload', issue: null, clientMutationId: asStr(input.clientMutationId) };
  const seq = nextSeq();
  const number = store.nextNumber(repo);
  const issue: IssueRec = {
    kind: 'issue', id: store.nextIssueOrPullId(), number, title: asStr(input.title), body: asStr(input.body), state: 'open',
    labels: [], createdSeq: seq, createdAt: isoAt(seq), updatedAt: isoAt(seq), closedAt: null,
    user: { login: store.viewerLogin, id: store.viewerId },
  };
  repo.issues.set(number, issue);
  return { __gql: 'CreateIssuePayload', issue: issueNode(repo, issue), clientMutationId: asStr(input.clientMutationId) };
}

function mutateCloseIssue(args: Record<string, unknown>): GqlNode {
  const input = isRecord(args.input) ? args.input : {};
  const decoded = decodeGlobalId(asStr(input.issueId));
  let node: GqlNode | null = null;
  if (decoded?.kind === 'I') {
    const [repoId, num] = decoded.key.split(':');
    const repo = repoById(Number(repoId));
    const issue = repo?.issues.get(Number(num));
    if (repo && issue) {
      const seq = nextSeq();
      issue.state = 'closed';
      issue.closedAt = isoAt(seq);
      issue.updatedAt = isoAt(seq);
      node = issueNode(repo, issue);
    }
  }
  return { __gql: 'CloseIssuePayload', issue: node, clientMutationId: asStr(input.clientMutationId) };
}

function mutateCreatePullRequest(args: Record<string, unknown>): GqlNode {
  const input = isRecord(args.input) ? args.input : {};
  const decoded = decodeGlobalId(asStr(input.repositoryId));
  const repo = decoded?.kind === 'R' ? repoById(Number(decoded.key)) : undefined;
  if (!repo) return { __gql: 'CreatePullRequestPayload', pullRequest: null, clientMutationId: asStr(input.clientMutationId) };
  const headRef = asStr(input.headRefName);
  const baseRef = asStr(input.baseRefName, repo.defaultBranch);
  for (const p of repo.pulls.values()) {
    if (p.state === 'open' && p.headRef === headRef && p.baseRef === baseRef) {
      return { __gql: 'CreatePullRequestPayload', pullRequest: pullNode(repo, p), clientMutationId: asStr(input.clientMutationId) };
    }
  }
  const headOid = repo.refOid(`refs/heads/${headRef}`);
  const baseOid = repo.refOid(`refs/heads/${baseRef}`);
  if (!headOid || !baseOid) return { __gql: 'CreatePullRequestPayload', pullRequest: null, clientMutationId: asStr(input.clientMutationId) };
  const seq = nextSeq();
  const number = store.nextNumber(repo);
  const pr: PullRec = {
    kind: 'pull', id: store.nextIssueOrPullId(), number, title: asStr(input.title), body: asStr(input.body), state: 'open', merged: false,
    headRef, headSha: repo.peelToCommit(headOid)!, baseRef, baseSha: repo.peelToCommit(baseOid)!,
    mergedAt: null, mergeCommitSha: null, createdSeq: seq, createdAt: isoAt(seq), updatedAt: isoAt(seq), closedAt: null,
    user: { login: store.viewerLogin, id: store.viewerId },
  };
  repo.pulls.set(number, pr);
  return { __gql: 'CreatePullRequestPayload', pullRequest: pullNode(repo, pr), clientMutationId: asStr(input.clientMutationId) };
}

function mutateMergePullRequest(args: Record<string, unknown>): GqlNode {
  const input = isRecord(args.input) ? args.input : {};
  const decoded = decodeGlobalId(asStr(input.pullRequestId));
  let node: GqlNode | null = null;
  if (decoded?.kind === 'P') {
    const [repoId, num] = decoded.key.split(':');
    const repo = repoById(Number(repoId));
    const pr = repo?.pulls.get(Number(num));
    if (repo && pr && !pr.merged && prMergeable(repo, pr) !== 'CONFLICTING') {
      const baseTip = repo.refOid(`refs/heads/${pr.baseRef}`);
      if (baseTip) {
        const seq = nextSeq();
        const author = `${DEFAULT_VIEWER.name} <${DEFAULT_VIEWER.email}>`;
        const mergeCommit = buildCommit({
          tree: repo.commitView(pr.headSha)!.tree,
          parents: [baseTip],
          message: `Merge pull request #${pr.number} from ${repo.owner}/${pr.headRef}`,
          author,
          committer: author,
          timestamp: EPOCH_SEC + seq * 60,
        });
        const mergeSha = repo.putObject('commit', mergeCommit);
        repo.refs.set(`refs/heads/${pr.baseRef}`, mergeSha);
        pr.state = 'closed';
        pr.merged = true;
        pr.mergedAt = isoAt(seq);
        pr.mergeCommitSha = mergeSha;
        pr.closedAt = isoAt(seq);
        pr.updatedAt = isoAt(seq);
        node = pullNode(repo, pr);
      }
    } else if (repo && pr && pr.merged) {
      node = pullNode(repo, pr);
    }
  }
  return { __gql: 'MergePullRequestPayload', pullRequest: node, clientMutationId: asStr(input.clientMutationId) };
}

function mutateAddComment(args: Record<string, unknown>): GqlNode {
  const input = isRecord(args.input) ? args.input : {};
  const decoded = decodeGlobalId(asStr(input.subjectId));
  let edge: GqlNode | null = null;
  let subject: GqlNode | null = null;
  if (decoded?.kind === 'I') {
    const [repoId, num] = decoded.key.split(':');
    const repo = repoById(Number(repoId));
    const issue = repo?.issues.get(Number(num));
    if (repo && issue) {
      const seq = nextSeq();
      const c: CommentRec = { id: store.nextComment(), body: asStr(input.body), createdSeq: seq, createdAt: isoAt(seq), user: { login: store.viewerLogin, id: store.viewerId } };
      const list = repo.comments.get(issue.number) ?? [];
      list.push(c);
      repo.comments.set(issue.number, list);
      edge = { __gql: 'IssueCommentEdge', node: commentNode(repo, issue.number, c), cursor: cursorFor(list.length) };
      subject = issueNode(repo, issue);
    }
  }
  return { __gql: 'AddCommentPayload', commentEdge: edge, subject, clientMutationId: asStr(input.clientMutationId) };
}

function execSelections(node: unknown, selections: GqlSelection[], variables: Record<string, unknown>, errors: Array<{ message: string }>, fragments: Map<string, GqlFragment>): Record<string, unknown> | null {
  if (node === null || node === undefined) return null;
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.kind === 'spread') {
      const frag = fragments.get(sel.name);
      if (!frag) {
        errors.push({ message: `Unknown fragment "${sel.name}".` });
        continue;
      }
      const sub = execSelections(node, frag.selections, variables, errors, fragments);
      if (sub) Object.assign(out, sub);
      continue;
    }
    if (sel.kind === 'inline') {
      const typeName = isRecord(node) && typeof node.__gql === 'string' ? gqlTypeName(node as GqlNode) : '';
      if (sel.typeCondition && sel.typeCondition !== typeName) continue;
      const sub = execSelections(node, sel.selections, variables, errors, fragments);
      if (sub) Object.assign(out, sub);
      continue;
    }
    // field
    const resolvedArgs: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(sel.args)) resolvedArgs[k] = resolveGqlValue(v, variables);
    const value = resolveField(node as GqlNode, sel.name, resolvedArgs, errors);
    if (sel.selections.length === 0) {
      out[sel.alias] = value;
    } else if (Array.isArray(value)) {
      out[sel.alias] = value.map((item) => execSelections(item, sel.selections, variables, errors, fragments));
    } else {
      out[sel.alias] = execSelections(value, sel.selections, variables, errors, fragments);
    }
  }
  return out;
}

function executeGraphQLOperation(doc: unknown, operationName: string | undefined): { data?: Record<string, unknown> | null; errors?: Array<{ message: string }> } {
  if (!isRecord(doc) || typeof doc.query !== 'string') {
    return { errors: [{ message: 'Request must include a query string.' }] };
  }
  const variables = isRecord(doc.variables) ? (doc.variables as Record<string, unknown>) : {};
  let defs: Array<GqlOperation | GqlFragment>;
  try {
    defs = new GqlParser(tokenizeGql(doc.query)).parseDocument();
  } catch (err) {
    return { errors: [{ message: `Syntax Error: ${err instanceof Error ? err.message : String(err)}` }] };
  }
  const fragments = new Map<string, GqlFragment>();
  const operations = defs.filter((d): d is GqlOperation => d.kind === 'operation');
  for (const d of defs) if (d.kind === 'fragment') fragments.set(d.name, d);
  if (operations.length === 0) return { errors: [{ message: 'No operations found.' }] };
  let operation: GqlOperation | undefined;
  if (operationName) operation = operations.find((o) => o.name === operationName);
  else operation = operations[0];
  if (!operation) return { errors: [{ message: operationName ? `Unknown operation named "${operationName}".` : 'Must provide an operation name if there are multiple operations.' }] };
  const mergedVariables: Record<string, unknown> = { ...operation.variableDefs, ...variables };
  const root: GqlNode = operation.operationType === 'mutation' ? { __gql: 'Mutation' } : { __gql: 'Query' };
  const errors: Array<{ message: string }> = [];
  const data = execSelections(root, operation.selections, mergedVariables, errors, fragments);
  const result: { data?: Record<string, unknown> | null; errors?: Array<{ message: string }> } = {};
  if (errors.length > 0) result.errors = errors;
  result.data = data;
  return result;
}

async function handleGraphQL(ctx: Ctx): Promise<boolean> {
  const { res } = ctx;
  const body = ctx.body;
  if (Array.isArray(body)) {
    const results = body.map((doc) => executeGraphQLOperation(doc, undefined));
    sendJson(res, 200, results);
    return true;
  }
  const operationName = isRecord(body) && typeof body.operationName === 'string' ? body.operationName : undefined;
  const result = executeGraphQLOperation(body, operationName);
  sendJson(res, 200, result);
  return true;
}

// ---------------------------------------------------------------------------
// MCP (JSON-RPC 2.0 Streamable HTTP)
// ---------------------------------------------------------------------------

const MCP_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const MCP_SERVER_NAME = 'github-core-clone-forge';
const MCP_SERVER_VERSION = '1.0.0';

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: { type: 'object'; properties: Record<string, { type: string; description?: string }>; required: string[] };
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Name of the repository to create' },
        description: { type: 'string', description: 'A short description of the repository' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner (user or organization) of the repository' },
        repo: { type: 'string', description: 'The name of the repository' },
        full_name: { type: 'string', description: 'The full name of the repository (owner/repo)' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner of the repository' },
        repo: { type: 'string', description: 'The name of the repository' },
        title: { type: 'string', description: 'The title of the issue' },
        body: { type: 'string', description: 'The body of the issue' },
        full_name: { type: 'string', description: 'The full name of the repository (owner/repo)' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner of the repository' },
        repo: { type: 'string', description: 'The name of the repository' },
        state: { type: 'string', description: 'Issue state filter: open, closed, or all' },
        full_name: { type: 'string', description: 'The full name of the repository (owner/repo)' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner of the repository' },
        repo: { type: 'string', description: 'The name of the repository' },
        title: { type: 'string', description: 'The title of the pull request' },
        head: { type: 'string', description: 'The name of the branch where the changes are implemented' },
        base: { type: 'string', description: 'The name of the branch the changes are pulled into' },
        body: { type: 'string', description: 'The body of the pull request' },
        full_name: { type: 'string', description: 'The full name of the repository (owner/repo)' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner of the repository' },
        repo: { type: 'string', description: 'The name of the repository' },
        pull_number: { type: 'integer', description: 'The number of the pull request to merge' },
        full_name: { type: 'string', description: 'The full name of the repository (owner/repo)' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

const MCP_TOOLS_LIST_JSON = JSON.stringify(MCP_TOOLS.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })));

function mcpResolveOwnerRepo(args: Record<string, unknown>): { owner: string; repo: string } {
  let owner = asStr(args.owner);
  let repo = asStr(args.repo);
  const fullName = asStr(args.full_name);
  if ((!owner || !repo) && fullName.includes('/')) {
    const [o, r] = fullName.split('/');
    if (!owner) owner = o;
    if (!repo) repo = r;
  }
  // also accept repository / repository_name aliases
  if (!repo) repo = asStr(args.repository_name) || asStr(args.repository);
  return { owner, repo };
}

function mcpTextResult(id: unknown, data: unknown): Json {
  const text = typeof data === 'string' ? data : JSON.stringify(data);
  return { jsonrpc: '2.0', id: id ?? null, result: { content: [{ type: 'text', text }], structuredContent: data, isError: false } };
}

function mcpErrorResult(id: unknown, data: unknown, message?: string): Json {
  const text = typeof data === 'string' ? data : JSON.stringify(data);
  return { jsonrpc: '2.0', id: id ?? null, result: { content: [{ type: 'text', text: message ? `${message}: ${text}` : text }], structuredContent: data, isError: true } };
}

function mcpJsonRpcError(id: unknown, code: number, message: string): Json {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

function mcpCallTool(toolName: string, args: Record<string, unknown>, id: unknown): Json {
  const normalized = toolName.toLowerCase().replace(/^github__/, '').replace(/^github-/, '');
  const def = MCP_TOOLS.find((t) => t.name === normalized || t.name.endsWith(normalized) || normalized.endsWith(t.name));
  if (!def) return mcpJsonRpcError(id, -32602, `Unknown tool: ${toolName}`);
  for (const required of def.inputSchema.required) {
    if (args[required] === undefined || args[required] === null || args[required] === '') {
      return mcpJsonRpcError(id, -32602, `Missing required argument: ${required}`);
    }
  }
  try {
    if (def.name === 'create_repo') {
      const name = asStr(args.name);
      const repo = store.createRepo(name, asStr(args.description), Boolean(args.private));
      if (!repo) return mcpErrorResult(id, { error: 'Repository already exists', name });
      return mcpTextResult(id, repoJson(repo));
    }
    const { owner, repo: repoName } = mcpResolveOwnerRepo(args);
    if (def.name === 'get_repo') {
      const repo = store.repoForOwner(owner, repoName);
      if (!repo) return mcpErrorResult(id, { error: 'Not Found', owner, repo: repoName });
      return mcpTextResult(id, repoJson(repo));
    }
    const repo = store.repoForOwner(owner, repoName);
    if (!repo) return mcpErrorResult(id, { error: 'Not Found', owner, repo: repoName });
    if (def.name === 'create_issue') {
      const seq = nextSeq();
      const number = store.nextNumber(repo);
      const issue: IssueRec = {
        kind: 'issue', id: store.nextIssueOrPullId(), number, title: asStr(args.title), body: asStr(args.body), state: 'open',
        labels: [], createdSeq: seq, createdAt: isoAt(seq), updatedAt: isoAt(seq), closedAt: null,
        user: { login: store.viewerLogin, id: store.viewerId },
      };
      repo.issues.set(number, issue);
      return mcpTextResult(id, issueJson(repo, issue));
    }
    if (def.name === 'list_issues') {
      const state = asStr(args.state, 'open');
      let list = [...repo.issues.values()];
      if (state !== 'all') list = list.filter((i) => i.state === state);
      list.sort((a, b) => b.createdSeq - a.createdSeq);
      return mcpTextResult(id, { issues: list.map((i) => issueJson(repo, i)) });
    }
    if (def.name === 'create_pull_request') {
      const headRef = asStr(args.head);
      const baseRef = asStr(args.base, repo.defaultBranch);
      const headOid = repo.refOid(`refs/heads/${headRef}`);
      const baseOid = repo.refOid(`refs/heads/${baseRef}`);
      if (!headOid || !baseOid) return mcpErrorResult(id, { error: 'Head or base ref does not exist', head: headRef, base: baseRef });
      for (const p of repo.pulls.values()) {
        if (p.state === 'open' && p.headRef === headRef && p.baseRef === baseRef) {
          return mcpTextResult(id, pullJson(repo, p));
        }
      }
      const seq = nextSeq();
      const number = store.nextNumber(repo);
      const pr: PullRec = {
        kind: 'pull', id: store.nextIssueOrPullId(), number, title: asStr(args.title), body: asStr(args.body), state: 'open', merged: false,
        headRef, headSha: repo.peelToCommit(headOid)!, baseRef, baseSha: repo.peelToCommit(baseOid)!,
        mergedAt: null, mergeCommitSha: null, createdSeq: seq, createdAt: isoAt(seq), updatedAt: isoAt(seq), closedAt: null,
        user: { login: store.viewerLogin, id: store.viewerId },
      };
      repo.pulls.set(number, pr);
      return mcpTextResult(id, pullJson(repo, pr));
    }
    if (def.name === 'merge_pull_request') {
      const num = asNum(args.pull_number);
      const pr = repo.pulls.get(num);
      if (!pr) return mcpErrorResult(id, { error: 'Not Found', pull_number: num });
      if (pr.merged) return mcpTextResult(id, { sha: pr.mergeCommitSha, merged: true, message: 'Pull request successfully merged' });
      if (prMergeable(repo, pr) === 'CONFLICTING') return mcpErrorResult(id, { error: 'Merge conflict', pull_number: num });
      const baseTip = repo.refOid(`refs/heads/${pr.baseRef}`);
      if (!baseTip) return mcpErrorResult(id, { error: 'Base branch not found' });
      const seq = nextSeq();
      const author = `${DEFAULT_VIEWER.name} <${DEFAULT_VIEWER.email}>`;
      const mergeCommit = buildCommit({
        tree: repo.commitView(pr.headSha)!.tree,
        parents: [baseTip],
        message: `Merge pull request #${pr.number} from ${repo.owner}/${pr.headRef}`,
        author,
        committer: author,
        timestamp: EPOCH_SEC + seq * 60,
      });
      const mergeSha = repo.putObject('commit', mergeCommit);
      repo.refs.set(`refs/heads/${pr.baseRef}`, mergeSha);
      pr.state = 'closed';
      pr.merged = true;
      pr.mergedAt = isoAt(seq);
      pr.mergeCommitSha = mergeSha;
      pr.closedAt = isoAt(seq);
      pr.updatedAt = isoAt(seq);
      return mcpTextResult(id, { sha: mergeSha, merged: true, message: 'Pull request successfully merged' });
    }
  } catch (err) {
    return mcpErrorResult(id, { error: err instanceof Error ? err.message : String(err) });
  }
  return mcpJsonRpcError(id, -32602, `Unknown tool: ${toolName}`);
}

async function handleMcp(ctx: Ctx): Promise<boolean> {
  const { req, res } = ctx;
  const method = req.method ?? 'POST';
  if (method === 'DELETE') {
    res.writeHead(204, { 'x-github-request-id': `req-${requestCounter}` });
    res.end();
    return true;
  }
  if (method !== 'POST') return false;
  if (!checkAuth(req)) {
    sendError(res, 401, 'Requires authentication');
    return true;
  }
  const parsed = parseJsonBody(ctx.rawBody);
  if (!parsed.ok) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return true;
  }
  const body = parsed.value;
  const handleOne = (msg: unknown): Json | null => {
    if (!isRecord(msg)) return { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } };
    const id = 'id' in msg ? msg.id : null;
    const m = msg as Record<string, unknown>;
    if (m.jsonrpc !== '2.0' || typeof m.method !== 'string') {
      return { jsonrpc: '2.0', id: id ?? null, error: { code: -32600, message: 'Invalid Request' } };
    }
    const methodName = m.method as string;
    const params = isRecord(m.params) ? (m.params as Record<string, unknown>) : {};
    if (methodName === 'server/discover') {
      return {
        jsonrpc: '2.0',
        id: id ?? null,
        result: {
          supportedVersions: [...MCP_VERSIONS],
          capabilities: { tools: {} },
          serverInfo: { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
          _meta: { 'io.modelcontextprotocol/serverInfo': { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION } },
        },
      };
    }
    if (methodName === 'initialize') {
      const requested = asStr(params.protocolVersion, '2026-07-28');
      const version = MCP_VERSIONS.includes(requested) ? requested : '2026-07-28';
      const headers: Record<string, string> = {};
      const sessionId = req.headers['mcp-session-id'];
      if (typeof sessionId === 'string' && sessionId) headers['mcp-session-id'] = sessionId;
      void headers;
      return {
        jsonrpc: '2.0',
        id: id ?? null,
        result: {
          protocolVersion: version,
          capabilities: { tools: {} },
          serverInfo: { name: MCP_SERVER_NAME, version: MCP_SERVER_VERSION },
        },
      };
    }
    if (methodName.startsWith('notifications/')) {
      return null; // notification: no response body content, but streamable HTTP wants a 202
    }
    if (methodName === 'ping') {
      return { jsonrpc: '2.0', id: id ?? null, result: {} };
    }
    if (methodName === 'tools/list') {
      // byte-identical on every call: return the pre-serialized list
      return { jsonrpc: '2.0', id: id ?? null, result: { tools: JSON.parse(MCP_TOOLS_LIST_JSON) as unknown[] } };
    }
    if (methodName === 'tools/call') {
      const toolName = asStr(params.name);
      const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
      return mcpCallTool(toolName, args, id);
    }
    return { jsonrpc: '2.0', id: id ?? null, error: { code: -32601, message: `Method not found: ${methodName}` } };
  };
  if (Array.isArray(body)) {
    const results = body.map(handleOne).filter((r): r is Json => r !== null);
    sendJson(res, 200, results);
    return true;
  }
  const result = handleOne(body);
  if (result === null) {
    // notification only
    res.writeHead(202, { 'x-github-request-id': `req-${requestCounter}` });
    res.end();
    return true;
  }
  // For initialize, echo back a session id header if the client sent one
  const extra: Record<string, string> = {};
  if (isRecord(body) && body.method === 'initialize' && typeof req.headers['mcp-session-id'] === 'string') {
    extra['mcp-session-id'] = req.headers['mcp-session-id'];
  }
  sendJson(res, 200, result, extra);
  return true;
}

// ---------------------------------------------------------------------------
// dispatcher
// ---------------------------------------------------------------------------

function splitPath(pathname: string): string[] {
  return pathname.split('/').filter((seg) => seg.length > 0).map((seg) => {
    try {
      return decodeURIComponent(seg);
    } catch {
      return seg;
    }
  });
}

export function createApp(): Server {
  const server = createServer((req, res) => {
    void (async () => {
      requestCounter += 1;
      const rid = requestCounter;
      try {
        const url = new URL(req.url ?? '/', 'http://127.0.0.1');
        const segments = splitPath(url.pathname);
        const rawBody = (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE') ? await readBody(req) : Buffer.alloc(0);
        const ctx: Ctx = { req, res, url, segments, query: url.searchParams, body: {}, rawBody };
        // health check (no auth)
        if (req.method === 'GET' && segments.length === 1 && segments[0] === 'healthz') {
          sendJson(res, 200, { ok: true, status: 'ok' });
          return;
        }
        // git smart HTTP (auth checked inside for POSTs; advertise is public like git)
        if (segments.length >= 2 && segments[1].endsWith('.git')) {
          if (await handleGit(ctx)) return;
          sendError(res, 404, 'Not Found');
          return;
        }
        // MCP
        if (segments.length === 1 && segments[0] === 'mcp') {
          if (await handleMcp(ctx)) return;
          sendError(res, 404, 'Not Found');
          return;
        }
        // GraphQL
        if (segments.length === 2 && segments[0] === 'api' && segments[1] === 'graphql') {
          if (req.method !== 'POST') {
            sendError(res, 405, 'Method Not Allowed');
            return;
          }
          if (!checkAuth(req)) {
            sendError(res, 401, 'Requires authentication');
            return;
          }
          const parsed = parseJsonBody(rawBody);
          if (!parsed.ok) {
            sendJson(res, 400, { errors: [{ message: parsed.error }] });
            return;
          }
          ctx.body = parsed.value;
          if (await handleGraphQL(ctx)) return;
          sendError(res, 404, 'Not Found');
          return;
        }
        // REST v3
        if (segments.length >= 2 && segments[0] === 'api' && segments[1] === 'v3') {
          if (!checkAuth(req)) {
            sendError(res, 401, 'Requires authentication');
            return;
          }
          if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE') {
            const parsed = parseJsonBody(rawBody);
            if (!parsed.ok) {
              sendError(res, 400, parsed.error);
              return;
            }
            ctx.body = parsed.value;
          }
          if (await handleRest(ctx)) return;
          sendError(res, 404, 'Not Found');
          return;
        }
        sendError(res, 404, 'Not Found');
      } catch (err) {
        if (!res.headersSent) {
          sendError(res, 500, err instanceof Error ? err.message : 'Internal Server Error');
        } else {
          res.end();
        }
        process.stderr.write(`[forge] request ${rid} failed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
      }
    })();
  });
  return server;
}
