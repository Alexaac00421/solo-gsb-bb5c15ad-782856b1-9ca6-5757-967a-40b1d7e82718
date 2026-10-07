'use strict';

// CIDR parsing / canonicalization / allocation math.
// IPv4 addresses are 32-bit BigInts, IPv6 addresses 128-bit BigInts.

class CidrError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CidrError';
    this.code = code;
  }
}

const V4_BITS = 32n;
const V6_BITS = 128n;
const MAX_BIG = (bits) => (1n << bits) - 1n;

function parseOctets(str) {
  const parts = str.split('.');
  if (parts.length !== 4) throw new CidrError('INVALID_CIDR', 'IPv4 must have 4 octets');
  const octets = [];
  for (const p of parts) {
    if (!/^(0|[1-9][0-9]*)$/.test(p)) {
      throw new CidrError('INVALID_CIDR', `bad IPv4 octet: ${p}`);
    }
    const n = Number(p);
    if (n > 255) throw new CidrError('INVALID_CIDR', `IPv4 octet out of range: ${p}`);
    octets.push(n);
  }
  let val = 0n;
  for (const n of octets) val = (val << 8n) | BigInt(n);
  return val;
}

function formatV4(val) {
  const out = [];
  for (let i = 3; i >= 0; i--) out.push(Number((val >> (8n * BigInt(i))) & 255n));
  return out.join('.');
}

function parseV6Groups(str) {
  // Reject zone ids, embedded IPv4, multiple "::" etc.
  if (str.includes('.')) throw new CidrError('INVALID_CIDR', 'embedded IPv4 not supported');
  if (str.includes('%')) throw new CidrError('INVALID_CIDR', 'zone id not supported');
  const doubleColons = str.split('::').length - 1;
  if (doubleColons > 1) throw new CidrError('INVALID_CIDR', 'multiple :: in IPv6 address');

  let groups;
  if (doubleColons === 1) {
    let [left, right] = str.split('::');
    const leftGroups = left === '' ? [] : left.split(':');
    const rightGroups = right === '' ? [] : right.split(':');
    if (leftGroups.length + rightGroups.length > 7) {
      throw new CidrError('INVALID_CIDR', 'too many IPv6 groups around ::');
    }
    const zeroFill = 8 - leftGroups.length - rightGroups.length;
    groups = [...leftGroups, ...Array(zeroFill).fill('0'), ...rightGroups];
  } else {
    groups = str.split(':');
  }
  if (groups.length !== 8) throw new CidrError('INVALID_CIDR', 'IPv6 must have 8 groups');

  let val = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) throw new CidrError('INVALID_CIDR', `bad IPv6 group: ${g}`);
    val = (val << 16n) | BigInt(parseInt(g, 16));
  }
  return val;
}

function formatV6(val) {
  const groups = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((val >> (16n * BigInt(i))) & 0xffffn));

  // Find longest run of >= 2 zero groups for RFC 5952 compression.
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i <= 8; i++) {
    if (i < 8 && groups[i] === 0) {
      if (curLen === 0) curStart = i;
      curLen++;
    } else if (curLen > 0) {
      if (curLen >= 2 && curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
      curLen = 0;
    }
  }
  const texts = groups.map((g) => g.toString(16));
  if (bestStart === -1) return texts.join(':');
  const head = texts.slice(0, bestStart).join(':');
  const tail = texts.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}

/**
 * Parse a strict canonical-ish CIDR. Host bits must be zero.
 * Returns { family, bits (BigInt), prefixLen (number), start, end, cidr }.
 */
function parseCidr(input) {
  if (typeof input !== 'string') throw new CidrError('INVALID_CIDR', 'CIDR must be a string');
  const text = input.trim();
  const idx = text.lastIndexOf('/');
  if (idx === -1) throw new CidrError('INVALID_CIDR', 'missing prefix length');
  const addr = text.slice(0, idx);
  const lenText = text.slice(idx + 1);
  if (!/^\d+$/.test(lenText)) throw new CidrError('INVALID_CIDR', 'prefix length must be a number');
  const prefixLen = Number(lenText);
  if (!addr) throw new CidrError('INVALID_CIDR', 'empty address');

  let family, bits, width;
  if (addr.includes(':')) {
    family = 6;
    width = V6_BITS;
    bits = parseV6Groups(addr);
  } else {
    family = 4;
    width = V4_BITS;
    bits = parseOctets(addr);
  }
  if (prefixLen > Number(width)) {
    throw new CidrError('INVALID_LENGTH', `prefix length /${prefixLen} exceeds /${Number(width)} for IPv${family}`);
  }
  const mask = width - BigInt(prefixLen);
  const start = mask === width ? 0n : (bits >> mask) << mask;
  if (start !== bits) {
    throw new CidrError('HOST_BITS_SET', `CIDR ${text} has host bits set; did you mean ${format(start, family, width)}/${prefixLen}?`);
  }
  const end = start | (mask === 0n ? 0n : (1n << mask) - 1n);
  const cidr = `${format(start, family, width)}/${prefixLen}`;
  return { family, bits, prefixLen, start, end, width, cidr };
}

function format(val, family, width) {
  return family === 4 ? formatV4(val) : formatV6(val, width);
}

/** inclusive interval overlap */
function overlaps(aStart, aEnd, bStart, bEnd) {
  return aStart <= bEnd && bStart <= aEnd;
}

function contains(parent, childStart, childEnd) {
  return parent.start <= childStart && childEnd <= parent.end;
}

/**
 * Pick the numerically smallest, CIDR-aligned sub-prefix of `parent` with
 * length `targetLen` that does not overlap any active direct children
 * (siblings, given as {start,end} sorted by start).
 *
 * Enumeration walks candidate block starts forward; when a candidate overlaps
 * a sibling it jumps past that sibling's end. For an aligned child block this
 * always lands exactly on the next valid boundary, so even IPv6 searches use
 * only a handful of iterations.
 *
 * Returns {start,end} or null when the parent has no room.
 */
function findSmallestSubnet(parent, targetLen, children) {
  // The child must be strictly smaller than its parent.
  const parentLen = BigInt(parent.prefixLen);
  const wanted = BigInt(targetLen);
  if (wanted <= parentLen) return null;
  const sizeBits = BigInt(parent.width) - wanted;
  if (sizeBits < 0n) return null;
  const size = 1n << sizeBits;
  const limit = parent.end;

  let candidate = parent.start;
  let i = 0;
  // Walk candidate blocks upward. Children are sorted; at each step the
  // candidate either clears every remaining child (pick it) or overlaps the
  // next child — jump to the first aligned boundary past that child.
  while (candidate + size - 1n <= limit) {
    while (i < children.length && children[i].end < candidate) i++;
    if (i >= children.length) {
      return { start: candidate, end: candidate + size - 1n };
    }
    const ch = children[i];
    const candEnd = candidate + size - 1n;
    if (ch.start > candEnd) {
      // next child starts after candidate -> candidate is free
      return { start: candidate, end: candEnd };
    }
    // overlap: move to the first block boundary strictly past the child.
    // Round (ch.end + 1) UP to a multiple of `size`.
    const after = ch.end + 1n;
    candidate = after + ((size - (after % size)) % size);
    i++;
  }
  return null;
}

module.exports = {
  CidrError,
  parseCidr,
  format,
  overlaps,
  contains,
  findSmallestSubnet,
};
