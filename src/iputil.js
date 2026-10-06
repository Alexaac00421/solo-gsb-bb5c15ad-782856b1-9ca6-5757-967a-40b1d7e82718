'use strict';

const ipaddr = require('ipaddr.js');
const { ApiError } = require('./errors');

/**
 * IP/CIDR 工具：所有前缀在数据库中均表示为半开区间 [start, end)，
 * start/end 为任意精度 NUMERIC（IPv4 最多 2^32，IPv6 最多 2^128）。
 *
 * 这里统一用 BigInt 做对齐与区间运算，再转成十进制字符串交给 pg。
 */

const FAM_BITS = { 4: 32, 6: 128 };
const FAM_NAME = { 4: 'ipv4', 6: 'ipv6' };

function badCidr(message) {
  return new ApiError(400, 'INVALID_CIDR', message || '非法 CIDR 表示');
}

/**
 * 严格解析 CIDR：
 *  - 必须是 "address/prefixLength" 形式
 *  - 地址必须规范（不接受简写歧义、IPv4-mapped IPv6、zone id）
 *  - 主机位必须为 0（不接受 192.168.1.5/24 这类带主机位的写法）
 * 返回 { family, length, start, end, cidr }
 */
function parseCidr(input) {
  if (typeof input !== 'string') throw badCidr();
  const s = input.trim();
  if (!s || s.includes(' ') || s.includes(',')) throw badCidr();

  // 显式拒绝 IPv6 zone id（如 fe80::1%eth0）
  if (s.includes('%')) throw badCidr('不支持 zone id');

  const slash = s.indexOf('/');
  if (slash < 0) throw badCidr('CIDR 必须包含 "/" 与前缀长度');
  const addrPart = s.slice(0, slash);
  const lenPart = s.slice(slash + 1);
  if (addrPart === '' || lenPart === '' || lenPart.includes('/')) {
    throw badCidr();
  }
  if (!/^\d+$/.test(lenPart)) throw badCidr('前缀长度必须为非负整数');

  let parsed;
  try {
    parsed = ipaddr.parse(addrPart);
  } catch (_e) {
    throw badCidr('IP 地址不合法');
  }

  let kind;
  if (parsed.kind() === 'ipv4') kind = 4;
  else if (parsed.kind() === 'ipv6') {
    kind = 6;
    // 拒绝 IPv4-mapped/IPv4-translated 等特殊表示，避免跨族歧义
    if (
      parsed.isIPv4MappedAddress &&
      typeof parsed.isIPv4MappedAddress === 'function' &&
      parsed.isIPv4MappedAddress()
    ) {
      throw badCidr('不接受 IPv4-mapped IPv6 地址');
    }
  } else {
    throw badCidr('不支持的地址族');
  }

  const maxLen = FAM_BITS[kind];
  const length = Number(lenPart);
  if (!Number.isInteger(length) || length < 0 || length > maxLen) {
    throw badCidr(
      kind === 4
        ? 'IPv4 前缀长度必须在 0~32 之间'
        : 'IPv6 前缀长度必须在 0~128 之间'
    );
  }

  const octets =
    kind === 4 ? parsed.octets : parsed.toByteArray(); // 16 字节
  let value = 0n;
  for (const b of octets) value = (value << 8n) | BigInt(b);

  if (length < maxLen) {
    const hostMask = (1n << BigInt(maxLen - length)) - 1n;
    if ((value & hostMask) !== 0n) {
      throw badCidr('主机位必须为 0，请使用规范的网络地址');
    }
  }

  const size = length === maxLen ? 1n : 1n << BigInt(maxLen - length);
  const start = value;
  const end = value + size;
  const cidr = formatCidr(kind, start, length);
  return { family: kind, length, start, end, cidr };
}

/** 将 BigInt 数值转回规范 CIDR 字符串 */
function formatCidr(family, start, length) {
  const bits = FAM_BITS[family];
  if (start < 0n || start >= 1n << BigInt(bits)) {
    throw new Error('地址数值超出范围');
  }
  const bytes = [];
  let v = start;
  const byteCount = bits / 8;
  for (let i = 0; i < byteCount; i += 1) {
    bytes.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  let addr;
  if (family === 4) {
    addr = bytes.join('.');
  } else {
    addr = ipaddr.fromByteArray(bytes).toString();
  }
  return `${addr}/${length}`;
}

/** 边界对齐检查：start 是否是 length 长度前缀的合法网络地址 */
function isAligned(start, family, length) {
  const bits = FAM_BITS[family];
  if (length >= bits) return true;
  const hostMask = (1n << BigInt(bits - length)) - 1n;
  return (start & hostMask) === 0n;
}

/** p 是否严格包含于 parent（parent 是有效前缀，同族） */
function isStrictlyInside(parent, start, end) {
  return start >= parent.start && end <= parent.end && start !== parent.start;
}

/**
 * 在父范围内选出“数值最小、按 CIDR 边界对齐、且不与任何已占用区间重叠”的
 * 目标长度子前缀。
 *
 * 经典的有序区间扫描：空闲窗口 [free, parentEnd) 初始为整个父范围。
 * 依次考察按起点排序的占用块 [s,e)：
 *   1. 若 s > free，先尝试在 [free, s) 内放置对齐块；
 *   2. 该块放不下时，把窗口起点推进到 max(free, e)（重叠的占用自动合并）。
 * 扫描结束后再尝试尾部的剩余窗口。复杂度仅与直属子前缀数量相关，
 * 不按地址数枚举，因此对 IPv6 /128 的场景同样安全。
 *
 * @param {object} parent  { family, length, start, end }
 * @param {number} targetLength 目标前缀长度（必须大于父长度）
 * @param {Array<{start:bigint,end:bigint}>} occupied
 *        父范围内所有直属有效子分配/保留（半开区间）
 * @returns {{start:bigint,end:bigint,cidr:string}} 或 null（空间不足）
 */
function findSmallestFree(parent, targetLength, occupied) {
  const bits = FAM_BITS[parent.family];
  if (targetLength <= parent.length || targetLength > bits) return null;

  const blockSize =
    targetLength === bits ? 1n : 1n << BigInt(bits - targetLength);

  const blocks = occupied
    .map((o) => ({ start: BigInt(o.start), end: BigInt(o.end) }))
    .filter((o) => o.start < parent.end && o.end > parent.start)
    .sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));

  const tryPlace = (free, limit) => {
    // 首个不小于 free 的 targetLength 对齐位置
    let cur = free;
    const rem = cur % blockSize;
    if (rem !== 0n) cur += blockSize - rem;
    if (cur + blockSize <= limit) {
      return {
        start: cur,
        end: cur + blockSize,
        cidr: formatCidr(parent.family, cur, targetLength),
      };
    }
    return null;
  };

  let free = parent.start;
  for (const b of blocks) {
    if (b.start > free) {
      const hit = tryPlace(free, b.start);
      if (hit) return hit;
    }
    if (b.end > free) free = b.end;
    if (free >= parent.end) return null;
  }
  return tryPlace(free, parent.end);
}

/** 数据库 NUMERIC 字符串 → BigInt */
function toBigInt(value) {
  return typeof value === 'bigint' ? value : BigInt(value);
}

module.exports = {
  FAM_BITS,
  FAM_NAME,
  parseCidr,
  formatCidr,
  isAligned,
  isStrictlyInside,
  findSmallestFree,
  toBigInt,
};
