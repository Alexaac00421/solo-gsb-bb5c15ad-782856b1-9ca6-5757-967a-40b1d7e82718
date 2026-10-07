'use strict';

// Build a parent_id-linked forest from flat prefix rows (active only).
function buildTree(rows) {
  const byId = new Map();
  const nodes = rows.map((r) => ({ ...r, children: [] }));
  for (const n of nodes) byId.set(n.id, n);
  const roots = [];
  for (const n of nodes) {
    if (n.parent_id && byId.has(n.parent_id)) {
      byId.get(n.parent_id).children.push(n);
    } else {
      roots.push(n);
    }
  }
  const sortNode = (n) => {
    n.children.sort((a, b) => (BigInt(a.start_ip) < BigInt(b.start_ip) ? -1 : 1));
    n.children.forEach(sortNode);
  };
  roots.sort((a, b) => (BigInt(a.start_ip) < BigInt(b.start_ip) ? -1 : 1));
  roots.forEach(sortNode);
  return roots;
}

module.exports = { buildTree };
