export function normalizeProto(value) {
  return String(value || "unknown").trim().toLowerCase() || "unknown";
}

export function isHoneypotInterface(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return normalized === "honeypot" || normalized.startsWith("honeypot:");
}

export function isHoneypotRow(row) {
  return isHoneypotInterface(row && row.interface);
}

export function truncateText(value, limit = 160) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (!text) return "";
  if (text.length <= limit) return text;
  return `${text.slice(0, Math.max(0, limit - 1)).trimEnd()}…`;
}

export function normalizeSearchText(value) {
  return String(value == null ? "" : value)
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

export function buildSearchText(values) {
  const source = Array.isArray(values) ? values : [values];
  return normalizeSearchText(
    source
      .map((value) => {
        if (typeof value === "string") return value;
        if (typeof value === "number" || typeof value === "boolean") return String(value);
        if (value && typeof value === "object") return JSON.stringify(value);
        return "";
      })
      .join(" ")
  );
}

export function matchesSearch(query, values) {
  const tokens = normalizeSearchText(query).split(" ").filter(Boolean);
  if (!tokens.length) return true;
  const haystack = buildSearchText(values);
  return tokens.every((token) => haystack.includes(token));
}

export function hasOptionValue(options, value) {
  const selected = normalizeSearchText(value);
  if (!selected) return true;
  return (Array.isArray(options) ? options : []).some((item) => {
    const optionValue = item && typeof item === "object" ? item.value : item;
    return normalizeSearchText(optionValue) === selected;
  });
}

export function formatTimestamp(value) {
  const text = String(value || "").trim();
  if (!text) return "-";
  const date = new Date(text);
  if (Number.isNaN(date.getTime())) return text;
  return date.toLocaleString();
}

export function formatEndpoint(ip, port) {
  const host = String(ip || "").trim();
  const numericPort = Number(port || 0);
  if (!host && !numericPort) return "-";
  if (!numericPort) return host || "-";
  return `${host || "?"}:${numericPort}`;
}

export function buildPacketDetail(row) {
  if (!row || typeof row !== "object") return "-";
  const proto = normalizeProto(row.proto);
  const parts = [];
  const flags = String(row.tcp_flags || "").trim();
  if (flags) parts.push(flags);
  if (proto === "icmp" || proto === "icmpv6") {
    parts.push(`type ${Number(row.icmp_type || 0)}`);
    parts.push(`code ${Number(row.icmp_code || 0)}`);
  }
  if (proto === "arp" && Number(row.arp_opcode || 0)) {
    parts.push(`opcode ${Number(row.arp_opcode || 0)}`);
  }
  return parts.filter(Boolean).join(" | ") || "-";
}

export function buildPacketSummary(row, limit = 150) {
  return truncateText(
    (row && (row.summary || row.banner_text || row.payload_text || row.banner)) || "",
    limit
  );
}

export function buildResponseSummary(row, limit = 150) {
  return truncateText((row && row.response_plain) || "", limit);
}

export function formatBytes(value) {
  const numeric = Number(value || 0);
  if (!Number.isFinite(numeric) || numeric <= 0) return "";
  return `${numeric}B`;
}

export function buildPacketSizeSummary(row) {
  if (!row || typeof row !== "object") return "-";
  const frame = formatBytes(row.length);
  const payload = formatBytes(row.payload_len);
  if (frame && payload) return `${frame} frame | ${payload} payload`;
  if (frame) return `${frame} frame`;
  if (payload) return `${payload} payload`;
  return "-";
}

export function buildPacketRouteSummary(row) {
  if (!row || typeof row !== "object") return "-";
  const parts = [];
  const ipVersion = Number(row.ip_version || 0);
  const ttl = Number(row.ttl || 0);
  const hopLimit = Number(row.hop_limit || 0);
  if (ipVersion > 0) {
    parts.push(`IPv${ipVersion}`);
  }
  if (ttl > 0) {
    parts.push(`TTL ${ttl}`);
  }
  if (hopLimit > 0) {
    parts.push(`Hop ${hopLimit}`);
  }
  return parts.join(" | ") || "-";
}

export function truncateMiddle(value, head = 12, tail = 12) {
  const text = String(value || "").trim();
  if (!text) return "";
  const safeHead = Math.max(1, Number(head) || 1);
  const safeTail = Math.max(1, Number(tail) || 1);
  if (text.length <= safeHead + safeTail + 3) {
    return text;
  }
  return `${text.slice(0, safeHead)}...${text.slice(-safeTail)}`;
}

export function uniqueSorted(values) {
  return [...new Set((Array.isArray(values) ? values : []).map((item) => String(item || "").trim()).filter(Boolean))].sort(
    (left, right) => left.localeCompare(right)
  );
}
