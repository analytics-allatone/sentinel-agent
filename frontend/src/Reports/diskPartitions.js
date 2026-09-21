/**
 * The mounted volumes the capacity API reports with each sample:
 *
 *   { device, mountpoint, fstype, percent, used_gb, total_gb, free_gb }
 *
 * This is a snapshot, not a series — it answers "what is full right now",
 * which the storage chart cannot: that line averages every partition together,
 * so one small volume at 98% disappears into it.
 *
 * Kept apart from the dashboard so it can be read and tested without pulling in
 * the charting and PDF libraries the page depends on.
 */

/** Usage bands, in the same language the agent's own severity rules use. */
export const DISK_WARN = 70;
export const DISK_CRITICAL = 85;

export function diskLevel(percent) {
  if (percent >= DISK_CRITICAL) return "critical";
  if (percent >= DISK_WARN) return "warn";
  return "ok";
}

/** Gigabytes, readable: precise for small volumes, no false precision for big. */
export function formatGb(value) {
  const n = Number(value);
  if (value == null || value === "" || Number.isNaN(n)) return "—";
  if (n >= 1024) return `${(n / 1024).toFixed(2)} TB`;
  return `${n.toFixed(n >= 100 ? 0 : 1)} GB`;
}

/**
 * The partitions of the latest sample, fullest first.
 *
 * Fullest first because that is the reading order that matters: the volume
 * about to run out is the one worth seeing, whatever its mount point sorts as.
 */
export function readPartitions(payload) {
  const list = payload && payload.disk_partitions;
  if (!Array.isArray(list)) return [];

  return list
    .filter((part) => part && (part.mountpoint || part.device))
    .map((part) => {
      const percent = Number(part.percent);
      return {
        device: part.device || "—",
        mountpoint: part.mountpoint || part.device,
        fstype: part.fstype || "",
        percent: Number.isFinite(percent) ? percent : 0,
        usedGb: part.used_gb,
        totalGb: part.total_gb,
        freeGb: part.free_gb,
      };
    })
    .sort((a, b) => b.percent - a.percent);
}

/** Totals across the volumes, skipping anything the agent could not measure. */
export function sumGb(partitions, key) {
  return partitions.reduce((total, part) => {
    const n = Number(part[key]);
    return Number.isFinite(n) ? total + n : total;
  }, 0);
}

/** What each band means in words, for people who do not read colour. */
export const DISK_LEVEL_LABEL = {
  ok: "Healthy",
  warn: "Watch",
  critical: "Critical",
};

/** How many volumes sit in each band — the one-line answer for the header. */
export function bandCounts(partitions) {
  return partitions.reduce(
    (counts, part) => {
      counts[diskLevel(part.percent)] += 1;
      return counts;
    },
    { ok: 0, warn: 0, critical: 0 }
  );
}

/**
 * What a mount point is *for*.
 *
 * "/dev/sdb1 at 96%" means nothing to most people reading a capacity report;
 * "Logs & variable data" tells them what fills up and what to clear. Only
 * well-known paths are named — a guess would be worse than silence.
 */
export function partitionRole(mountpoint) {
  const path = String(mountpoint || "").trim();
  if (!path) return "";

  const windowsDrive = /^([a-z]):\\?$/i.exec(path);
  if (windowsDrive) {
    return windowsDrive[1].toUpperCase() === "C"
      ? "System drive"
      : "Secondary drive";
  }

  const unix = path.replace(/\/+$/, "").toLowerCase() || "/";
  const known = {
    "/": "System root",
    "/boot": "Boot partition",
    "/boot/efi": "EFI boot partition",
    "/home": "User data",
    "/var": "Variable data",
    "/var/log": "Logs & variable data",
    "/var/lib/docker": "Container storage",
    "/tmp": "Temporary files",
    "/srv": "Served data",
    "/opt": "Optional software",
    "/usr": "System software",
  };
  if (known[unix]) return known[unix];

  if (unix.startsWith("/mnt/") || unix.startsWith("/media/")) {
    return "Mounted storage";
  }
  if (unix.startsWith("/var/log")) return "Logs & variable data";
  if (unix.startsWith("/home/")) return "User data";

  return "";
}
