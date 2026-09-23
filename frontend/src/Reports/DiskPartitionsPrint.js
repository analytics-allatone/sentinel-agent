import React from "react";

import {
  DISK_CRITICAL,
  DISK_LEVEL_LABEL,
  DISK_WARN,
  bandCounts,
  diskLevel,
  formatGb,
  partitionRole,
  sumGb,
} from "./diskPartitions";

/**
 * The disk partitions page of the exported report.
 *
 * It is a page of the same tree the rest of the report uses, so both routes out
 * of this screen carry it: "Export to PDF" (the browser's own print-to-PDF over
 * `.capacity-dash__print`) and "Send Report" (html2canvas over each
 * `.capacity-dash__print-page`).
 *
 * Nothing renders when the agent reported no partitions — an empty table would
 * read as "no disks", which is a different claim from "not measured".
 */
export default function DiskPartitionsPrint({ partitions, pageNumber, pageCount }) {
  if (!partitions || partitions.length === 0) return null;

  const counts = bandCounts(partitions);

  return (
    <section className="capacity-dash__print-page capacity-dash__print-evidence-page">
      <div className="capacity-dash__print-page-number">
        {String(pageNumber).padStart(2, "0")}
      </div>

      <div className="capacity-dash__print-page-heading">
        <div className="capacity-dash__print-eyebrow">CAPACITY EVIDENCE</div>

        <h2 className="capacity-dash__print-evidence-title">Disk partitions</h2>

        <div className="capacity-dash__print-evidence-unit">
          Snapshot at the end of the window · {partitions.length}{" "}
          {partitions.length === 1 ? "volume" : "volumes"}
        </div>
      </div>

      <p className="capacity-dash__print-evidence-lead">
        The storage series averages every mounted volume into a single line.
        This table is the per-volume position, so one small partition close to
        full is visible rather than averaged away.
      </p>

      <div className="capacity-dash__print-disk-tally">
        <span className="capacity-dash__print-disk-tally-item capacity-dash__print-disk-pct--critical">
          {counts.critical} critical
        </span>
        <span className="capacity-dash__print-disk-tally-item capacity-dash__print-disk-pct--warn">
          {counts.warn} to watch
        </span>
        <span className="capacity-dash__print-disk-tally-item capacity-dash__print-disk-pct--ok">
          {counts.ok} healthy
        </span>
        <span className="capacity-dash__print-disk-tally-total">
          {formatGb(sumGb(partitions, "freeGb"))} free of{" "}
          {formatGb(sumGb(partitions, "totalGb"))}
        </span>
      </div>

      <table className="capacity-dash__print-disk-table">
        <thead>
          <tr>
            <th>Mount point</th>
            <th>Device</th>
            <th>Type</th>
            <th className="capacity-dash__print-disk-num">Used</th>
            <th className="capacity-dash__print-disk-num">Free</th>
            <th className="capacity-dash__print-disk-num">Total</th>
            <th className="capacity-dash__print-disk-num">Used %</th>
            <th>Status</th>
          </tr>
        </thead>

        <tbody>
          {partitions.map((part) => {
            const level = diskLevel(part.percent);
            const role = partitionRole(part.mountpoint);

            return (
              <tr key={part.device + "|" + part.mountpoint}>
                <td className="capacity-dash__print-disk-mount">
                  {part.mountpoint}
                  {role && (
                    <span className="capacity-dash__print-disk-role">{role}</span>
                  )}
                </td>
                <td>{part.device}</td>
                <td>{part.fstype || "—"}</td>
                <td className="capacity-dash__print-disk-num">
                  {formatGb(part.usedGb)}
                </td>
                <td className="capacity-dash__print-disk-num">
                  {formatGb(part.freeGb)}
                </td>
                <td className="capacity-dash__print-disk-num">
                  {formatGb(part.totalGb)}
                </td>
                <td
                  className={
                    "capacity-dash__print-disk-num capacity-dash__print-disk-pct " +
                    "capacity-dash__print-disk-pct--" +
                    level
                  }
                >
                  {part.percent.toFixed(1)}%
                </td>
                <td
                  className={
                    "capacity-dash__print-disk-status " +
                    "capacity-dash__print-disk-pct--" +
                    level
                  }
                >
                  {DISK_LEVEL_LABEL[level]}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <p className="capacity-dash__print-disk-note">
        Volumes at or above {DISK_CRITICAL}% are marked critical and those at or
        above {DISK_WARN}% are marked for attention. Figures are as reported by
        the agent at its last successful sample.
      </p>

      <div className="capacity-dash__print-page-footer">
        <span>GUARDLYNX · CAPACITY MONITORING</span>

        <span>
          CONFIDENTIAL · Page {pageNumber} of {pageCount}
        </span>
      </div>
    </section>
  );
}
