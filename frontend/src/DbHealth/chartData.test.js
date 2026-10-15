/**
 * The data behind the pictures, and the formatting that feeds them.
 *
 * These are the parts where a quiet mistake is invisible on screen: a ranking
 * that silently drops its largest row, a day series sorted by size instead of
 * by date, a number read as a year.
 */
import {
  archiveSeries,
  compactNumber,
  expiringAccounts,
  formatSeconds,
  topSegments,
  topSqlByTime,
} from "./chartData";
import { formatValue } from "./dbHealthFormat";

describe("numbers at tile size", () => {
  it("keeps small numbers whole and groups the thousands", () => {
    expect(compactNumber(0)).toBe("0");
    expect(compactNumber(1284)).toBe("1,284");
  });

  it("compacts once the digits stop being readable", () => {
    expect(compactNumber(47074)).toBe("47.1K");
    expect(compactNumber(4200000)).toBe("4.2M");
    expect(compactNumber(2e9)).toBe("2B");
  });

  it("says so when there is no number", () => {
    expect(compactNumber(null)).toBe("—");
    expect(compactNumber("whenever")).toBe("—");
  });
});

describe("durations", () => {
  it("drops to milliseconds under a second, so 0.05s is not '0s'", () => {
    expect(formatSeconds(0.05)).toBe("50ms");
    expect(formatSeconds(0.99)).toBe("990ms");
  });

  it("keeps two decimals where seconds are the useful unit", () => {
    expect(formatSeconds(6.42)).toBe("6.42s");
    expect(formatSeconds(1)).toBe("1s");
  });

  it("goes to minutes past a minute", () => {
    expect(formatSeconds(135)).toBe("2m 15s");
  });
});

describe("rankings", () => {
  const record = {
    top_sql_elapsed: [
      { sql_id: "slow", elapsed_s: 10, executions: 5, avg_ms: 2000, sql_text: "select 1" },
      { sql_id: "mid", elapsed_s: 5, executions: 50, avg_ms: 100, sql_text: "select 2" },
      { sql_id: "idle", elapsed_s: 0, executions: 1, avg_ms: 0, sql_text: "select 3" },
    ],
    top_segments: [
      { segment_name: "BIG", owner: "SYS", segment_type: "TABLE", total_size_bytes: 48234496 },
      { segment_name: "SMALL", owner: "SYS", segment_type: "INDEX", total_size_bytes: 1024 },
    ],
  };

  it("puts the largest first and scales the rest against it", () => {
    const bars = topSqlByTime(record);
    expect(bars.map((b) => b.label)).toEqual(["slow", "mid"]);
    expect(bars[0].share).toBe(100);
    expect(bars[1].share).toBe(50);
  });

  it("leaves out rows with nothing to draw rather than drawing a zero bar", () => {
    expect(topSqlByTime(record).some((b) => b.label === "idle")).toBe(false);
  });

  it("carries the value as text, so the bar is never the only reading", () => {
    expect(topSqlByTime(record)[0].display).toBe("10s");
    expect(topSegments(record)[0].display).toBe("46 MB");
  });

  it("keeps the full statement for the tooltip", () => {
    expect(topSqlByTime(record)[0].title).toBe("select 1");
  });

  it("has nothing to draw for an engine that sent no such list", () => {
    expect(topSqlByTime({ engine: "redis" })).toEqual([]);
    expect(topSegments({})).toEqual([]);
  });
});

describe("archive volume per day", () => {
  const record = {
    archive_log_daily: [
      { day: "2026-09-29", day_name: "TUE", archives: 1, size_mb: 197.65 },
      { day: "2026-09-14", day_name: "MON", archives: 1, size_mb: 194 },
      { day: "2026-09-18", day_name: "FRI", archives: 2, size_mb: 362.31 },
    ],
  };

  it("runs in date order, not by size — the question is whether it is growing", () => {
    expect(archiveSeries(record).map((p) => p.day)).toEqual([
      "2026-09-14",
      "2026-09-18",
      "2026-09-29",
    ]);
  });

  it("scales every column against the busiest day", () => {
    const points = archiveSeries(record);
    expect(points[1].share).toBe(100);
    expect(Math.round(points[0].share)).toBe(54);
  });

  it("has nothing to plot when no day archived anything", () => {
    expect(archiveSeries({ archive_log_daily: [] })).toEqual([]);
  });
});

describe("expiring passwords", () => {
  const record = {
    user_accounts: [
      { username: "PDBADMIN", days_to_expire: 27, account_status: "OPEN" },
      { username: "URGENT", days_to_expire: 3, account_status: "OPEN" },
      { username: "FINE", days_to_expire: 300, account_status: "OPEN" },
    ],
  };

  it("names only the accounts that expire soon, soonest first", () => {
    expect(expiringAccounts(record).map((a) => a.username)).toEqual(["URGENT", "PDBADMIN"]);
  });

  it("treats the last week as a different kind of urgent", () => {
    const [urgent, soon] = expiringAccounts(record);
    expect(urgent.level).toBe("bad");
    expect(soon.level).toBe("warn");
  });
});

describe("reading a value by its shape, not by its key", () => {
  it('does not read the "180" in pwd_life_time as the year 180', () => {
    expect(formatValue("pwd_life_time", "180")).toBe("180");
  });

  it("formats a full instant", () => {
    expect(formatValue("created", "2026-04-29T01:35:46")).toMatch(/29 Apr 2026/);
  });

  it("does not invent a time of day for a date that has none", () => {
    const shown = formatValue("day", "2026-09-14");
    // "Sep" or "Sept" depending on the ICU build the runtime was compiled with
    expect(shown).toMatch(/14 Sept? 2026/);
    expect(shown).not.toMatch(/00:00/);
  });
});
