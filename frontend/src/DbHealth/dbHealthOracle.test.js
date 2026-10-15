/**
 * The Oracle shape: a database that really was inspected.
 *
 * The MySQL fixtures next door cover a short, flat record. This one covers what
 * the richer payload brings with it — an envelope wrapped inside the envelope,
 * tablespaces that autoextend, "null" spelled as a four-character string, and
 * lists long enough to bury the page.
 */
import React from "react";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";

import DbHealthPage from "./DbHealthPage";
import api from "../api/api";
import {
  blockedSessions,
  hitRatios,
  memoryBreakdown,
  resourceLimits,
  isBlank,
  ratioLevel,
  tablespaces,
  unwrapRows,
  usageLevel,
} from "./dbHealthFormat";

jest.mock("../api/api", () => ({
  __esModule: true,
  default: { get: jest.fn() },
  logout: jest.fn(),
}));

const record = {
  sessions_current: 1,
  sessions_active: 1,
  sessions_blocked: 0,
  uptime_seconds: 29128,
  database_role: "PRIMARY",
  open_mode: "READ WRITE",
  cache_hit_pct: 98.87,
  library_hit_pct: 95.75,
  dict_hit_pct: 92.72,
  cache_hit_ratio: {
    library_hit_ratio: 95.75,
    dictionary_hit_ratio: 92.72,
    buffer_cache_hit_ratio: 98.87,
  },
  database_sizes: [
    // nearly full, but 32 TB of autoextend left: routine
    { datname: "SYSTEM", ts_type: "PERMANENT", used_mb: 298.9, free_mb: 1.1, total_mb: 300, max_mb: 33554432, pct_used: 99.65, pct_of_max: 0 },
    { datname: "SYSAUX", ts_type: "PERMANENT", used_mb: 509.9, free_mb: 30.1, total_mb: 540, max_mb: 33554432, pct_used: 94.43, pct_of_max: 0 },
    // all it will ever be, and nearly gone: the one worth a warning
    { datname: "FIXED", ts_type: "PERMANENT", used_mb: 97, free_mb: 3, total_mb: 100, max_mb: 100, pct_used: 97, pct_of_max: 97 },
  ],
  sessions_by_user: Array.from({ length: 50 }, (_, i) => ({
    username: "(background)",
    program: `oracle@host (BG${String(i).padStart(2, "0")})`,
    sessions: 1,
    machine: "274ae7bf37d4",
  })),
  memory: "null",
  details: "null",
  id: 2,
  agent_name: "shiv1",
  engine: "oracle",
  service_name: "freepdb1",
  inspected: true,
  health_status: "healthy",
  db_host: "141.148.220.11",
  db_port: 1521,
  db_version: "23.26.2.0.0",
  table_count: 2522,
  total_size_bytes: 993001472,
  issues: [],
  timestamp: "2026-09-29T12:20:24.333240+00:00",
};

/** What the endpoint really answers: an envelope whose `rows` is an envelope. */
const nested = {
  data: {
    status: "success",
    message: "stored database data",
    data: {
      engine: "oracle",
      service_name: "freepdb1",
      matched_on: "service_name",
      count: 3,
      rows: {
        status: "success",
        message: "stored database data",
        data: { engine: "oracle", service_name: "freepdb1", count: 1, rows: [record] },
      },
    },
  },
};

beforeEach(() => {
  api.get.mockResolvedValue(nested);
});

function renderPage(query = "?agent=shiv1&engine=oracle&service=freepdb1") {
  return render(
    <MemoryRouter initialEntries={[`/app/db-health${query}`]}>
      <Routes>
        <Route path="/app/dashboard" element={<div>Dashboard page</div>} />
        <Route path="/app/db-health" element={<DbHealthPage />} />
      </Routes>
    </MemoryRouter>
  );
}

async function region(selector) {
  return waitFor(() => {
    const el = document.querySelector(selector);
    if (!el) throw new Error(`${selector} not rendered yet`);
    return el;
  });
}

describe("unwrapping the response", () => {
  it("finds the records when rows is another whole envelope", () => {
    expect(unwrapRows(nested.data.data)).toEqual([record]);
  });

  it("still takes a plain list of rows", () => {
    expect(unwrapRows({ engine: "mysql", rows: [{ id: 1 }] })).toEqual([{ id: 1 }]);
  });

  it("gives back nothing rather than throwing on a shape it cannot follow", () => {
    expect(unwrapRows(null)).toEqual([]);
    expect(unwrapRows({ engine: "oracle" })).toEqual([]);
  });
});

describe("the ways this API spells empty", () => {
  it('treats the four-character string "null" as nothing', () => {
    expect(isBlank("null")).toBe(true);
    expect(isBlank("NULL")).toBe(true);
    expect(isBlank(null)).toBe(true);
    expect(isBlank("")).toBe(true);
  });

  it("does not swallow a real value", () => {
    expect(isBlank("PRIMARY")).toBe(false);
    expect(isBlank(0)).toBe(false);
    expect(isBlank(false)).toBe(false);
  });
});

describe("judging the figures", () => {
  it("reads a cache ratio as better when higher", () => {
    expect(ratioLevel(98.87)).toBe("ok");
    expect(ratioLevel(92.72)).toBe("warn");
    expect(ratioLevel(70)).toBe("bad");
  });

  it("reads space used as worse when higher", () => {
    expect(usageLevel(20)).toBe("ok");
    expect(usageLevel(88)).toBe("warn");
    expect(usageLevel(99)).toBe("bad");
  });

  it("collects the three Oracle hit ratios", () => {
    expect(hitRatios(record).map((r) => [r.label, r.value, r.level])).toEqual([
      ["Buffer cache", 98.87, "ok"],
      ["Library cache", 95.75, "ok"],
      ["Dictionary cache", 92.72, "warn"],
    ]);
  });

  it("has nothing to show for an engine that reports no ratios", () => {
    expect(hitRatios({ engine: "redis" })).toEqual([]);
  });
});

describe("tablespace pressure", () => {
  const spaces = tablespaces(record);
  const byName = (name) => spaces.find((t) => t.name === name);

  it("does not cry wolf over a datafile that can still autoextend", () => {
    // 99.65% of what it has, but 32 TB of room left to take
    const system = byName("SYSTEM");
    expect(system.pctUsed).toBe(99.65);
    expect(system.canGrow).toBe(true);
    expect(system.level).toBe("ok");
  });

  it("warns on the one that cannot grow", () => {
    const fixed = byName("FIXED");
    expect(fixed.canGrow).toBe(false);
    expect(fixed.level).toBe("bad");
  });

  it("puts the tablespace under real pressure first", () => {
    expect(spaces[0].name).toBe("FIXED");
  });

  it("falls back to how full it is when nothing is under pressure", () => {
    // every autoextending tablespace sits at ~0% of its maximum, so without a
    // tiebreak the order would be arbitrary and a near-full SYSTEM could land last
    const extendable = spaces.filter((t) => t.canGrow).map((t) => t.name);
    expect(extendable).toEqual(["SYSTEM", "SYSAUX"]);
  });

  it("does not let a hundredth of a percent outrank a nearly-full datafile", () => {
    // TEMP reports 0.01% of its maximum against SYSTEM's 0 — a rounding error,
    // not a reason to put a fifth-full tablespace above an almost-full one
    const withTemp = tablespaces({
      database_sizes: [
        ...record.database_sizes,
        { datname: "TEMP", ts_type: "TEMP", used_mb: 4, free_mb: 16, total_mb: 20, max_mb: 32768, pct_used: 20, pct_of_max: 0.01 },
      ],
    });
    expect(withTemp.map((t) => t.name)).toEqual(["FIXED", "SYSTEM", "SYSAUX", "TEMP"]);
  });

  it("has nothing to show when the engine sent no sizes", () => {
    expect(tablespaces({ engine: "redis" })).toEqual([]);
  });
});

describe("the page, on the real payload", () => {
  it("renders the record that the nested envelope was hiding", async () => {
    renderPage();
    expect(await screen.findByText("freepdb1")).toBeInTheDocument();
    // The heading carries the service name straight from the address, so that
    // alone proves nothing: the badge only appears once a record has arrived.
    // "healthy" is a meter word too, hence the badge rather than the text.
    expect((await region(".dbh-badge")).textContent).toBe("healthy");
  });

  it("draws the cache ratios as meters, with the state in words", async () => {
    renderPage();
    const meters = await region(".dbh-meters");
    expect(within(meters).getByText("Buffer cache")).toBeInTheDocument();
    expect(within(meters).getByText("98.87%")).toBeInTheDocument();
    // the colour is not the only channel
    expect(within(meters).getAllByText("healthy").length).toBe(2);
    expect(within(meters).getByText("low")).toBeInTheDocument();
  });

  it("draws a bar per tablespace and explains the autoextend headroom", async () => {
    renderPage();
    const spaces = await region(".dbh-ts-list");
    expect(within(spaces).getByText("SYSTEM")).toBeInTheDocument();
    expect(
      within(spaces).getByText(/99\.65% of allocated · can extend to/)
    ).toBeInTheDocument();
    expect(within(spaces).getByText(/97% of allocated · fixed size/)).toBeInTheDocument();
  });

  it("folds a fifty-row list down to a readable preview", async () => {
    renderPage();
    // sessions_by_user lives behind the Sessions tab
    const tabs = await region(".dbh-tabs");
    fireEvent.click(within(tabs).getByRole("tab", { name: /sessions/i }));
    const more = await screen.findByRole("button", { name: /Show all 50 rows/ });
    const card = more.closest("section");
    expect(within(card).getAllByRole("row").length).toBe(9); // header + 8

    fireEvent.click(more);
    await waitFor(() =>
      expect(within(card).getAllByRole("row").length).toBe(51)
    );
  });

  it('does not print "null" as if the database had reported it', async () => {
    renderPage();
    await region(".dbh-page");
    expect(screen.queryByText("null")).not.toBeInTheDocument();
  });
});

/* ───────────────────────────────────────────────────────────────
   The fuller payload: an instance with contention and real memory
   ─────────────────────────────────────────────────────────────── */

const busy = {
  ...record,
  locks_blocking: {
    blocked: [
      {
        blocked_sid: 145,
        blocking_sid: 302,
        username: "APP",
        event: "enq: TX - row lock contention",
        wait_class: "Application",
        seconds_in_wait: 87,
      },
      {
        blocked_sid: 150,
        blocking_sid: 302,
        username: "APP",
        event: "enq: TX - row lock contention",
        wait_class: "Application",
        seconds_in_wait: 12,
      },
    ],
  },
  memory: {
    sga_total_bytes: 2147483648,
    buffer_cache_bytes: 1073741824,
    shared_pool_bytes: 536870912,
    pga_allocated_bytes: 805306368,
    pga_inuse_bytes: 603979776,
  },
  resource_limits: [
    { resource_name: "processes", current_utilization: 88, max_utilization: 120, limit_value: "300" },
    { resource_name: "sessions", current_utilization: 95, max_utilization: 460, limit_value: "472" },
    { resource_name: "transactions", current_utilization: 4, max_utilization: 18, limit_value: "519" },
  ],
  index_usage: {
    monitoring_note: "per-index usage needs ALTER INDEX ... MONITORING USAGE",
    unusable_indexes: [{ owner: "APP", index_name: "IDX_ORDERS_CUSTID", status: "UNUSABLE" }],
  },
};

/** The envelope this engine sends: the records sit under `data`, not `rows`. */
const underData = {
  data: {
    status: "success",
    message: "stored database data",
    data: { engine: "postgresql", service_name: "post67", count: 1, data: [busy] },
  },
};

describe("the records under a `data` key", () => {
  it("finds them where this engine puts them", () => {
    expect(unwrapRows(underData.data.data)).toEqual([busy]);
  });
});

describe("sessions waiting on a lock", () => {
  it("reads the blocked list out of its wrapper", () => {
    expect(blockedSessions(busy).map((b) => b.blocked)).toEqual([145, 150]);
  });

  it("puts the longest wait first — that is the one that is stuck", () => {
    expect(blockedSessions(busy)[0].seconds).toBe(87);
  });

  it("treats a minute of waiting as worse than a moment of it", () => {
    const [longest, brief] = blockedSessions(busy);
    expect(longest.level).toBe("bad");
    expect(brief.level).toBe("warn");
  });

  it("has nothing to report on an engine that sent a bare empty list", () => {
    expect(blockedSessions({ locks_blocking: [] })).toEqual([]);
    expect(blockedSessions({})).toEqual([]);
  });
});

describe("resource limits", () => {
  const limits = resourceLimits(busy);
  const byName = (name) => limits.find((l) => l.name === name);

  it("judges a resource on its high-water mark, not on this moment", () => {
    // 95 of 472 in use looks calm; it has been to 460 of 472
    const sessions = byName("sessions");
    expect(Math.round(sessions.pct)).toBe(20);
    expect(Math.round(sessions.peakPct)).toBe(97);
    expect(sessions.level).toBe("bad");
  });

  it("leaves a resource with room alone", () => {
    expect(byName("transactions").level).toBe("ok");
  });

  it("puts the one closest to its limit first", () => {
    expect(limits[0].name).toBe("sessions");
  });
});

describe("memory", () => {
  it("shows the parts against the whole they belong to", () => {
    const memory = memoryBreakdown(busy);
    expect(memory.sga).toBe(2147483648);
    const cache = memory.parts.find((p) => p.label === "Buffer cache");
    // half the SGA, not half of all memory
    expect(Math.round(cache.pct)).toBe(50);
  });

  it("has nothing to show when the engine reported none", () => {
    expect(memoryBreakdown({ memory: "null" })).toBeNull();
    expect(memoryBreakdown({})).toBeNull();
  });
});

describe("the page, on an instance under contention", () => {
  beforeEach(() => {
    api.get.mockResolvedValue(underData);
  });

  it("puts the blocked sessions above everything it measures", async () => {
    renderPage();
    const card = await region(".dbh-card--blocked");
    expect(within(card).getByText(/SID 145/)).toBeInTheDocument();
    // one blocker, two victims — so 302 appears on both rows
    expect(within(card).getAllByText(/SID 302/).length).toBe(2);
    expect(within(card).getAllByText(/blocked by/).length).toBe(2);
  });

  it("marks the high-water mark on each limit", async () => {
    renderPage();
    const card = await region(".dbh-card--limits");
    expect(within(card).getByText(/peak 460/)).toBeInTheDocument();
    expect(card.querySelectorAll(".dbh-limit-peak").length).toBe(3);
  });

  it("names the indexes the optimiser cannot use", async () => {
    renderPage();
    const card = await region(".dbh-card--unusable");
    expect(within(card).getByText("IDX_ORDERS_CUSTID")).toBeInTheDocument();
  });

  it("still says a check came back empty rather than dropping it", async () => {
    // locks_blocking has its own card only when somebody is waiting; when the
    // check ran and found nobody, the generic card has to say so
    api.get.mockResolvedValue({
      data: { data: { engine: "oracle", count: 1, data: [{ ...record, locks_blocking: [] }] } },
    });
    renderPage();
    const tabs = await region(".dbh-tabs");
    fireEvent.click(within(tabs).getByRole("tab", { name: /sessions/i }));
    const cards = await region(".dbh-cards");
    expect(within(cards).getByText("Locks blocking")).toBeInTheDocument();
    expect(document.querySelector(".dbh-card--blocked")).toBeNull();
  });
});

describe("forty-three cards behind six tabs", () => {
  beforeEach(() => {
    api.get.mockResolvedValue(nested);
  });

  it("opens on the overview, not on everything at once", async () => {
    renderPage();
    const tabs = await region(".dbh-tabs");
    expect(within(tabs).getByRole("tab", { name: /overview/i })).toHaveAttribute(
      "aria-selected",
      "true"
    );
  });

  it("shows only the open group's cards", async () => {
    renderPage();
    const panel = await region(".dbh-cards");
    const shown = within(panel).getAllByRole("heading", { level: 3 }).length;
    const total = document.querySelectorAll(".dbh-tab-count").length;
    // a page of everything is what the tabs exist to avoid
    expect(shown).toBeGreaterThan(0);
    expect(total).toBeGreaterThan(1);
    expect(shown).toBeLessThan(20);
  });

  it("says how many cards each closed tab is holding", async () => {
    renderPage();
    const tabs = await region(".dbh-tabs");
    const counts = [...tabs.querySelectorAll(".dbh-tab-count")].map((c) => Number(c.textContent));
    expect(counts.every((n) => n > 0)).toBe(true);
  });

  it("loses no check: every card is inside exactly one tab", async () => {
    renderPage();
    const tabs = await region(".dbh-tabs");
    const promised = [...tabs.querySelectorAll(".dbh-tab-count")].reduce(
      (sum, c) => sum + Number(c.textContent),
      0
    );

    let seen = 0;
    for (const tab of within(tabs).getAllByRole("tab")) {
      fireEvent.click(tab);
      seen += document.querySelectorAll(".dbh-cards > section").length;
    }
    expect(seen).toBe(promised);
  });

  it("switches the panel when a tab is chosen", async () => {
    renderPage();
    const tabs = await region(".dbh-tabs");
    const before = document.querySelector(".dbh-cards").textContent;

    // whichever groups this record happens to fill — a thin record has fewer
    const [, second] = within(tabs).getAllByRole("tab");
    fireEvent.click(second);

    expect(document.querySelector(".dbh-cards").textContent).not.toBe(before);
    expect(second).toHaveAttribute("aria-selected", "true");
  });

  it("ties each panel to the tab that opens it", async () => {
    renderPage();
    const tabs = await region(".dbh-tabs");
    const open = within(tabs).getAllByRole("tab").find((t) => t.getAttribute("aria-selected") === "true");
    const panel = document.querySelector(".dbh-cards");
    expect(panel.getAttribute("aria-labelledby")).toBe(open.id);
    expect(open.getAttribute("aria-controls")).toBe(panel.id);
  });
});
