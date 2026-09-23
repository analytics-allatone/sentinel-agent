/**
 * The stored health record for one database. The payload is engine-shaped —
 * these fixtures are the real MySQL response — so the page is asserted on what
 * it does with the shape, not on a fixed set of keys.
 */
import React from "react";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";

import DbHealthPage from "./DbHealthPage";
import api from "../api/api";

jest.mock("../api/api", () => ({
  __esModule: true,
  default: { get: jest.fn() },
  logout: jest.fn(),
}));

const record = {
  basic_connectivity: {
    version: "8.0.46",
    currentuser: "root@localhost",
    server_host: "WINDOWS-EP8PIFQ",
    server_port: 3306,
    current_database: "sentinelagent",
  },
  database_size: {
    databases: [
      { tables: 38, datname: "mysql", size_bytes: 2736128 },
      { tables: 1, datname: "sentinelagent", size_bytes: 16384 },
    ],
    current_database: "sentinelagent",
    current_db_size_bytes: 16384,
  },
  locks_blocking: { blocking: [] },
  cache_hit_ratio: { disk_reads: 893, read_requests: 780561, buffer_pool_hit_pct: 99.89 },
  transaction_wraparound: { not_applicable: "No XID wraparound concept in MySQL/InnoDB" },
  health_summary: {
    check_time: null,
    db_size_bytes: 16384,
    active_queries: 2,
    uptime_seconds: 259465,
    current_database: "sentinelagent",
    total_connections: 1,
  },
  id: 23,
  agent_name: "agent1",
  engine: "mysql",
  health_status: "degraded",
  db_host: "127.0.0.1",
  db_port: 3306,
  db_version: "8.0.46",
  issues: [],
  timestamp: "2026-09-14T11:21:46.916683+00:00",
};

const response = {
  data: {
    status: "success",
    message: "stored database data",
    data: { engine: "mysql", host: null, service_name: "sql3", count: 1, latest: record, rows: [record] },
  },
};

beforeEach(() => {
  api.get.mockResolvedValue(response);
});

/** Wait for a region of the page to exist, then hand it back. */
async function region(selector) {
  return waitFor(() => {
    const el = document.querySelector(selector);
    if (!el) throw new Error(`${selector} not rendered yet`);
    return el;
  });
}

/** The value of one headline stat, by its label. */
async function statValue(label) {
  const stats = await region(".dbh-stats");
  const stat = within(stats).getByText(label).closest(".dbh-stat");
  return stat.querySelector(".dbh-stat-value").textContent;
}

/** The check card with this title. */
async function checkCard(title) {
  const cards = await region(".dbh-cards");
  return within(cards).getByText(title).closest("section");
}

function renderPage(query = "?agent=agent1&engine=mysql&service=sql3") {
  return render(
    <MemoryRouter initialEntries={[`/app/db-health${query}`]}>
      <Routes>
        <Route path="/app/dashboard" element={<div>Dashboard page</div>} />
        <Route path="/app/db-health" element={<DbHealthPage />} />
      </Routes>
    </MemoryRouter>
  );
}

test("it reads the database named in the address", async () => {
  renderPage();

  await waitFor(() =>
    expect(api.get).toHaveBeenCalledWith("/api/db/data", {
      params: {
        agent_name: "agent1",
        engine: "mysql",
        service_name: "sql3",
        limit: 1,
        compact: false,
      },
      skipGlobalLoader: true,
    })
  );
});

test("the heading names the service and its health", async () => {
  renderPage();

  const heading = await screen.findByRole("heading", { level: 1 });
  expect(heading).toHaveTextContent("sql3");
  expect(heading).toHaveTextContent("degraded");
});

test("sizes are shown as sizes and uptime as a duration, not raw numbers", async () => {
  renderPage();

  expect(await statValue("Database size")).toBe("16 KB"); // 16384 bytes
  expect(await statValue("Uptime")).toBe("3d 0h 4m"); // 259465 seconds
  expect(await statValue("Cache hit")).toBe("99.89%");
});

test("a list of objects inside a check becomes a table", async () => {
  renderPage();

  const card = await checkCard("Database size");
  const table = within(card).getByRole("table");
  expect(within(table).getByText("mysql")).toBeInTheDocument();
  expect(within(table).getByText("2.6 MB")).toBeInTheDocument(); // 2736128 bytes
});

test("an empty check says so rather than rendering nothing", async () => {
  renderPage();

  const card = await checkCard("Locks blocking");
  expect(within(card).getByText(/nothing reported/i)).toBeInTheDocument();
});

test("a check the page has no special knowledge of still renders", async () => {
  renderPage();

  expect(await screen.findByText("Transaction wraparound")).toBeInTheDocument();
  expect(screen.getByText(/No XID wraparound concept/)).toBeInTheDocument();
});

test("changing limit and compact re-reads with those values", async () => {
  renderPage();
  await statValue("Database size");

  fireEvent.change(screen.getByRole("spinbutton"), { target: { value: "50" } });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(screen.getByRole("button", { name: /^load$/i }));

  await waitFor(() =>
    expect(api.get).toHaveBeenLastCalledWith(
      "/api/db/data",
      expect.objectContaining({
        params: expect.objectContaining({ limit: 50, compact: true }),
      })
    )
  );
});

test("a limit past 500 is clamped rather than sent off to fail", async () => {
  renderPage();
  await statValue("Database size");

  fireEvent.change(screen.getByRole("spinbutton"), { target: { value: "9000" } });
  fireEvent.click(screen.getByRole("button", { name: /^load$/i }));

  await waitFor(() =>
    expect(api.get).toHaveBeenLastCalledWith(
      "/api/db/data",
      expect.objectContaining({ params: expect.objectContaining({ limit: 500 }) })
    )
  );
});

test("several readings offer a picker, and it switches record", async () => {
  const older = { ...record, id: 22, timestamp: "2026-09-13T09:00:00+00:00", health_status: "healthy" };
  api.get.mockResolvedValue({
    data: { data: { engine: "mysql", count: 2, rows: [record, older] } },
  });
  renderPage();

  const tabs = await screen.findAllByRole("tab");
  expect(tabs).toHaveLength(2);

  fireEvent.click(tabs[1]);

  expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("healthy");
});

test("nothing stored yet is explained", async () => {
  api.get.mockRejectedValue({
    response: { status: 404, data: { detail: "no stored data yet for that database" } },
  });
  renderPage();

  expect(await screen.findByRole("alert")).toHaveTextContent(/no stored data yet/i);
});

test("an address missing its agent says so instead of calling the API", async () => {
  renderPage("?service=sql3");

  expect(await screen.findByRole("alert")).toHaveTextContent(/needs an agent/i);
  expect(api.get).not.toHaveBeenCalled();
});

/**
 * The other half of reality: a database the agent *found* but never read.
 * Every check comes back null and the only useful field is `notes`, so the
 * page has to explain itself rather than print a wall of dashes.
 */
const NOT_INSPECTED = {
  sessions_current: null,
  sessions_active: null,
  cache_hit_pct: null,
  health_summary: null,
  uptime_seconds: null,
  database_role: null,
  id: 481,
  agent_name: "shiv1",
  service_name: "freepdb1",
  engine: "oracle",
  action: "db_detected",
  outcome: "success",
  severity: "low",
  collector: "db_discovery",
  tags: ["database", "inspect", "oracle"],
  notes: "driver unavailable for oracle: No module named collectors.dbprobe.oracle",
  inspected: false,
  health_status: null,
  target_name: "oracle@141.148.220.11",
  db_host: "141.148.220.11",
  db_port: 1521,
  db_version: null,
  issues: [],
  details: null,
  timestamp: "2026-09-21T10:39:36.740807+00:00",
};

describe("a database that was detected but not inspected", () => {
  beforeEach(() => {
    api.get.mockResolvedValue({
      data: {
        data: {
          engine: "oracle",
          service_name: "freepdb1",
          matched_on: "service_name",
          count: 1,
          latest: NOT_INSPECTED,
          rows: [NOT_INSPECTED],
        },
      },
    });
  });

  const renderOracle = () =>
    renderPage("?agent=shiv1&engine=oracle&service=freepdb1");

  test("the reason is stated at the top, not buried at the bottom", async () => {
    renderOracle();

    const notice = await screen.findByRole("status");
    expect(notice).toHaveTextContent(/detected, but not inspected/i);
    expect(notice).toHaveTextContent(/driver unavailable for oracle/i);
    expect(notice).toHaveTextContent("oracle@141.148.220.11");
  });

  test("the heading says what state it is in, rather than nothing", async () => {
    renderOracle();
    await screen.findByRole("status"); // the record has arrived

    const heading = screen.getByRole("heading", { level: 1 });
    expect(heading).toHaveTextContent("freepdb1");
    expect(heading).toHaveTextContent(/not inspected/i);
  });

  // A row of dashes reads as a broken page; no row reads as no measurements.
  test("no figures means no stat row at all", async () => {
    renderOracle();
    await screen.findByRole("status");

    expect(document.querySelector(".dbh-stats")).toBeNull();
  });

  test("what the agent did is shown as chips", async () => {
    renderOracle();
    await screen.findByRole("status");

    const chips = document.querySelector(".dbh-chips");
    expect(chips).toHaveTextContent("db_detected");
    expect(chips).toHaveTextContent("success");
    expect(chips).toHaveTextContent("db_discovery");
  });

  test("the empty fields are folded away, but kept", async () => {
    renderOracle();
    await screen.findByRole("status");

    // what is actually known is on the page
    expect(screen.getByText("141.148.220.11")).toBeInTheDocument();

    const toggle = screen.getByRole("button", { name: /show \d+ empty fields/i });
    expect(screen.queryByText("Database role")).not.toBeInTheDocument();

    fireEvent.click(toggle);

    expect(screen.getByText("Database role")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /hide \d+ empty fields/i })
    ).toBeInTheDocument();
  });

  describe("the record as a table", () => {
    /** The record card's table, whichever else is on the page. */
    const recordTable = () =>
      document.querySelector(".dbh-card--record table");

    /** One row of it, by the field name in the first cell. */
    const rowFor = (field) =>
      [...recordTable().querySelectorAll("tbody tr")].find(
        (tr) => tr.cells[0].textContent === field
      );

    test("it is a table of fields and values, one row each", async () => {
      renderOracle();
      await screen.findByRole("status");

      const table = recordTable();
      const headers = [...table.querySelectorAll("thead th")].map(
        (th) => th.textContent
      );
      expect(headers).toEqual(["Field", "Value"]);

      expect(rowFor("Agent name").cells[1]).toHaveTextContent("shiv1");
      expect(rowFor("Db port").cells[1]).toHaveTextContent("1,521");
      expect(rowFor("Inspected").cells[1]).toHaveTextContent("No");
      expect(rowFor("Notes").cells[1]).toHaveTextContent(/driver unavailable/i);
    });

    // A field the engine never filled is still a fact about the reading.
    test("an unmeasured field gets a row of its own, marked as empty", async () => {
      renderOracle();
      await screen.findByRole("status");

      fireEvent.click(screen.getByRole("button", { name: /show \d+ empty fields/i }));

      const row = rowFor("Database role");
      expect(row).toHaveClass("dbh-kv-row--empty");
      expect(row.cells[1]).toHaveTextContent("—");
    });

    test("the filter narrows the rows and says how many are left", async () => {
      renderOracle();
      await screen.findByRole("status");
      const before = recordTable().querySelectorAll("tbody tr").length;

      fireEvent.change(screen.getByLabelText(/filter record fields/i), {
        target: { value: "host" },
      });

      const rows = [...recordTable().querySelectorAll("tbody tr")];
      expect(rows.length).toBeLessThan(before);
      expect(rows.every((tr) => /host/i.test(tr.textContent))).toBe(true);
      expect(screen.getByText(`${rows.length} of ${before}`)).toBeInTheDocument();
    });

    test("a filter that matches nothing says so instead of showing an empty table", async () => {
      renderOracle();
      await screen.findByRole("status");

      fireEvent.change(screen.getByLabelText(/filter record fields/i), {
        target: { value: "zzz-nothing" },
      });

      expect(recordTable()).toBeNull();
      expect(screen.getByText(/no field matches that filter/i)).toBeInTheDocument();
    });
  });
});
