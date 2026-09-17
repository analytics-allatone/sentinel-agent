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
