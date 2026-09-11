/**
 * The agents table filters on status and operating system, alongside the search
 * box. The OS one filters by family, because the stored `os` string is a full
 * build ("Windows 10 10.0.19045") and near-unique per host.
 */
import React from "react";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import Dashboard from "./Dashboard";
import api from "../api/api";

const mockAgents = [
  { id: 1, agent_name: "win-a", host_name: "WINBOX", main_ip: "10.0.0.1", os: "Windows", release: "10", version: "10.0.19045", status: "active", group_name: "default", machine_architecture: "x64" },
  { id: 2, agent_name: "ubuntu-a", host_name: "UBU", main_ip: "10.0.0.2", os: "Ubuntu", release: "22.04", version: "5.15", status: "disconnected", group_name: "default", machine_architecture: "x64" },
  { id: 3, agent_name: "win-b", host_name: "WINBOX2", main_ip: "10.0.0.3", os: "Windows", release: "11", version: "10.0.22631", status: "disconnected", group_name: "default", machine_architecture: "x64" },
];

// CRA runs jest with resetMocks:true, which strips any implementation given
// in the factory before each test — so the responses are set in beforeEach.
jest.mock("../api/api", () => ({
  __esModule: true,
  default: { get: jest.fn(), post: jest.fn() },
  logout: jest.fn(),
}));

beforeEach(() => {
  api.get.mockImplementation((url) =>
    String(url).includes("get-agents")
      ? Promise.resolve({ data: { status: "success", data: { agents: mockAgents } } })
      : Promise.resolve({ data: { status: "success", data: {} } })
  );
  api.post.mockResolvedValue({ data: {} });
});

async function renderDashboard() {
  render(
    <MemoryRouter>
      <Dashboard />
    </MemoryRouter>
  );
  await waitFor(() => expect(screen.getByText("win-a")).toBeInTheDocument());
}

function openFilters() {
  fireEvent.click(screen.getByRole("button", { name: /filters/i }));
  return screen.getByRole("group", { name: /filter agents/i });
}

/** The agent names on screen — read from the name link, not a cell index. */
function rowNames() {
  return [...document.querySelectorAll("table.agents-table .agent-name-link")].map((el) =>
    el.textContent.trim()
  );
}

test("filtering by status keeps only that status", async () => {
  await renderDashboard();
  const panel = openFilters();

  fireEvent.change(within(panel).getByLabelText(/status/i), {
    target: { value: "active" },
  });

  expect(rowNames()).toEqual(["win-a"]);
});

test("filtering by OS family matches the whole family, not the build string", async () => {
  await renderDashboard();
  const panel = openFilters();

  fireEvent.change(within(panel).getByLabelText(/operating system/i), {
    target: { value: "windows" },
  });

  expect(rowNames()).toEqual(["win-a", "win-b"]);
});

test("the two filters narrow together", async () => {
  await renderDashboard();
  const panel = openFilters();

  fireEvent.change(within(panel).getByLabelText(/operating system/i), {
    target: { value: "windows" },
  });
  fireEvent.change(within(panel).getByLabelText(/status/i), {
    target: { value: "disconnected" },
  });

  expect(rowNames()).toEqual(["win-b"]);
});

test("Clear puts every agent back", async () => {
  await renderDashboard();
  const panel = openFilters();

  fireEvent.change(within(panel).getByLabelText(/status/i), {
    target: { value: "active" },
  });
  fireEvent.click(within(panel).getByRole("button", { name: /clear/i }));

  expect(rowNames()).toHaveLength(3);
});

test("the button shows how many filters are on", async () => {
  await renderDashboard();
  const panel = openFilters();

  fireEvent.change(within(panel).getByLabelText(/status/i), {
    target: { value: "active" },
  });

  expect(screen.getByRole("button", { name: /filters/i })).toHaveTextContent("1");
});
