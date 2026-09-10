/**
 * The Actions column can pause and resume an agent's collection.
 *
 * GET /toggle_status?agent_name=…&action=active|pause is forwarded to the agent
 * over MQTT, so the request is slow, the answer is authoritative, and an offline
 * agent produces a 504 rather than a change.
 */
import React from "react";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import Dashboard from "./Dashboard";
import api from "../api/api";

const mockAgents = [
  { id: 1, agent_name: "Mywindows", host_name: "WINBOX", main_ip: "10.0.0.1", os: "Windows", release: "10", status: "active", group_name: "default", machine_architecture: "x64" },
  { id: 2, agent_name: "linux-a", host_name: "UBU", main_ip: "10.0.0.2", os: "Ubuntu", release: "22.04", status: "pause", group_name: "default", machine_architecture: "x64" },
  { id: 3, agent_name: "gone-a", host_name: "OLD", main_ip: "10.0.0.3", os: "Windows", release: "10", status: "disconnected", group_name: "default", machine_architecture: "x64" },
  { id: 4, agent_name: "new-a", host_name: "NEW", main_ip: "10.0.0.4", os: "Linux", release: "6.1", status: "never_connected", group_name: "default", machine_architecture: "x64" },
];

// CRA runs jest with resetMocks:true, so implementations are set per test.
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
});

async function renderDashboard() {
  render(
    <MemoryRouter>
      <Dashboard />
    </MemoryRouter>
  );
  await waitFor(() => expect(screen.getByText("Mywindows")).toBeInTheDocument());
}

/** The toggle in the row for `name`. */
function toggleFor(name) {
  const row = screen.getByText(name).closest("tr");
  return within(row).getByTitle(/collection on|cannot be paused/i);
}

test("an active agent offers to pause, and asks the API to", async () => {
  await renderDashboard();
  api.get.mockResolvedValueOnce({ data: { success: true, status: "pause" } });

  expect(toggleFor("Mywindows")).toHaveTextContent("Active");
  fireEvent.click(toggleFor("Mywindows"));

  await waitFor(() =>
    expect(api.get).toHaveBeenCalledWith("/toggle_status", {
      params: { agent_name: "Mywindows", action: "pause" },
    })
  );
});

test("a paused agent asks for active instead", async () => {
  await renderDashboard();
  api.get.mockResolvedValueOnce({ data: { success: true, status: "active" } });

  expect(toggleFor("linux-a")).toHaveTextContent("Paused");
  fireEvent.click(toggleFor("linux-a"));

  await waitFor(() =>
    expect(api.get).toHaveBeenCalledWith("/toggle_status", {
      params: { agent_name: "linux-a", action: "active" },
    })
  );
});

test("the row follows the status the agent settled on, not the one requested", async () => {
  await renderDashboard();
  // asked to pause, but the agent reports it stayed active
  api.get.mockResolvedValueOnce({ data: { success: true, status: "active" } });

  fireEvent.click(toggleFor("Mywindows"));

  await waitFor(() => expect(toggleFor("Mywindows")).toHaveTextContent("Active"));
});

test("an offline agent (504) is reported and changes nothing", async () => {
  await renderDashboard();
  api.get.mockRejectedValueOnce({ response: { status: 504, data: { detail: "Agent did not respond" } } });

  fireEvent.click(toggleFor("Mywindows"));

  expect(await screen.findByRole("alert")).toHaveTextContent(/did not respond/i);
  expect(toggleFor("Mywindows")).toHaveTextContent("Active");
});

describe("agents that cannot answer", () => {
  test("a disconnected agent has an inert toggle", async () => {
    await renderDashboard();

    expect(toggleFor("gone-a")).toBeDisabled();
  });

  test("so does one that has never connected", async () => {
    await renderDashboard();

    expect(toggleFor("new-a")).toBeDisabled();
  });

  test("clicking it sends nothing", async () => {
    await renderDashboard();
    const callsBefore = api.get.mock.calls.length;

    fireEvent.click(toggleFor("gone-a"));

    expect(api.get).toHaveBeenCalledTimes(callsBefore);
  });

  test("it says why, rather than just being dead", async () => {
    await renderDashboard();

    expect(toggleFor("gone-a")).toHaveAttribute(
      "title",
      expect.stringContaining("cannot be paused or resumed")
    );
  });

  test("a paused agent stays clickable, or it could never be resumed", async () => {
    await renderDashboard();

    expect(toggleFor("linux-a")).toBeEnabled();
  });
});
