/**
 * /available-services answers with `available_engines` as an OBJECT keyed by
 * engine name, each value the services stored for it:
 *
 *   { postgresql: [{ service_name, is_enable }], nginx: [] }
 *
 * The panel shows one row per engine, expands to that engine's services, and
 * each service toggles through /pause-service and /restart-service.
 */
import React from "react";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import Dashboard from "./Dashboard";
import api from "../api/api";

const mockAgents = [
  { id: 1, agent_name: "UpdatedWindowAgent", host_name: "WIN", main_ip: "10.0.0.1", os: "Windows", release: "10", status: "active", group_name: "default", machine_architecture: "x64" },
];

const availableEngines = {
  postgresql: [
    { service_name: "databasepg3", is_enable: true },
    { service_name: "databasepg4", is_enable: false },
  ],
  nginx: [],
};

// CRA runs jest with resetMocks:true, so implementations are set per test.
jest.mock("../api/api", () => ({
  __esModule: true,
  default: { get: jest.fn(), post: jest.fn(), delete: jest.fn() },
  logout: jest.fn(),
}));

beforeEach(() => {
  api.get.mockImplementation((url) => {
    if (String(url).includes("get-agents")) {
      return Promise.resolve({ data: { status: "success", data: { agents: mockAgents } } });
    }
    if (String(url).includes("available-services")) {
      return Promise.resolve({
        data: {
          status: "success",
          message: "Available services fetched successfully",
          data: { available_engines: availableEngines },
        },
      });
    }
    return Promise.resolve({ data: { status: "success", data: {} } });
  });
});

async function openServices() {
  render(
    <MemoryRouter>
      <Dashboard />
    </MemoryRouter>
  );
  await waitFor(() => expect(screen.getByText("UpdatedWindowAgent")).toBeInTheDocument());

  fireEvent.click(screen.getByTitle(/show available services/i));
  await waitFor(() => expect(screen.getByText("postgresql")).toBeInTheDocument());
}

/** The engine row for `engine`. */
function engineRow(engine) {
  return screen.getByText(engine).closest("tr");
}

test("every engine gets a row, including one with no services", async () => {
  await openServices();

  expect(screen.getByText("postgresql")).toBeInTheDocument();
  expect(screen.getByText("nginx")).toBeInTheDocument();
});

test("the row says how many services the engine has", async () => {
  await openServices();

  expect(within(engineRow("postgresql")).getByText("2 services")).toBeInTheDocument();
  expect(within(engineRow("nginx")).getByText(/no services yet/i)).toBeInTheDocument();
});

test("an engine with no services offers nothing to expand", async () => {
  await openServices();

  expect(within(engineRow("nginx")).queryByTitle(/show nginx services/i)).not.toBeInTheDocument();
});

test("+ reveals that engine's services, and nothing else's", async () => {
  await openServices();

  expect(screen.queryByText("databasepg3")).not.toBeInTheDocument();

  fireEvent.click(screen.getByTitle(/show postgresql services/i));

  expect(screen.getByText("databasepg3")).toBeInTheDocument();
  expect(screen.getByText("databasepg4")).toBeInTheDocument();
});

test("each service shows its state as a toggle", async () => {
  await openServices();
  fireEvent.click(screen.getByTitle(/show postgresql services/i));
  expect(screen.getByTitle(/pause databasepg3/i)).toHaveTextContent("Enabled");
  expect(screen.getByTitle(/start databasepg4/i)).toHaveTextContent("Disabled");
});

test("turning an enabled service off calls /pause-service", async () => {
  await openServices();
  fireEvent.click(screen.getByTitle(/show postgresql services/i));

  fireEvent.click(screen.getByTitle(/pause databasepg3/i));

  await waitFor(() =>
    expect(api.get).toHaveBeenCalledWith("/pause-service", {
      params: { agent_name: "UpdatedWindowAgent", service_name: "databasepg3" },
    })
  );
  await waitFor(() => expect(screen.getByTitle(/start databasepg3/i)).toHaveTextContent("Disabled"));
});

test("turning a disabled service on calls /restart-service", async () => {
  await openServices();
  fireEvent.click(screen.getByTitle(/show postgresql services/i));

  fireEvent.click(screen.getByTitle(/start databasepg4/i));

  await waitFor(() =>
    expect(api.get).toHaveBeenCalledWith("/restart-service", {
      params: { agent_name: "UpdatedWindowAgent", service_name: "databasepg4" },
    })
  );
  await waitFor(() => expect(screen.getByTitle(/pause databasepg4/i)).toHaveTextContent("Enabled"));
});

test("a failed toggle is reported and leaves the row alone", async () => {
  await openServices();
  fireEvent.click(screen.getByTitle(/show postgresql services/i));

  api.get.mockRejectedValueOnce({ response: { status: 504, data: { detail: "Agent did not respond" } } });
  fireEvent.click(screen.getByTitle(/pause databasepg3/i));

  expect(await screen.findByRole("alert")).toHaveTextContent(/did not respond/i);
  expect(screen.getByTitle(/pause databasepg3/i)).toHaveTextContent("Enabled");
});

describe("adding a credential from an engine row", () => {
  async function openAddForm(engine) {
    await openServices();
    fireEvent.click(
      within(engineRow(engine)).getByRole("button", { name: /add credential/i })
    );
  }

  test("the row offers Add credential, not a view link", async () => {
    await openServices();

    expect(
      within(engineRow("postgresql")).getByRole("button", { name: /add credential/i })
    ).toBeInTheDocument();
    expect(screen.queryByText(/view credentials/i)).not.toBeInTheDocument();
  });

  test("the engine it was opened from is filled in", async () => {
    await openAddForm("postgresql");

    expect(screen.getByPlaceholderText("postgresql")).toHaveValue("postgresql");
  });

  test("the host defaults to the agent address, the port to the engine default", async () => {
    await openAddForm("postgresql");

    expect(screen.getByDisplayValue("10.0.0.1")).toBeInTheDocument();
    expect(screen.getByDisplayValue("5432")).toBeInTheDocument();
  });

  test("nginx gets port 80 rather than a database port", async () => {
    await openServices();
    fireEvent.click(
      within(engineRow("nginx")).getByRole("button", { name: /add credential/i })
    );

    expect(screen.getByDisplayValue("80")).toBeInTheDocument();
  });

  test("saving without a service name is refused", async () => {
    await openAddForm("postgresql");

    fireEvent.change(screen.getByPlaceholderText("db_user"), {
      target: { value: "admin" },
    });
    fireEvent.submit(document.querySelector("form.cred-form"));

    expect(await screen.findByText(/service name is required/i)).toBeInTheDocument();
    expect(api.post).not.toHaveBeenCalled();
  });

  test("with a service name it posts the credential", async () => {
    api.post.mockResolvedValue({ data: { status: "success" } });
    await openAddForm("postgresql");

    fireEvent.change(screen.getByPlaceholderText("db_user"), {
      target: { value: "admin" },
    });
    fireEvent.change(screen.getByPlaceholderText("postgres"), {
      target: { value: "databasepg9" },
    });
    fireEvent.submit(document.querySelector("form.cred-form"));

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        "/add-credential",
        expect.objectContaining({
          engine: "postgresql",
          agent_name: "UpdatedWindowAgent",
          service_name: "databasepg9",
          host: "10.0.0.1",
          port: 5432,
        })
      )
    );
  });
});

/**
 * Deleting a credential also tells the agent to stop that service, so the row
 * asks before it goes, and only disappears once the server has confirmed.
 */
describe("deleting a service", () => {
  async function openPostgres() {
    await openServices();
    fireEvent.click(screen.getByTitle(/show postgresql services/i));
  }

  test("the row offers Delete", async () => {
    await openPostgres();

    expect(screen.getByTitle(/delete databasepg3/i)).toBeInTheDocument();
  });

  test("one click asks rather than deletes", async () => {
    await openPostgres();

    fireEvent.click(screen.getByTitle(/delete databasepg3/i));

    expect(screen.getByText("Delete?")).toBeInTheDocument();
    expect(api.delete).not.toHaveBeenCalled();
  });

  test("No backs out and leaves the row alone", async () => {
    await openPostgres();

    fireEvent.click(screen.getByTitle(/delete databasepg3/i));
    fireEvent.click(screen.getByRole("button", { name: "No" }));

    expect(api.delete).not.toHaveBeenCalled();
    expect(screen.getByText("databasepg3")).toBeInTheDocument();
  });

  test("Yes calls DELETE /delete-credential with the agent and service", async () => {
    api.delete.mockResolvedValue({ data: { status: "success" } });
    await openPostgres();

    fireEvent.click(screen.getByTitle(/delete databasepg3/i));
    fireEvent.click(screen.getByRole("button", { name: "Yes" }));

    await waitFor(() =>
      expect(api.delete).toHaveBeenCalledWith("/delete-credential", {
        params: { agent_name: "UpdatedWindowAgent", service_name: "databasepg3" },
      })
    );
  });

  test("the row goes once the server confirms — and only that row", async () => {
    api.delete.mockResolvedValue({ data: { status: "success" } });
    await openPostgres();

    fireEvent.click(screen.getByTitle(/delete databasepg3/i));
    fireEvent.click(screen.getByRole("button", { name: "Yes" }));

    await waitFor(() => expect(screen.queryByText("databasepg3")).not.toBeInTheDocument());
    expect(screen.getByText("databasepg4")).toBeInTheDocument();
  });

  test("a failed delete keeps the row and says why", async () => {
    api.delete.mockRejectedValueOnce({
      response: { status: 404, data: { detail: "Credential not found" } },
    });
    await openPostgres();

    fireEvent.click(screen.getByTitle(/delete databasepg3/i));
    fireEvent.click(screen.getByRole("button", { name: "Yes" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/was not found/i);
    expect(screen.getByText("databasepg3")).toBeInTheDocument();
  });
});

/**
 * Saving used to turn the add form into the credentials list for that engine.
 * The form was opened to add one entry; once that is done it should get out of
 * the way, and the new row in the services table is the confirmation.
 */
describe("after the credential is added", () => {
  async function addOne() {
    api.post.mockResolvedValue({ data: { status: "success" } });
    await openServices();
    fireEvent.click(
      within(engineRow("postgresql")).getByRole("button", { name: /add credential/i })
    );

    fireEvent.change(screen.getByPlaceholderText("db_user"), {
      target: { value: "admin" },
    });
    fireEvent.change(screen.getByPlaceholderText("postgres"), {
      target: { value: "databasepg9" },
    });
    fireEvent.submit(document.querySelector("form.cred-form"));
  }

  test("the popup closes instead of showing the credentials list", async () => {
    await addOne();

    await waitFor(() =>
      expect(document.querySelector("form.cred-form")).not.toBeInTheDocument()
    );
    expect(screen.queryByText(/credentials/i)).not.toBeInTheDocument();
  });

  test("the services list is re-read, so the new service shows up", async () => {
    await addOne();

    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith("/available-services", {
        params: { agent_name: "UpdatedWindowAgent" },
      })
    );
  });

  test("the panel says what was added", async () => {
    await addOne();

    expect(await screen.findByRole("status")).toHaveTextContent(
      /databasepg9 added to postgresql/i
    );
  });
});
