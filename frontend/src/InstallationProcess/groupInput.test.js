/**
 * A group name ends up in a query parameter and in the install command the user
 * copies, so it must not contain spaces. Typing one is refused, pasting one is
 * cleaned, and either way the page says why.
 */
import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import InstallationProcess from "./InstallationProcess";

jest.mock("../api/api", () => ({
  __esModule: true,
  default: {
    get: jest.fn().mockResolvedValue({ data: { data: { groups: [] } } }),
    post: jest.fn().mockResolvedValue({ data: {} }),
  },
  logout: jest.fn(),
}));

function groupField() {
  return screen.getByPlaceholderText(/search or type a new group/i);
}

async function renderPage() {
  render(
    <MemoryRouter>
      <InstallationProcess />
    </MemoryRouter>
  );
  await waitFor(() => expect(groupField()).toBeEnabled());
}

test("a typed space never reaches the field", async () => {
  await renderPage();
  const input = groupField();

  fireEvent.change(input, { target: { value: "prod" } });
  fireEvent.keyDown(input, { key: " ", code: "Space" });

  expect(input).toHaveValue("prod");
});

test("typing a space explains why nothing happened", async () => {
  await renderPage();

  fireEvent.keyDown(groupField(), { key: " ", code: "Space" });

  expect(await screen.findByRole("alert")).toHaveTextContent(/spaces are not allowed/i);
});

test("a pasted name has its spaces stripped, not silently kept", async () => {
  await renderPage();
  const input = groupField();

  fireEvent.change(input, { target: { value: "prod web servers" } });

  expect(input).toHaveValue("prodwebservers");
  expect(screen.getByRole("alert")).toBeInTheDocument();
});

test("an ordinary name is left alone and raises nothing", async () => {
  await renderPage();
  const input = groupField();

  fireEvent.change(input, { target: { value: "prod-web_01" } });

  expect(input).toHaveValue("prod-web_01");
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});
