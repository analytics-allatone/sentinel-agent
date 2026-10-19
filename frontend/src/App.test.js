/**
 * The app mounts, and its router sends an address to the right page.
 *
 * This file used to hold create-react-app's "renders learn react link" — a
 * test for a starter page this product never had, which had been failing since
 * the first commit and so was never going to report anything.
 *
 * What is worth asserting instead is the thing that breaks a whole deploy: App
 * is the one module that imports every page, so a bad import or a route table
 * that throws takes the site down with a blank screen. Mounting it catches
 * that, and nothing else in the suite does.
 */
import { render, screen, waitFor } from "@testing-library/react";

import App from "./App";
import { getCookie } from "./api/api";

jest.mock("./api/api", () => ({
  __esModule: true,
  default: {
    get: jest.fn(() => Promise.resolve({ data: { data: {} } })),
    post: jest.fn(() => Promise.resolve({ data: { data: {} } })),
    interceptors: { request: { use: jest.fn() }, response: { use: jest.fn() } },
  },
  setCookie: jest.fn(),
  getCookie: jest.fn(() => null),
  deleteCookie: jest.fn(),
  clearAuthCookies: jest.fn(),
  logout: jest.fn(),
  // the loading overlay registers itself with the client on mount
  registerLoaderCallbacks: jest.fn(),
  triggerShowLoader: jest.fn(),
  triggerHideLoader: jest.fn(),
  pendingRequestCount: jest.fn(() => 0),
  API_PREFIX: "/api/v1",
  API_ORIGIN: "http://localhost:8000",
  API_BASE_URL: "http://localhost:8000/api/v1",
}));

/** App brings its own BrowserRouter, so the address is set before it mounts. */
function renderAt(path) {
  window.history.pushState({}, "", path);
  return render(<App />);
}

test("the login page is what an unknown visitor lands on", async () => {
  renderAt("/app/login");
  expect(await screen.findByRole("heading", { name: /welcome back/i })).toBeInTheDocument();
});

test("a route the app does not have lands on its own page, not a blank screen", async () => {
  renderAt("/app/no-such-page");
  await waitFor(() => expect(document.body.textContent.trim().length).toBeGreaterThan(0));
  expect(screen.queryByRole("heading", { name: /welcome back/i })).not.toBeInTheDocument();
});

test("the old /app/alerts address still works, filters and all", async () => {
  // the section was renamed, and this page keeps its whole view in the query
  // string — a link shared before the rename has to arrive intact.
  // A session, because /app/events is behind the route guard and a visitor
  // without one would be sent to login before the redirect could be seen.
  getCookie.mockReturnValue("a-session");
  renderAt("/app/alerts?sev=4&agent=shiv1");

  await waitFor(() => expect(window.location.pathname).toBe("/app/events"));
  expect(window.location.search).toBe("?sev=4&agent=shiv1");
});
