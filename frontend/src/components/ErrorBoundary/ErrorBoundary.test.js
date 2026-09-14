/**
 * A failing API usually does not throw where it is called — it leaves a screen
 * holding data it did not expect, and the throw lands in render. Without a
 * boundary React unmounts the whole tree and the user gets a white page.
 */
import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import ErrorBoundary from "./ErrorBoundary";

/** Stands in for a screen that got an error response where a list was expected. */
function BadScreen({ agents }) {
  return <div>{agents.map((a) => a.name)}</div>;
}

let consoleError;

beforeEach(() => {
  // React logs the caught error itself; keep the test output readable.
  consoleError = jest.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => consoleError.mockRestore());

test("a crashing page is replaced, not left blank", () => {
  render(
    <MemoryRouter>
      <ErrorBoundary>
        <BadScreen agents={undefined} />
      </ErrorBoundary>
    </MemoryRouter>
  );

  expect(screen.getByRole("alert")).toHaveTextContent(/something went wrong/i);
});

test("the rest of the app is still reachable from it", () => {
  render(
    <MemoryRouter>
      <ErrorBoundary>
        <BadScreen agents={undefined} />
      </ErrorBoundary>
    </MemoryRouter>
  );

  expect(screen.getByRole("link", { name: /dashboard/i })).toHaveAttribute(
    "href",
    "/app/dashboard"
  );
});

test("the detail is available but not shoved in the user's face", () => {
  render(
    <MemoryRouter>
      <ErrorBoundary>
        <BadScreen agents={undefined} />
      </ErrorBoundary>
    </MemoryRouter>
  );

  expect(screen.queryByText(/Cannot read properties/i)).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /show technical detail/i }));

  expect(screen.getByText(/Cannot read properties|undefined/i)).toBeInTheDocument();
});

test("Try again re-renders the page, so a transient failure recovers", () => {
  function Flaky({ shouldThrow }) {
    if (shouldThrow) throw new Error("API returned nothing");
    return <div>Recovered</div>;
  }

  const { rerender } = render(
    <MemoryRouter>
      <ErrorBoundary>
        <Flaky shouldThrow />
      </ErrorBoundary>
    </MemoryRouter>
  );

  expect(screen.getByRole("alert")).toBeInTheDocument();

  // the retry now succeeds — as it would once the API answers properly
  rerender(
    <MemoryRouter>
      <ErrorBoundary>
        <Flaky shouldThrow={false} />
      </ErrorBoundary>
    </MemoryRouter>
  );
  fireEvent.click(screen.getByRole("button", { name: /try again/i }));

  expect(screen.getByText("Recovered")).toBeInTheDocument();
});

test("a healthy page passes straight through", () => {
  render(
    <MemoryRouter>
      <ErrorBoundary>
        <div>All good</div>
      </ErrorBoundary>
    </MemoryRouter>
  );

  expect(screen.getByText("All good")).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});
