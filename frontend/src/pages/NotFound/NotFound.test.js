/**
 * The 404 page has one job beyond looking right: tell the visitor which address
 * missed, and give them somewhere real to go.
 */
import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";

import NotFound from "./NotFound";

function renderAt(path) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/app/dashboard" element={<div>Dashboard page</div>} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </MemoryRouter>
  );
}

test("it names the address that was asked for", () => {
  renderAt("/app/policies");

  expect(screen.getByText("/app/policies")).toBeInTheDocument();
});

test("the query string is shown too, since a bad parameter is a common cause", () => {
  renderAt("/app/reports/soc2x?agent=TestAgent");

  expect(screen.getByText("/app/reports/soc2x?agent=TestAgent")).toBeInTheDocument();
});

test("it announces itself as a 404", () => {
  renderAt("/nope");

  expect(screen.getByText("404")).toBeInTheDocument();
  expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("isn't on the map");
});

test("Go to Dashboard actually navigates there", () => {
  renderAt("/app/nope");

  fireEvent.click(screen.getByRole("button", { name: /go to the dashboard/i }));

  expect(screen.getByText("Dashboard page")).toBeInTheDocument();
});

test("the suggested links point at pages that exist", () => {
  renderAt("/app/nope");

  fireEvent.click(screen.getByRole("button", { name: /Dashboard Agents, status/i }));

  expect(screen.getByText("Dashboard page")).toBeInTheDocument();
});

test("reporting the broken link carries the address in the mail", () => {
  renderAt("/app/typo");

  const link = screen.getByRole("link", { name: /report this broken link/i });
  expect(link.getAttribute("href")).toContain(encodeURIComponent("/app/typo"));
});
