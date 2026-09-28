/**
 * The design system page.
 *
 * It is a reference *and* a check: it reads the tokens from the running
 * stylesheet and measures the contrast of each fill against its text. jsdom
 * does not resolve custom properties, so the numbers cannot be asserted here —
 * what is asserted is that the page describes the whole system, and that an
 * unmeasurable pair is reported as unknown rather than as a failure.
 */
import React from "react";
import { render, screen, within } from "@testing-library/react";

import DesignSystemPage from "./DesignSystemPage";
import { COLOR_GROUPS, PAIRS } from "./designTokens";

test("it names every colour token the system defines", () => {
  render(<DesignSystemPage />);

  COLOR_GROUPS.forEach((group) => {
    // "Status" is both a group of tokens and a column in the agents table.
    expect(
      screen.getAllByRole("heading", { name: group.title }).length
    ).toBeGreaterThan(0);
    group.tokens.forEach((token) => {
      // A token can appear twice: as a swatch, and again in the pairs table.
      expect(screen.getAllByText(`--${token.name}`).length).toBeGreaterThan(0);
    });
  });
});

test("every fill is listed with the text it carries", () => {
  render(<DesignSystemPage />);

  const table = screen.getAllByRole("table")[0];
  const rows = within(table).getAllByRole("row").slice(1);

  expect(rows).toHaveLength(PAIRS.length);
  expect(within(table).getByText("primary button")).toBeInTheDocument();
  expect(within(table).getByText("danger button")).toBeInTheDocument();
});

// A ratio nobody could compute is not a verdict of "bad".
test("a pair that cannot be measured says so", () => {
  render(<DesignSystemPage />);

  expect(screen.getAllByText("Not measured").length).toBe(PAIRS.length);
  expect(screen.queryByText("Too close")).not.toBeInTheDocument();
});

test("the component gallery shows each button and field state", () => {
  render(<DesignSystemPage />);

  expect(screen.getByRole("button", { name: /save changes/i })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /delete agent/i })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /creating/i })).toHaveAttribute(
    "aria-busy",
    "true"
  );

  const group = screen.getByLabelText(/^group$/i);
  expect(group).toHaveAttribute("aria-invalid", "true");
  expect(screen.getByText(/cannot contain spaces/i)).toBeInTheDocument();
});

test("it offers the theme, and a way to change it", () => {
  render(<DesignSystemPage />);

  expect(
    screen.getByRole("button", { name: /switch to (light|dark) theme/i })
  ).toBeInTheDocument();
});
