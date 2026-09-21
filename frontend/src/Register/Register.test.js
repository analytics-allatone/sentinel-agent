/**
 * Registration asks for a name, an email and a password — and sends exactly
 * those three. The role is the backend's to assign, so it is never in the body.
 *
 * Signup answers with a real session, and the account lands on the two-step
 * verification choice rather than back at the login form.
 */
import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";

import Register from "./Register";
import api, { setCookie } from "../api/api";

jest.mock("../api/api", () => ({
  __esModule: true,
  default: { post: jest.fn(), get: jest.fn() },
  getCookie: jest.fn(),
  setCookie: jest.fn(),
  logout: jest.fn(),
}));

beforeEach(() => {
  localStorage.clear();
  api.post.mockResolvedValue({
    data: {
      status: "success",
      data: { access_token: "new-session", refresh_token: "new-refresh" },
    },
  });
});

function renderForm() {
  return render(
    <MemoryRouter initialEntries={["/app/register"]}>
      <Routes>
        <Route path="/app/register" element={<Register />} />
        <Route path="/app/login" element={<div>Login page</div>} />
        <Route path="/app/2fa/enable" element={<div>Two-step choice</div>} />
      </Routes>
    </MemoryRouter>
  );
}

const fill = () => {
  fireEvent.change(screen.getByLabelText(/^name$/i), {
    target: { value: "Naresh Kumar" },
  });
  fireEvent.change(screen.getByLabelText(/^email$/i), {
    target: { value: "Naresh@Allatone.in" },
  });
  fireEvent.change(screen.getByLabelText(/^password$/i), {
    target: { value: "sentinel123" },
  });
};

test("it asks for three fields and nothing else", () => {
  renderForm();

  expect(screen.getByLabelText(/^name$/i)).toBeInTheDocument();
  expect(screen.getByLabelText(/^email$/i)).toBeInTheDocument();
  expect(screen.getByLabelText(/^password$/i)).toBeInTheDocument();

  expect(screen.queryByLabelText(/first name/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/last name/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/phone/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/confirm/i)).not.toBeInTheDocument();
});

test("it sends the contract the API publishes", async () => {
  renderForm();
  fill();

  fireEvent.click(screen.getByRole("button", { name: /sign up/i }));

  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith("/signup", {
      name: "Naresh Kumar",
      email: "naresh@allatone.in",
      password: "sentinel123",
    })
  );
});

test("the signup body never carries a role", async () => {
  renderForm();
  fill();

  fireEvent.click(screen.getByRole("button", { name: /sign up/i }));

  await waitFor(() => expect(api.post).toHaveBeenCalled());
  const sent = api.post.mock.calls[0][1];
  expect(sent).not.toHaveProperty("role");
  expect(Object.keys(sent).sort()).toEqual(["email", "name", "password"]);
});

test("the new account is signed in and asked about two-step verification", async () => {
  renderForm();
  fill();

  fireEvent.click(screen.getByRole("button", { name: /sign up/i }));

  await waitFor(() => expect(screen.getByText("Two-step choice")).toBeInTheDocument());
  expect(setCookie).toHaveBeenCalledWith("token", "new-session", 7);
  expect(setCookie).toHaveBeenCalledWith("refresh_token", "new-refresh", 30);
  expect(localStorage.getItem("auth_email")).toBe("naresh@allatone.in");
});

test("no session in the answer means no half-signed-in state", async () => {
  api.post.mockResolvedValue({ data: { status: "success", data: {} } });
  renderForm();
  fill();

  fireEvent.click(screen.getByRole("button", { name: /sign up/i }));

  expect(await screen.findByText(/please log in/i)).toBeInTheDocument();
  expect(setCookie).not.toHaveBeenCalled();
  expect(screen.queryByText("Two-step choice")).not.toBeInTheDocument();
});

test("an empty field stops the request", () => {
  renderForm();

  fireEvent.click(screen.getByRole("button", { name: /sign up/i }));

  expect(screen.getByText(/please fill in all fields/i)).toBeInTheDocument();
  expect(api.post).not.toHaveBeenCalled();
});

test("a short password is refused before it reaches the API", () => {
  renderForm();
  fill();
  fireEvent.change(screen.getByLabelText(/^password$/i), {
    target: { value: "abc" },
  });

  fireEvent.click(screen.getByRole("button", { name: /sign up/i }));

  expect(screen.getByText(/at least 6 characters/i)).toBeInTheDocument();
  expect(api.post).not.toHaveBeenCalled();
});

describe("showing the password", () => {
  test("it is hidden to begin with", () => {
    renderForm();

    expect(screen.getByLabelText(/^password$/i)).toHaveAttribute("type", "password");
  });

  test("the eye reveals it, and hides it again", () => {
    renderForm();

    fireEvent.click(screen.getByRole("button", { name: /show password/i }));
    expect(screen.getByLabelText(/^password$/i)).toHaveAttribute("type", "text");

    fireEvent.click(screen.getByRole("button", { name: /hide password/i }));
    expect(screen.getByLabelText(/^password$/i)).toHaveAttribute("type", "password");
  });

  test("the toggle does not submit the form", () => {
    renderForm();
    fill();

    fireEvent.click(screen.getByRole("button", { name: /show password/i }));

    expect(api.post).not.toHaveBeenCalled();
  });
});
