/**
 * What the login form does with the answer to POST /login.
 *
 * The API replies with the same LoginResponse either way — what separates the
 * two paths is whether a challenge_token came back with it:
 *
 *   two_fa_enabled false  tokens arrive -> store the session, go to the dashboard
 *   two_fa_enabled true   no tokens, a challenge_token -> ask for the code, and
 *                         only POST /login/2fa turns that into a session
 *
 * A session stored before the code is entered would defeat the second factor
 * entirely, so that is asserted in both directions.
 */
import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";

import api, { setCookie } from "../api/api";
import Login from "./Login";
import TwoFactorVerify from "../TwoFactor/TwoFactorVerify";
import { TwoFactorProvider, RequireTempToken } from "../TwoFactor/TwoFactorContext";

jest.mock("../api/api", () => ({
  __esModule: true,
  default: { post: jest.fn(), get: jest.fn() },
  getCookie: jest.fn(),
  setCookie: jest.fn(),
  logout: jest.fn(),
}));

/** 2FA off: the API signs the user straight in. */
const SIGNED_IN = {
  data: {
    status: "success",
    message: "Logged in successfully",
    data: {
      access_token: "real-token",
      refresh_token: "refresh-token",
      two_fa_enabled: false,
      challenge_token: null,
    },
  },
};

/** 2FA on: no session yet, only the challenge. */
const CHALLENGED = {
  data: {
    status: "success",
    message: "Enter your authentication code",
    data: {
      access_token: null,
      refresh_token: null,
      two_fa_enabled: true,
      challenge_token: "challenge-xyz",
    },
  },
};

function renderLogin() {
  return render(
    <MemoryRouter initialEntries={["/app/login"]}>
      <TwoFactorProvider>
        <Routes>
          <Route path="/app/login" element={<Login />} />
          <Route path="/app/dashboard" element={<div>Dashboard page</div>} />
          <Route
            path="/app/2fa/verify"
            element={
              <RequireTempToken>
                <TwoFactorVerify />
              </RequireTempToken>
            }
          />
        </Routes>
      </TwoFactorProvider>
    </MemoryRouter>
  );
}

const signIn = () => {
  fireEvent.change(screen.getByLabelText(/^email$/i), {
    target: { value: "Ops@Allatone.in" },
  });
  fireEvent.change(screen.getByLabelText(/^password$/i), {
    target: { value: "sentinel123" },
  });
  fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
};

const typeCode = (code) => {
  const boxes = screen.getAllByRole("textbox");
  code.split("").forEach((digit, i) => {
    fireEvent.change(boxes[i], { target: { value: digit } });
  });
};

beforeEach(() => {
  localStorage.clear();
  api.post.mockResolvedValue(SIGNED_IN);
});

test("the address is sent lowercased, with the password", async () => {
  renderLogin();
  signIn();

  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith(
      "/login",
      { email: "ops@allatone.in", password: "sentinel123" },
      expect.anything()
    )
  );
});

test("without 2FA, the session is stored and the dashboard opens", async () => {
  renderLogin();
  signIn();

  await waitFor(() => expect(screen.getByText("Dashboard page")).toBeInTheDocument());
  expect(setCookie).toHaveBeenCalledWith("token", "real-token", 7);
  expect(setCookie).toHaveBeenCalledWith("refresh_token", "refresh-token", 30);
});

describe("with 2FA on", () => {
  test("the code is asked for, and no session is stored yet", async () => {
    api.post.mockResolvedValue(CHALLENGED);
    renderLogin();
    signIn();

    await waitFor(() => expect(screen.getAllByRole("textbox")).toHaveLength(6));
    expect(screen.queryByText("Dashboard page")).not.toBeInTheDocument();
    expect(setCookie).not.toHaveBeenCalled();
  });

  test("the code goes to /login/2fa with the challenge token, and that signs in", async () => {
    api.post.mockResolvedValueOnce(CHALLENGED).mockResolvedValueOnce({
      data: {
        status: "success",
        data: { access_token: "after-2fa", refresh_token: "after-2fa-refresh" },
      },
    });
    renderLogin();
    signIn();
    await waitFor(() => expect(screen.getAllByRole("textbox")).toHaveLength(6));

    typeCode("123456");

    await waitFor(() =>
      expect(api.post).toHaveBeenLastCalledWith(
        "/login/2fa",
        { challenge_token: "challenge-xyz", code: "123456" },
        expect.anything()
      )
    );
    await waitFor(() => expect(setCookie).toHaveBeenCalledWith("token", "after-2fa", 7));
    expect(await screen.findByText("Dashboard page")).toBeInTheDocument();
  });
});

// two_fa_enabled is what decides the path, so an answer that claims 2FA but
// carries no challenge must not fall through into a session.
test("2FA on with no challenge token signs nobody in", async () => {
  api.post.mockResolvedValue({
    data: {
      status: "success",
      data: {
        access_token: "should-not-be-used",
        refresh_token: "should-not-be-used",
        two_fa_enabled: true,
        challenge_token: null,
      },
    },
  });
  renderLogin();
  signIn();

  expect(await screen.findByText(/could not start/i)).toBeInTheDocument();
  expect(setCookie).not.toHaveBeenCalled();
  expect(screen.queryByText("Dashboard page")).not.toBeInTheDocument();
});

test("a refused sign-in says so and stores nothing", async () => {
  api.post.mockRejectedValue({
    response: { status: 401, data: { detail: "Invalid password" } },
  });
  renderLogin();
  signIn();

  expect(await screen.findByText(/invalid password/i)).toBeInTheDocument();
  expect(setCookie).not.toHaveBeenCalled();
});
