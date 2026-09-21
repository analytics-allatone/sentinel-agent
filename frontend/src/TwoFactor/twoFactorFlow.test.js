/**
 * The two-step verification flow end to end, through the router, with only the
 * HTTP layer mocked. What is asserted is the shape of the flow: which page
 * follows which, what each call carries, and what each page needs to open.
 *
 * Two different credentials are in play, and mixing them up is the mistake this
 * file exists to catch:
 *
 *   signing up   leaves a real session   -> the choice page and setup run on it
 *   signing in   with 2FA on leaves only a challenge token -> the verify page
 */
import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";

import api, { getCookie, setCookie } from "../api/api";
import {
  TwoFactorProvider,
  RequireSession,
  RequireTempToken,
  useTwoFactor,
} from "./TwoFactorContext";
import EnableTwoFactorPrompt from "./EnableTwoFactorPrompt";
import TwoFactorSetup from "./TwoFactorSetup";
import TwoFactorVerify from "./TwoFactorVerify";
import EmailOtpVerify from "./EmailOtpVerify";
import { TWO_FACTOR_ENABLED_KEY } from "./twoFactorPreference";

jest.mock("../api/api", () => ({
  __esModule: true,
  default: { post: jest.fn(), get: jest.fn() },
  getCookie: jest.fn(),
  setCookie: jest.fn(),
  logout: jest.fn(),
}));

/** What POST /2fa/setup really answers with: bare base64 PNG bytes. */
const SETUP_RESPONSE = {
  data: {
    data: {
      secret: "JBSWY3DPEHPK3PXP",
      otpauth_uri: "otpauth://totp/sentinel:ops@allatone.in?secret=JBSWY3DPEHPK3PXP",
      qr_code_png_base64: "iVBORw0KGgo=",
    },
  },
};

/** Starts a sign-in attempt, so the challenge route has a token to let through. */
function Seed({ children }) {
  const { begin, tempToken } = useTwoFactor();
  React.useEffect(() => {
    if (!tempToken) begin("challenge-abc", "ops@allatone.in");
  }, [begin, tempToken]);
  return tempToken ? children : null;
}

function routes() {
  return (
    <Routes>
      <Route path="/app/login" element={<div>Login page</div>} />
      <Route path="/app/dashboard" element={<div>Dashboard page</div>} />
      <Route
        path="/app/2fa/enable"
        element={
          <RequireSession>
            <EnableTwoFactorPrompt />
          </RequireSession>
        }
      />
      <Route
        path="/app/2fa/setup"
        element={
          <RequireSession>
            <TwoFactorSetup />
          </RequireSession>
        }
      />
      <Route
        path="/app/2fa/verify"
        element={
          <RequireTempToken>
            <TwoFactorVerify />
          </RequireTempToken>
        }
      />
      <Route
        path="/app/2fa/email-otp"
        element={
          <RequireTempToken>
            <EmailOtpVerify />
          </RequireTempToken>
        }
      />
    </Routes>
  );
}

/** A signed-in visitor: what someone who has just signed up looks like. */
function renderSignedIn(initialPath) {
  getCookie.mockReturnValue("real-session-token");
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <TwoFactorProvider>{routes()}</TwoFactorProvider>
    </MemoryRouter>
  );
}

/** Someone mid sign-in: a challenge token and nothing else. */
function renderChallenge(initialPath) {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <TwoFactorProvider>
        <Seed>{routes()}</Seed>
      </TwoFactorProvider>
    </MemoryRouter>
  );
}

const typeCode = (code) => {
  const boxes = screen.getAllByRole("textbox");
  code.split("").forEach((digit, i) => {
    fireEvent.change(boxes[i], { target: { value: digit } });
  });
};

beforeEach(() => {
  localStorage.clear();
  api.post.mockResolvedValue({ data: { data: {} } });
  getCookie.mockReturnValue(null);
});

describe("what each page needs to open", () => {
  test("the challenge page needs a sign-in in progress", () => {
    render(
      <MemoryRouter initialEntries={["/app/2fa/verify"]}>
        <TwoFactorProvider>{routes()}</TwoFactorProvider>
      </MemoryRouter>
    );

    expect(screen.getByText("Login page")).toBeInTheDocument();
  });

  test("the setup page needs a real session", () => {
    render(
      <MemoryRouter initialEntries={["/app/2fa/setup"]}>
        <TwoFactorProvider>{routes()}</TwoFactorProvider>
      </MemoryRouter>
    );

    expect(screen.getByText("Login page")).toBeInTheDocument();
    expect(api.post).not.toHaveBeenCalled();
  });

  // The app treats three places as a session; a page that only honoured one of
  // them threw signed-in people back to the login screen.
  test.each([
    ["the access_token cookie", () => getCookie.mockImplementation((n) => (n === "access_token" ? "tok" : null))],
    ["a token in localStorage", () => localStorage.setItem("token", "tok")],
  ])("a session held in %s opens the page", async (_name, arrange) => {
    api.post.mockResolvedValue(SETUP_RESPONSE);
    arrange();

    render(
      <MemoryRouter initialEntries={["/app/2fa/setup"]}>
        <TwoFactorProvider>{routes()}</TwoFactorProvider>
      </MemoryRouter>
    );

    expect(await screen.findByAltText(/scan with your authenticator/i)).toBeInTheDocument();
    expect(screen.queryByText("Login page")).not.toBeInTheDocument();
  });
});

describe("the choice offered after signing up", () => {
  test("skipping goes straight to the dashboard, asking the API nothing", async () => {
    renderSignedIn("/app/2fa/enable");

    fireEvent.click(screen.getByRole("button", { name: /skip for now/i }));

    await waitFor(() => expect(screen.getByText("Dashboard page")).toBeInTheDocument());
    // Signup already issued the session; there is no "skip" call to make.
    expect(api.post).not.toHaveBeenCalled();
    expect(setCookie).not.toHaveBeenCalled();
    expect(localStorage.getItem(TWO_FACTOR_ENABLED_KEY)).toBe("false");
  });

  test("enabling opens setup and asks for a QR", async () => {
    api.post.mockResolvedValue(SETUP_RESPONSE);
    renderSignedIn("/app/2fa/enable");

    fireEvent.click(
      screen.getByRole("button", { name: /enable two-step verification/i })
    );

    const img = await screen.findByAltText(/scan with your authenticator/i);
    expect(img).toHaveAttribute("src", "data:image/png;base64,iVBORw0KGgo=");
    expect(api.post).toHaveBeenCalledWith("/2fa/setup", {}, expect.anything());
  });
});

describe("setting up", () => {
  test("the code turns 2FA on and lands on the dashboard", async () => {
    api.post
      .mockResolvedValueOnce(SETUP_RESPONSE)
      .mockResolvedValueOnce({ data: { data: { two_fa_enabled: true } } });
    renderSignedIn("/app/2fa/setup");
    await screen.findByAltText(/scan with your authenticator/i);

    typeCode("654321");

    await waitFor(() =>
      expect(api.post).toHaveBeenLastCalledWith(
        "/2fa/enable",
        { code: "654321" },
        expect.anything()
      )
    );
    await waitFor(() => expect(screen.getByText("Dashboard page")).toBeInTheDocument());
    expect(localStorage.getItem(TWO_FACTOR_ENABLED_KEY)).toBe("true");
  });

  // /login/2fa belongs to sign-in; nothing on this page may reach for it.
  test("a wrong code costs one attempt, on one endpoint", async () => {
    api.post
      .mockResolvedValueOnce(SETUP_RESPONSE)
      .mockRejectedValueOnce({
        response: { status: 401, data: { detail: "Invalid code" } },
      });
    renderSignedIn("/app/2fa/setup");
    await screen.findByAltText(/scan with your authenticator/i);

    typeCode("111111");

    expect(await screen.findByRole("alert")).toHaveTextContent(/invalid code/i);
    // setup + the one refused attempt, and nothing more
    expect(api.post).toHaveBeenCalledTimes(2);
    expect(api.post).not.toHaveBeenCalledWith("/login/2fa", expect.anything(), expect.anything());
    expect(localStorage.getItem(TWO_FACTOR_ENABLED_KEY)).not.toBe("true");
  });

  // The boxes mount disabled while the QR is fetched. If nothing puts the
  // cursor back afterwards, the page looks ready and eats every keystroke.
  test("the boxes take typing as soon as the QR arrives", async () => {
    api.post.mockResolvedValue(SETUP_RESPONSE);
    renderSignedIn("/app/2fa/setup");
    await screen.findByAltText(/scan with your authenticator/i);

    const boxes = screen.getAllByRole("textbox");
    expect(document.activeElement).toBe(boxes[0]);

    fireEvent.change(document.activeElement, { target: { value: "4" } });
    expect(boxes[0]).toHaveValue("4");
  });

  // The backend answers 401 to a mistyped code as well as to a dead token;
  // one wrong digit must not throw the user out to the login screen.
  test("a rejected code stays on the page and puts the cursor back", async () => {
    api.post
      .mockResolvedValueOnce(SETUP_RESPONSE)
      .mockRejectedValueOnce({ response: { status: 401, data: { detail: "Invalid code" } } });
    renderSignedIn("/app/2fa/setup");
    await screen.findByAltText(/scan with your authenticator/i);

    typeCode("111111");

    expect(await screen.findByRole("alert")).toHaveTextContent(/invalid code/i);
    expect(document.activeElement).toBe(screen.getAllByRole("textbox")[0]);
  });

  test("the key is offered for a camera that will not scan", async () => {
    api.post.mockResolvedValue(SETUP_RESPONSE);
    renderSignedIn("/app/2fa/setup");

    expect(await screen.findByText("JBSW Y3DP EHPK 3PXP")).toBeInTheDocument();
  });

  test("leaving early leaves 2FA off rather than half on", async () => {
    api.post.mockResolvedValue(SETUP_RESPONSE);
    renderSignedIn("/app/2fa/setup");
    await screen.findByAltText(/scan with your authenticator/i);

    fireEvent.click(screen.getByRole("button", { name: /skip for now/i }));

    await waitFor(() => expect(screen.getByText("Dashboard page")).toBeInTheDocument());
    expect(localStorage.getItem(TWO_FACTOR_ENABLED_KEY)).toBe("false");
  });
});

describe("verifying at sign-in", () => {
  test("the challenge token goes in the body and as the bearer", async () => {
    renderChallenge("/app/2fa/verify");
    typeCode("123456");

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        "/login/2fa",
        { challenge_token: "challenge-abc", code: "123456" },
        expect.anything()
      )
    );
    const config = api.post.mock.calls[0][2];
    expect(config.headers.Authorization).toBe("Bearer challenge-abc");
    // the challenge is the credential this step owns, so no session cookie
    expect(config.skipAuthToken).toBe(true);
  });

  test("no QR code is ever shown on this page", () => {
    renderChallenge("/app/2fa/verify");

    expect(screen.queryByAltText(/scan with your authenticator/i)).not.toBeInTheDocument();
    expect(api.post).not.toHaveBeenCalledWith(
      "/2fa/setup",
      expect.anything(),
      expect.anything()
    );
  });

  test("a correct code stores the session and opens the dashboard", async () => {
    api.post.mockResolvedValue({
      data: { data: { access_token: "real-token", refresh_token: "refresh-token" } },
    });
    renderChallenge("/app/2fa/verify");

    typeCode("123456");

    await waitFor(() => expect(setCookie).toHaveBeenCalledWith("token", "real-token", 7));
    expect(setCookie).toHaveBeenCalledWith("refresh_token", "refresh-token", 30);
    await waitFor(() => expect(screen.getByText("Dashboard page")).toBeInTheDocument());
  });

  test("a wrong code clears the boxes and says so, without signing in", async () => {
    api.post.mockRejectedValue({
      response: { status: 400, data: { detail: "Invalid code" } },
    });
    renderChallenge("/app/2fa/verify");

    typeCode("111111");

    expect(await screen.findByRole("alert")).toHaveTextContent(/invalid code/i);
    expect(screen.getAllByRole("textbox")[0]).toHaveValue("");
    expect(setCookie).not.toHaveBeenCalled();
  });

  test("an expired challenge sends the user back to login", async () => {
    api.post.mockRejectedValue({ response: { status: 401 } });
    renderChallenge("/app/2fa/verify");

    typeCode("222222");

    await waitFor(() => expect(screen.getByText("Login page")).toBeInTheDocument());
  });

  test("the email link sends a code and opens the email page", async () => {
    renderChallenge("/app/2fa/verify");

    fireEvent.click(screen.getByRole("button", { name: /get a code by email/i }));

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith("/2fa/email-otp/send", {}, expect.anything())
    );
    expect(await screen.findByText(/sent a 6-digit code/i)).toBeInTheDocument();
  });
});

describe("the email route back in", () => {
  test("a correct emailed code leads to setup, not to the dashboard", async () => {
    api.post.mockResolvedValueOnce({ data: { data: {} } }).mockResolvedValueOnce(SETUP_RESPONSE);
    getCookie.mockReturnValue("real-session-token");
    renderChallenge("/app/2fa/email-otp");

    typeCode("333333");

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        "/2fa/email-otp/verify",
        { otp: "333333" },
        expect.anything()
      )
    );
    expect(await screen.findByAltText(/scan with your authenticator/i)).toBeInTheDocument();
    expect(setCookie).not.toHaveBeenCalled();
  });

  test("resend is locked behind a countdown", async () => {
    renderChallenge("/app/2fa/email-otp");

    const resend = await screen.findByRole("button", { name: /resend code in \d+s/i });
    expect(resend).toBeDisabled();
  });
});
