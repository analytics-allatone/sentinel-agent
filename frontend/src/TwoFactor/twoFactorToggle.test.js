/**
 * The sidebar switch, against the contract the backend actually ships
 * (src/api/v1/auth_api.py): setup answers with bare base64 PNG bytes, and
 * disable wants the password as well as a code.
 *
 * What matters is that the switch never moves on its own: it follows proof the
 * user has the authenticator app, in both directions.
 */
import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

import { MemoryRouter } from "react-router-dom";

import api from "../api/api";
import TwoFactorToggle from "./TwoFactorToggle";
import { TwoFactorProvider } from "./TwoFactorContext";
import { TWO_FACTOR_ENABLED_KEY } from "./twoFactorPreference";

jest.mock("../api/api", () => ({
  __esModule: true,
  default: { post: jest.fn(), get: jest.fn() },
  getCookie: jest.fn(),
  setCookie: jest.fn(),
  logout: jest.fn(),
  TWO_FACTOR_ENABLED_KEY: "two_factor_enabled",
}));

/** What POST /2fa/setup really answers with. */
const SETUP_RESPONSE = {
  data: {
    status: "success",
    data: {
      secret: "JBSWY3DPEHPK3PXP",
      otpauth_uri: "otpauth://totp/sentinel:ops@allatone.in?secret=JBSWY3DPEHPK3PXP",
      qr_code_png_base64: "iVBORw0KGgoAAAANSUhEUg==",
    },
  },
};

/** The switch lives inside the app, so it sits inside the 2FA provider. */
const renderToggle = () =>
  render(
    <MemoryRouter>
      <TwoFactorProvider>
        <TwoFactorToggle />
      </TwoFactorProvider>
    </MemoryRouter>
  );

const typeCode = (code) => {
  const boxes = screen.getAllByRole("textbox");
  code.split("").forEach((digit, i) => {
    fireEvent.change(boxes[i], { target: { value: digit } });
  });
};

const theSwitch = () => screen.getByRole("switch", { name: /two-step verification/i });

const startOn = () => localStorage.setItem(TWO_FACTOR_ENABLED_KEY, "true");

beforeEach(() => {
  localStorage.clear();
  api.get.mockResolvedValue({ data: { data: {} } });
  api.post.mockResolvedValue({ data: { data: {} } });
});

describe("where the switch starts", () => {
  test("off, unless sign-in said the account has 2FA on", () => {
    renderToggle();
    expect(theSwitch()).toHaveAttribute("aria-checked", "false");
  });

  test("on, when it does", () => {
    startOn();
    renderToggle();
    expect(theSwitch()).toHaveAttribute("aria-checked", "true");
  });
});

describe("turning it on", () => {
  test("the QR arrives as bare base64 and is still drawn", async () => {
    api.post.mockResolvedValueOnce(SETUP_RESPONSE);
    renderToggle();

    fireEvent.click(theSwitch());

    const img = await screen.findByAltText(/scan with your authenticator/i);
    // The API sends the PNG's bytes only; the media type has to be put back.
    expect(img).toHaveAttribute("src", "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==");
    expect(api.post).toHaveBeenCalledWith("/2fa/setup", {}, expect.anything());
  });

  test("the key is offered for a camera that will not scan", async () => {
    api.post.mockResolvedValueOnce(SETUP_RESPONSE);
    renderToggle();

    fireEvent.click(theSwitch());

    expect(await screen.findByText("JBSW Y3DP EHPK 3PXP")).toBeInTheDocument();
  });

  // The dialog opens before the QR arrives. If focus is left on the dialog
  // itself, everything typed goes nowhere and the boxes look broken.
  test("the first box has the cursor as soon as the QR arrives", async () => {
    api.post.mockResolvedValueOnce(SETUP_RESPONSE);
    renderToggle();

    fireEvent.click(theSwitch());
    await screen.findByAltText(/scan with your authenticator/i);

    const boxes = screen.getAllByRole("textbox");
    expect(document.activeElement).toBe(boxes[0]);

    // typing without clicking a box first must land in it
    fireEvent.change(document.activeElement, { target: { value: "7" } });
    expect(boxes[0]).toHaveValue("7");
  });

  test("the switch only moves after a good code", async () => {
    api.post.mockResolvedValueOnce(SETUP_RESPONSE);
    renderToggle();

    fireEvent.click(theSwitch());
    await screen.findByAltText(/scan with your authenticator/i);
    // Not on yet — a QR on screen proves nothing about the phone.
    expect(theSwitch()).toHaveAttribute("aria-checked", "false");

    typeCode("123456");

    await waitFor(() =>
      expect(api.post).toHaveBeenLastCalledWith(
        "/2fa/enable",
        { code: "123456" },
        expect.anything()
      )
    );
    // /login/2fa belongs to sign-in; the switch never reaches for it.
    expect(api.post).not.toHaveBeenCalledWith("/login/2fa", expect.anything(), expect.anything());
    await waitFor(() => expect(theSwitch()).toHaveAttribute("aria-checked", "true"));
    await waitFor(() => expect(theSwitch()).toHaveAttribute("aria-checked", "true"));
    expect(localStorage.getItem(TWO_FACTOR_ENABLED_KEY)).toBe("true");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  test("a rejected code leaves the switch off and says why", async () => {
    api.post
      .mockResolvedValueOnce(SETUP_RESPONSE)
      .mockRejectedValueOnce({ response: { status: 401, data: { detail: "Invalid code" } } });
    renderToggle();

    fireEvent.click(theSwitch());
    await screen.findByAltText(/scan with your authenticator/i);
    typeCode("111111");

    expect(await screen.findByRole("alert")).toHaveTextContent(/invalid code/i);
    expect(theSwitch()).toHaveAttribute("aria-checked", "false");
    expect(screen.getAllByRole("textbox")[0]).toHaveValue("");
  });
});

describe("turning it off", () => {
  beforeEach(startOn);

  test("password and code go together, and no QR is shown", async () => {
    renderToggle();

    fireEvent.click(theSwitch());

    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(screen.queryByAltText(/scan with your authenticator/i)).not.toBeInTheDocument();
    expect(api.post).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText(/^password$/i), {
      target: { value: "sentinel123" },
    });
    typeCode("654321");

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        "/2fa/disable",
        { password: "sentinel123", code: "654321" },
        expect.anything()
      )
    );
    await waitFor(() => expect(theSwitch()).toHaveAttribute("aria-checked", "false"));
    expect(localStorage.getItem(TWO_FACTOR_ENABLED_KEY)).toBe("false");
  });

  test("the password box has the cursor when the dialog opens", async () => {
    renderToggle();

    fireEvent.click(theSwitch());
    await screen.findByRole("dialog");

    expect(document.activeElement).toBe(screen.getByLabelText(/^password$/i));
  });

  test("a code without a password asks for the password instead of calling", async () => {
    renderToggle();

    fireEvent.click(theSwitch());
    typeCode("654321");

    expect(await screen.findByRole("alert")).toHaveTextContent(/enter your password/i);
    expect(api.post).not.toHaveBeenCalled();
    expect(theSwitch()).toHaveAttribute("aria-checked", "true");
  });

  test("cancelling changes nothing", async () => {
    renderToggle();

    fireEvent.click(theSwitch());
    fireEvent.click(await screen.findByRole("button", { name: /cancel/i }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(theSwitch()).toHaveAttribute("aria-checked", "true");
    expect(api.post).not.toHaveBeenCalled();
  });

  test("a wrong password keeps 2FA on", async () => {
    api.post.mockRejectedValue({
      response: { status: 401, data: { detail: "Invalid password" } },
    });
    renderToggle();

    fireEvent.click(theSwitch());
    fireEvent.change(screen.getByLabelText(/^password$/i), {
      target: { value: "wrong-one" },
    });
    typeCode("222222");

    expect(await screen.findByRole("alert")).toHaveTextContent(/invalid password/i);
    expect(theSwitch()).toHaveAttribute("aria-checked", "true");
    expect(localStorage.getItem(TWO_FACTOR_ENABLED_KEY)).toBe("true");
  });
});
