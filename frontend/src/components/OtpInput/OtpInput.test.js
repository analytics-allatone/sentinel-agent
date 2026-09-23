/**
 * The six-box code field. People type, paste, correct and autofill into these,
 * so each of those paths is checked rather than assumed.
 */
import React, { useState } from "react";
import { render, screen, fireEvent } from "@testing-library/react";

import OtpInput from "./OtpInput";

/** The component is controlled, so the test holds the value like a page would. */
function Harness({ onComplete }) {
  const [value, setValue] = useState("");
  return (
    <>
      <OtpInput value={value} onChange={setValue} onComplete={onComplete} />
      <output data-testid="value">{value}</output>
    </>
  );
}

const boxes = () => screen.getAllByRole("textbox");
const currentValue = () => screen.getByTestId("value").textContent;

test("the first box has focus on arrival", () => {
  render(<Harness />);

  expect(boxes()[0]).toHaveFocus();
});

test("typing fills a box and moves to the next", () => {
  render(<Harness />);

  fireEvent.change(boxes()[0], { target: { value: "4" } });

  expect(boxes()[0]).toHaveValue("4");
  expect(boxes()[1]).toHaveFocus();
});

test("letters are refused, digits are kept", () => {
  render(<Harness />);

  fireEvent.change(boxes()[0], { target: { value: "a" } });
  expect(currentValue()).toBe("");

  fireEvent.change(boxes()[0], { target: { value: "7" } });
  expect(currentValue()).toBe("7");
});

test("backspace clears the box, then steps back", () => {
  render(<Harness />);
  fireEvent.change(boxes()[0], { target: { value: "1" } });
  fireEvent.change(boxes()[1], { target: { value: "2" } });

  fireEvent.keyDown(boxes()[1], { key: "Backspace" });
  expect(currentValue()).toBe("1");

  fireEvent.keyDown(boxes()[1], { key: "Backspace" });
  expect(currentValue()).toBe("");
  expect(boxes()[0]).toHaveFocus();
});

test("pasting six digits fills every box", () => {
  const onComplete = jest.fn();
  render(<Harness onComplete={onComplete} />);

  fireEvent.paste(boxes()[0], {
    clipboardData: { getData: () => "123456" },
  });

  expect(currentValue()).toBe("123456");
  expect(onComplete).toHaveBeenCalledWith("123456");
});

test("a code pasted into a later box still fills from the start", () => {
  render(<Harness />);

  fireEvent.paste(boxes()[3], { clipboardData: { getData: () => "987654" } });

  expect(currentValue()).toBe("987654");
});

test("a pasted code with spaces or dashes is cleaned up", () => {
  render(<Harness />);

  fireEvent.paste(boxes()[0], { clipboardData: { getData: () => "12 34-56" } });

  expect(currentValue()).toBe("123456");
});

test("an autofilled code arriving in one box is spread across them", () => {
  render(<Harness />);

  // browsers deliver an SMS/email code as a single value in the focused box
  fireEvent.change(boxes()[0], { target: { value: "246810" } });

  expect(currentValue()).toBe("246810");
});

test("completing the code reports it exactly once", () => {
  const onComplete = jest.fn();
  render(<Harness onComplete={onComplete} />);

  "135790".split("").forEach((digit, i) => {
    fireEvent.change(boxes()[i], { target: { value: digit } });
  });

  expect(onComplete).toHaveBeenCalledTimes(1);
  expect(onComplete).toHaveBeenCalledWith("135790");
});

test("arrow keys move between boxes", () => {
  render(<Harness />);

  fireEvent.keyDown(boxes()[0], { key: "ArrowRight" });
  expect(boxes()[1]).toHaveFocus();

  fireEvent.keyDown(boxes()[1], { key: "ArrowLeft" });
  expect(boxes()[0]).toHaveFocus();
});

test("a wrong code marks the boxes, and clearing the value empties them", () => {
  const { rerender } = render(
    <OtpInput value="123456" onChange={() => {}} invalid />
  );

  expect(screen.getAllByRole("textbox")[0]).toHaveAttribute("aria-invalid", "true");

  rerender(<OtpInput value="" onChange={() => {}} />);
  expect(screen.getAllByRole("textbox")[0]).toHaveValue("");
});
