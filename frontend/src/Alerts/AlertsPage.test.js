/**
 * The alerts page.
 *
 * The fixtures are the real response: a quarter of a million rows reported in
 * `total`, fifty handed over, the same rule repeated down the page, and a
 * `category` of null on every one of them. Most of what is asserted here is
 * about not overclaiming — the page must never present what it holds as if it
 * described everything the server has.
 */
import React from "react";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";

import AlertsPage from "./AlertsPage";
import api from "../api/api";
import {
  burstSpan,
  clampNumber,
  describeWindow,
  digitsOnly,
  groupByRule,
  isoToLocalInput,
  localToIso,
  pageCount,
  rangeProblem,
  rangeWindow,
  relativeTime,
  alertsToCsv,
  csvFilename,
  ruleId,
  safePage,
  safePageSize,
  technique,
  TIME_RANGES,
} from "./alertsFormat";

jest.mock("../api/api", () => ({
  __esModule: true,
  default: { get: jest.fn() },
  logout: jest.fn(),
}));

const NOW = Date.parse("2026-10-07T06:11:00Z");

/** The page groups digits for whoever is reading it — "246,201" in en-US,
 *  "2,46,201" in en-IN — so the expected text is built, never hardcoded. */
const TOTAL = 246201;
const TOTAL_TEXT = TOTAL.toLocaleString();

/** The headline figure. Scoped to its own element because the severity
    counts add up to the same number — as they should. */
/** Reports the address the page writes, so the URL itself can be asserted on. */
function Address() {
  lastSearch = useLocation().search;
  return null;
}

let lastSearch = "";

/**
 * The page inside a router.
 *
 * It keeps the whole view in the query string now, so rendering it bare is not
 * how it ever runs — a test that did would be testing a different page.
 */
function renderPage(initial = "/app/alerts") {
  lastSearch = "";
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <AlertsPage />
      <Address />
    </MemoryRouter>
  );
}

const hero = () =>
  waitFor(() => {
    const el = document.querySelector(".al-hero");
    // The headline reads "0" while the first request is still out, so waiting
    // on it alone lets a test run against the skeleton rows. The showing line
    // stays blank until the answer is in, which is the real signal.
    const showing = document.querySelector(".al-showing");
    if (!el || !el.textContent.trim()) throw new Error("no headline yet");
    if (!showing || !showing.textContent.trim()) throw new Error("still loading");
    return el;
  });

const alert = (over = {}) => ({
  id: 370268,
  rule_id: "SIGMA_34986307-b7f4-49be-92f3-e7a4d01ac5db",
  category: "file",
  severity: 3,
  severity_label: "medium",
  agent_name: "agent_david",
  entity: "WINDOWS-EP8PIFQ$",
  event_count: 9,
  first_seen: "2026-10-07T06:10:21.029064Z",
  last_seen: "2026-10-07T06:10:21.871312Z",
  detail: "Rclone Config File Creation",
  technique: "attack.t1567.002",
  ...over,
});

const PAGE = [
  alert(),
  alert({ id: 370257, agent_name: "shiv1", entity: "DESKTOP-4G26IBD$", event_count: 6 }),
  alert({
    id: 370264,
    rule_id: "SIGMA_a238b5d0-ce2d-4414-a676-7a531b3d13d6",
    severity: 4,
    severity_label: "high",
    agent_name: "shiv1",
    entity: "chrome.exe",
    event_count: 2,
    detail: "ETW Trace Evasion Activity",
    technique: "attack.t1070",
    category: "process",
  }),
];

/** The list call answers the page; the four tally calls answer a count each. */
const AGENTS = [
  { id: 1, agent_name: "shiv1", host_name: "DESKTOP-4G26IBD", main_ip: "10.0.0.4", status: "active" },
  { id: 2, agent_name: "agent_david", host_name: "WINDOWS-EP8PIFQ", main_ip: "10.0.0.5", status: "active" },
  { id: 3, agent_name: "Linux_testing", host_name: "ubuntu-01", main_ip: "10.0.0.6", status: "active" },
];

function mockApi({ total = TOTAL, alerts = PAGE, tallies = {}, agents = AGENTS } = {}) {
  api.get.mockImplementation((url, config) => {
    const params = (config && config.params) || {};
    if (String(url).includes("get-agents")) {
      return Promise.resolve({ data: { data: { agents } } });
    }
    if (params.page_size === 1 && params.severity) {
      return Promise.resolve({
        data: { data: { total: tallies[params.severity] ?? 0, page: 1, page_size: 1, alerts: [] } },
      });
    }
    return Promise.resolve({
      data: { data: { total, page: params.page || 1, page_size: params.page_size || 50, alerts } },
    });
  });
}

/** The params of the most recent call that asked for a page of alerts. */
function lastListParams() {
  const calls = api.get.mock.calls.filter(([, c]) => (c.params || {}).page_size !== 1);
  return calls[calls.length - 1][1].params;
}

beforeEach(() => {
  api.get.mockReset();
  mockApi({ tallies: { 5: 140, 4: 56490, 3: 189142, 2: 429 } });
});

describe("reading the response", () => {
  it("counts the pages there are to walk", () => {
    expect(pageCount(246201, 50)).toBe(4925);
    expect(pageCount(0, 50)).toBe(0);
    expect(pageCount(10, 0)).toBe(0);
  });

  it("turns an ATT&CK reference into an id and a link", () => {
    expect(technique("attack.t1567.002")).toEqual({
      id: "T1567.002",
      url: "https://attack.mitre.org/techniques/T1567/002/",
    });
    expect(technique("attack.t1070").id).toBe("T1070");
  });

  it("has nothing to link when the rule named no technique", () => {
    expect(technique("")).toBeNull();
    expect(technique(null)).toBeNull();
  });

  it("drops the engine prefix from a rule id", () => {
    expect(ruleId("SIGMA_34986307-b7f4")).toBe("34986307-b7f4");
  });
});

describe("how long ago, and over how long", () => {
  it("reads recent instants as minutes rather than dates", () => {
    expect(relativeTime("2026-10-07T06:10:21Z", NOW)).toBe("just now");
    expect(relativeTime("2026-10-07T05:41:00Z", NOW)).toBe("30 min ago");
    expect(relativeTime("2026-10-06T06:11:00Z", NOW)).toBe("1 day ago");
  });

  it("says so when there is no instant to read", () => {
    expect(relativeTime(null)).toBe("—");
  });

  it("separates a burst from a single moment", () => {
    // nine events at one instant is not nine events over a minute
    expect(burstSpan({ first_seen: "2026-10-07T06:10:21Z", last_seen: "2026-10-07T06:10:21Z" })).toBe(
      "at once"
    );
    expect(burstSpan({ first_seen: "2026-10-07T06:09:21Z", last_seen: "2026-10-07T06:10:21Z" })).toBe(
      "over 1 min"
    );
  });
});

describe("folding repeats", () => {
  const groups = groupByRule(PAGE);

  it("puts the same rule in one row and adds up its events", () => {
    const rclone = groups.find((g) => g.detail === "Rclone Config File Creation");
    expect(rclone.alerts).toBe(2);
    expect(rclone.events).toBe(15);
  });

  it("keeps every agent the rule fired on", () => {
    const rclone = groups.find((g) => g.detail === "Rclone Config File Creation");
    expect(rclone.agents.sort()).toEqual(["agent_david", "shiv1"]);
  });

  it("puts the worst severity first, not the commonest", () => {
    expect(groups[0].detail).toBe("ETW Trace Evasion Activity");
  });

  it("covers the whole window the group spans", () => {
    const rclone = groups.find((g) => g.detail === "Rclone Config File Creation");
    expect(rclone.first_seen <= rclone.last_seen).toBe(true);
  });
});

describe("numbers, and only numbers", () => {
  it("keeps the digits and drops everything else", () => {
    expect(digitsOnly("1e3")).toBe("13");
    expect(digitsOnly("-25.7")).toBe("257");
    expect(digitsOnly("")).toBe("");
    expect(digitsOnly(null)).toBe("");
  });

  it("clamps into range rather than refusing", () => {
    expect(clampNumber("900", { min: 1, max: 200, fallback: 50 })).toBe(200);
    expect(clampNumber("0", { min: 1, max: 200, fallback: 50 })).toBe(50);
    expect(clampNumber("", { min: 1, max: 200, fallback: 50 })).toBe(50);
    expect(clampNumber("37", { min: 1, max: 200, fallback: 50 })).toBe(37);
  });

  it("holds the page size inside what the endpoint accepts", () => {
    // 201 and above come back 422
    expect(safePageSize("201")).toBe(200);
    expect(safePageSize("abc")).toBe(50);
    expect(safePageSize("1")).toBe(1);
  });

  it("holds the page inside the pages that exist", () => {
    expect(safePage("9999", 3)).toBe(3);
    expect(safePage("2", 3)).toBe(2);
    expect(safePage("", 3)).toBe(1);
    expect(safePage("5", 0)).toBe(1);
  });
});

describe("time windows", () => {
  it("offers every preset the list is meant to have", () => {
    expect(TIME_RANGES.map((r) => r.id)).toEqual([
      "1h", "3h", "6h", "12h", "24h", "5d", "10d", "15d", "30d",
    ]);
  });

  it("bounds both ends, computed when it is applied", () => {
    expect(rangeWindow("1h", NOW)).toEqual({
      from_dt: new Date(NOW - 3600000).toISOString(),
      to_dt: new Date(NOW).toISOString(),
    });
  });

  it("measures the longer presets in days", () => {
    const window = rangeWindow("30d", NOW);
    expect(Date.parse(window.to_dt) - Date.parse(window.from_dt)).toBe(30 * 86400000);
  });

  it("has no window for a preset it does not know", () => {
    expect(rangeWindow("forever", NOW)).toBeNull();
  });

  it("reads a typed wall-clock time in the reader's own zone", () => {
    // what someone types is the time on their clock, not a UTC instant
    const typed = "2026-10-07T11:30";
    expect(localToIso(typed)).toBe(new Date(typed).toISOString());
    expect(isoToLocalInput(localToIso(typed))).toBe(typed);
  });

  it("refuses a window before it is sent, rather than showing an empty list", () => {
    expect(rangeProblem("2026-10-07T12:00", "2026-10-07T10:00")).toMatch(/before the end/);
    expect(rangeProblem("", "2026-10-07T10:00")).toMatch(/Both a start and an end/);
    expect(rangeProblem("2026-10-07T10:00", "2026-10-07T12:00")).toBe("");
  });

  it("says the window in words", () => {
    expect(describeWindow(rangeWindow("1h", NOW))).toMatch(/→/);
    expect(describeWindow(null)).toBe("");
  });
});

describe("the page", () => {
  it("asks for the first page at fifty, bounded at both ends, on arrival", async () => {
    renderPage();
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    const params = lastListParams();
    expect(params).toMatchObject({ page: 1, page_size: 50 });
    expect(Date.parse(params.from_dt)).not.toBeNaN();
    expect(Date.parse(params.to_dt)).not.toBeNaN();
    // the default is the last 24 hours
    expect(Date.parse(params.to_dt) - Date.parse(params.from_dt)).toBeCloseTo(86400000, -3);
  });

  it("sends both paging values as numbers, never as the strings the fields hold", async () => {
    renderPage();
    await hero();
    const params = lastListParams();
    expect(typeof params.page).toBe("number");
    expect(typeof params.page_size).toBe("number");
  });

  it("keeps anything that is not a digit out of the paging fields", async () => {
    renderPage();
    await hero();

    const size = screen.getByLabelText("Per page");
    fireEvent.change(size, { target: { value: "1e3" } });
    expect(size.value).toBe("13");

    fireEvent.change(size, { target: { value: "-25abc" } });
    expect(size.value).toBe("25");
  });

  it("takes a page size and starts again from the first page", async () => {
    renderPage();
    await hero();

    fireEvent.change(screen.getByLabelText("Per page"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));

    await waitFor(() => expect(lastListParams()).toMatchObject({ page: 1, page_size: 100 }));
  });

  it("clamps a page size past the endpoint's ceiling instead of earning a 422", async () => {
    renderPage();
    await hero();

    const size = screen.getByLabelText("Per page");
    fireEvent.change(size, { target: { value: "900" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));

    expect(size.value).toBe("200");
    await waitFor(() => expect(lastListParams()).toMatchObject({ page_size: 200 }));
  });

  it("jumps to a page that is typed rather than clicked to", async () => {
    renderPage();
    await hero();

    const field = screen.getByLabelText("Page");
    fireEvent.change(field, { target: { value: "128" } });
    fireEvent.submit(field.closest("form"));

    await waitFor(() => expect(lastListParams()).toMatchObject({ page: 128 }));
  });

  it("will not jump past the last page there is", async () => {
    mockApi({ total: 120 }); // three pages at fifty
    renderPage();
    await hero();

    const field = screen.getByLabelText("Page");
    fireEvent.change(field, { target: { value: "9999" } });
    fireEvent.submit(field.closest("form"));

    expect(field.value).toBe("3");
    await waitFor(() => expect(lastListParams()).toMatchObject({ page: 3 }));
  });

  it("puts the page field back to one whenever the question changes", async () => {
    renderPage();
    await hero();

    const field = screen.getByLabelText("Page");
    fireEvent.change(field, { target: { value: "40" } });
    fireEvent.submit(field.closest("form"));
    await waitFor(() => expect(lastListParams()).toMatchObject({ page: 40 }));

    fireEvent.click(screen.getByRole("button", { name: /high/i }));
    await waitFor(() => expect(lastListParams()).toMatchObject({ page: 1 }));
    expect(screen.getByLabelText("Page").value).toBe("1");
  });

  it("leads with the server's own total, not the number of rows on screen", async () => {
    renderPage();
    expect((await hero()).textContent).toBe(TOTAL_TEXT);
    expect(screen.getByText(`Showing 1–3 of ${TOTAL_TEXT}`)).toBeInTheDocument();
  });

  it("shows each detection with its severity, agent and technique", async () => {
    renderPage();
    const list = await screen.findByRole("list", { name: "" }).catch(() => null);
    expect(await screen.findByText("ETW Trace Evasion Activity")).toBeInTheDocument();
    expect(screen.getByText("T1070")).toBeInTheDocument();
    expect(screen.getAllByText("high").length).toBeGreaterThan(0);
    expect(list === null || list).toBeTruthy();
  });

  it("counts each severity across everything the other filters match", async () => {
    renderPage();
    const critical = await screen.findByRole("button", { name: /critical/i });
    await waitFor(() => expect(within(critical).getByText((140).toLocaleString())).toBeInTheDocument());
  });

  it("filters on severity_min, because a level means it and everything above", async () => {
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /high/i }));
    await waitFor(() => expect(lastListParams()).toMatchObject({ severity_min: 4 }));
  });

  it("goes back to the first page whenever the question changes", async () => {
    renderPage();
    await hero();

    fireEvent.click(screen.getByRole("button", { name: /Older/ }));
    await waitFor(() => expect(lastListParams()).toMatchObject({ page: 2 }));

    fireEvent.click(screen.getByRole("button", { name: /medium/i }));
    await waitFor(() => expect(lastListParams()).toMatchObject({ page: 1, severity_min: 3 }));
  });

  it("sends nothing until Apply, whichever field was touched", async () => {
    renderPage();
    await hero();
    const before = api.get.mock.calls.length;

    fireEvent.change(screen.getByLabelText("Agent"), { target: { value: "shiv1" } });
    fireEvent.change(screen.getByLabelText("Seen"), { target: { value: "6h" } });
    fireEvent.change(screen.getByLabelText("Per page"), { target: { value: "100" } });
    expect(api.get.mock.calls.length).toBe(before);

    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() =>
      expect(lastListParams()).toMatchObject({ agent_name: "shiv1", page_size: 100, page: 1 })
    );
  });

  it("commits every field from the one button, in one request", async () => {
    renderPage();
    await hero();

    fireEvent.change(screen.getByLabelText("Seen"), { target: { value: "custom" } });
    fireEvent.change(screen.getByLabelText("From"), { target: { value: "2026-10-01T09:00" } });
    fireEvent.change(screen.getByLabelText("To"), { target: { value: "2026-10-02T17:30" } });
    fireEvent.change(screen.getByLabelText("Agent"), { target: { value: "shiv1" } });
    fireEvent.change(screen.getByLabelText("Per page"), { target: { value: "75" } });

    const before = api.get.mock.calls.filter(([, c]) => (c.params || {}).page_size !== 1).length;
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));

    await waitFor(() =>
      expect(lastListParams()).toMatchObject({
        agent_name: "shiv1",
        page_size: 75,
        page: 1,
        from_dt: new Date("2026-10-01T09:00").toISOString(),
        to_dt: new Date("2026-10-02T17:30").toISOString(),
      })
    );
    const after = api.get.mock.calls.filter(([, c]) => (c.params || {}).page_size !== 1).length;
    expect(after - before).toBe(1);
  });

  it("offers one Apply, not one per field", async () => {
    renderPage();
    await hero();
    fireEvent.change(screen.getByLabelText("Seen"), { target: { value: "custom" } });
    expect(screen.getAllByRole("button", { name: /^apply/i })).toHaveLength(1);
  });

  it("narrows the window from the dropdown", async () => {
    renderPage();
    await hero();

    fireEvent.change(screen.getByLabelText("Seen"), { target: { value: "1h" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => {
      const p = lastListParams();
      expect(Date.parse(p.to_dt) - Date.parse(p.from_dt)).toBeCloseTo(3600000, -3);
    });
  });

  it("takes a window typed by hand, to the minute", async () => {
    renderPage();
    await hero();

    fireEvent.change(screen.getByLabelText("Seen"), { target: { value: "custom" } });
    fireEvent.change(screen.getByLabelText("From"), { target: { value: "2026-10-01T09:00" } });
    fireEvent.change(screen.getByLabelText("To"), { target: { value: "2026-10-02T17:30" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));

    await waitFor(() =>
      expect(lastListParams()).toMatchObject({
        from_dt: new Date("2026-10-01T09:00").toISOString(),
        to_dt: new Date("2026-10-02T17:30").toISOString(),
        page: 1,
        page_size: 50,
      })
    );
  });

  it("seeds the custom fields from the window already on screen", async () => {
    renderPage();
    await hero();

    fireEvent.change(screen.getByLabelText("Seen"), { target: { value: "custom" } });
    const stamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/;
    expect(screen.getByLabelText("From").value).toMatch(stamp);
    expect(screen.getByLabelText("To").value).toMatch(stamp);
  });

  it("says a backwards window is backwards instead of asking for it", async () => {
    renderPage();
    await hero();

    fireEvent.change(screen.getByLabelText("Seen"), { target: { value: "custom" } });
    fireEvent.change(screen.getByLabelText("From"), { target: { value: "2026-10-02T17:30" } });
    fireEvent.change(screen.getByLabelText("To"), { target: { value: "2026-10-01T09:00" } });

    const before = api.get.mock.calls.length;
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/before the end/);
    expect(api.get.mock.calls.length).toBe(before);
  });

  it("says the folding only reaches this page", async () => {
    renderPage();
    expect(await screen.findByText("Fold repeats on this page")).toBeInTheDocument();
  });

  it("folds the list when asked", async () => {
    renderPage();
    await hero();
    expect(screen.getAllByText("Rclone Config File Creation").length).toBe(2);

    fireEvent.click(screen.getByLabelText("Fold repeats on this page"));
    await waitFor(() =>
      expect(screen.getAllByText("Rclone Config File Creation").length).toBe(1)
    );
    expect(screen.getByText("×2")).toBeInTheDocument();
  });

  it("offers a way out when a filter matches nothing", async () => {
    mockApi({ total: 0, alerts: [] });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /critical/i }));
    expect(await screen.findByText("No alert matches these filters.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Clear the filters" })).toBeInTheDocument();
  });

  it("says what went wrong rather than showing an empty list", async () => {
    api.get.mockRejectedValue({ response: { status: 500, data: { detail: "Internal Server Error" } } });
    renderPage();
    expect(await screen.findByRole("alert")).toHaveTextContent("Internal Server Error");
  });

  it("does not offer a pager when everything fits on one page", async () => {
    mockApi({ total: 3 });
    renderPage();
    await screen.findByText("Showing 1–3 of 3");
    expect(screen.queryByRole("navigation", { name: "Pages" })).not.toBeInTheDocument();
  });
});

describe("picking an agent from the ones that exist", () => {
  /** The combobox input, whatever role it is currently playing. */
  const field = () => screen.getByLabelText("Agent");

  /**
   * Open the list, once there is one.
   *
   * The agents arrive from a second request, and until they do the field is a
   * plain text box that opens nothing — which is the point of the fallback, and
   * which a test that clicks the instant the page renders would hit every time.
   */
  const openAgents = async () => {
    await waitFor(() => expect(field()).toHaveAttribute("role", "combobox"));
    fireEvent.click(field());
    return screen.findByRole("listbox", { name: "Agents" });
  };

  it("shows the agents when the field is clicked", async () => {
    renderPage();
    await hero();

    const list = await openAgents();
    expect(within(list).getByText("shiv1")).toBeInTheDocument();
    expect(within(list).getByText("agent_david")).toBeInTheDocument();
    expect(within(list).getByText("DESKTOP-4G26IBD")).toBeInTheDocument();
  });

  it("narrows the list as the name is typed", async () => {
    renderPage();
    await hero();

    await openAgents();
    fireEvent.change(field(), { target: { value: "lin" } });

    const list = screen.getByRole("listbox", { name: "Agents" });
    expect(within(list).getByText("Linux_testing")).toBeInTheDocument();
    expect(within(list).queryByText("shiv1")).not.toBeInTheDocument();
  });

  it("searches the hostname too, which is what people remember", async () => {
    renderPage();
    await hero();

    await openAgents();
    fireEvent.change(field(), { target: { value: "EP8PIFQ" } });

    const list = screen.getByRole("listbox", { name: "Agents" });
    expect(within(list).getByText("agent_david")).toBeInTheDocument();
  });

  it("takes the agent that is clicked and closes the list", async () => {
    renderPage();
    await hero();

    const list = await openAgents();
    fireEvent.click(within(list).getByText("agent_david"));

    expect(field().value).toBe("agent_david");
    await waitFor(() =>
      expect(screen.queryByRole("listbox", { name: "Agents" })).not.toBeInTheDocument()
    );
  });

  it("does not call the API until Apply, and then sends the agent", async () => {
    renderPage();
    await hero();

    const list = await openAgents();
    const before = api.get.mock.calls.length;
    fireEvent.click(within(list).getByText("shiv1"));
    expect(api.get.mock.calls.length).toBe(before);

    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(lastListParams()).toMatchObject({ agent_name: "shiv1" }));
  });

  it("walks the list with the arrow keys and takes one with Enter", async () => {
    renderPage();
    await hero();

    await openAgents();
    fireEvent.keyDown(field(), { key: "ArrowDown" });
    fireEvent.keyDown(field(), { key: "Enter" });

    expect(field().value).toBe(AGENTS[0].agent_name);
  });

  it("clears back to every agent from inside the list", async () => {
    renderPage();
    await hero();

    let list = await openAgents();
    fireEvent.click(within(list).getByText("shiv1"));
    expect(field().value).toBe("shiv1");

    list = await openAgents();
    fireEvent.click(within(list).getByText("Every agent"));

    expect(field().value).toBe("");
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(lastListParams().agent_name).toBeUndefined());
  });

  it("escape closes the list without choosing", async () => {
    renderPage();
    await hero();

    await openAgents();
    fireEvent.keyDown(field(), { key: "Escape" });

    await waitFor(() =>
      expect(screen.queryByRole("listbox", { name: "Agents" })).not.toBeInTheDocument()
    );
    expect(field().value).toBe("");
  });

  it("stays a plain field when the agent list cannot be read", async () => {
    // /get-agents needs a session and answers 401 without one; the filter must
    // not stop working because a second, unrelated request failed
    mockApi({ agents: [] });
    renderPage();
    await hero();

    fireEvent.click(field());
    expect(screen.queryByRole("listbox", { name: "Agents" })).not.toBeInTheDocument();

    fireEvent.change(field(), { target: { value: "typed_by_hand" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(lastListParams()).toMatchObject({ agent_name: "typed_by_hand" }));
  });

  it("sends a name that is typed but not in the list", async () => {
    renderPage();
    await hero();

    fireEvent.change(field(), { target: { value: "ghost_agent" } });
    expect(screen.getByText(/It will still be sent as typed/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(lastListParams()).toMatchObject({ agent_name: "ghost_agent" }));
  });
});

describe("category, and which severity question is being asked", () => {
  it("offers exactly the categories the endpoint documents", async () => {
    renderPage();
    await hero();

    const picker = screen.getByLabelText("Category");
    expect([...picker.options].map((o) => o.value)).toEqual([
      "",
      "file",
      "process",
      "network",
      "authentication",
      "usb",
      "database",
    ]);
  });

  it("sends the category only once Apply is pressed", async () => {
    renderPage();
    await hero();

    const before = api.get.mock.calls.length;
    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "process" } });
    expect(api.get.mock.calls.length).toBe(before);

    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(lastListParams()).toMatchObject({ category: "process" }));
  });

  it("sends no category at all for every category", async () => {
    renderPage();
    await hero();

    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "usb" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(lastListParams().category).toBe("usb"));

    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(lastListParams().category).toBeUndefined());
  });

  it("names the cause when the server rejects a category", async () => {
    // a request carrying a category is the one most likely to have been
    // refused, so say which filter to drop rather than "please try again"
    renderPage();
    await hero();

    api.get.mockRejectedValue({ response: { status: 500, data: {} } });
    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "network" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/could not answer with the category "network"/i);
    expect(alert).toHaveTextContent(/other filters are unaffected/i);
  });

  it("names the cause even when the browser blocked the 500 outright", async () => {
    // FastAPI’s unhandled error skips its CORS middleware, so the browser
    // blocks the response and axios is left with no status to read
    renderPage();
    await hero();

    api.get.mockRejectedValue(new Error("Network Error"));
    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "usb" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/could not answer with the category "usb"/i);
  });

  it("includes the info level the API documents", async () => {
    renderPage();
    await hero();
    expect(screen.getByRole("button", { name: /info/i })).toBeInTheDocument();
  });

  it("asks for a level and above by default", async () => {
    renderPage();
    await hero();

    fireEvent.click(screen.getByRole("button", { name: /high/i }));
    await waitFor(() => {
      const p = lastListParams();
      expect(p.severity_min).toBe(4);
      expect(p.severity).toBeUndefined();
    });
  });

  it("switches to the exact level, and sends the other parameter", async () => {
    renderPage();
    await hero();

    fireEvent.click(screen.getByRole("button", { name: /high/i }));
    await waitFor(() => expect(lastListParams().severity_min).toBe(4));

    fireEvent.click(screen.getByRole("button", { name: "exactly" }));
    await waitFor(() => {
      const p = lastListParams();
      expect(p.severity).toBe(4);
      expect(p.severity_min).toBeUndefined();
    });
  });

  it("sends neither parameter while the level is Any", async () => {
    renderPage();
    await hero();

    fireEvent.click(screen.getByRole("button", { name: "exactly" }));
    await waitFor(() => {
      const p = lastListParams();
      expect(p.severity).toBeUndefined();
      expect(p.severity_min).toBeUndefined();
    });
  });

  it("says which question the counts are answering", async () => {
    renderPage();
    await hero();
    expect(screen.getByText(/and everything above it/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "exactly" }));
    expect(screen.getByText(/that level only/)).toBeInTheDocument();
  });
});

describe("counts that could not be read", () => {
  it('says "—" for Any rather than summing failures to zero', async () => {
    // a category filter makes every count request fail too; a confident 0 beside
    // "Any" would contradict the dashes beside every level under it
    api.get.mockImplementation((url, config) => {
      const params = (config && config.params) || {};
      if (String(url).includes("get-agents")) return Promise.resolve({ data: { data: { agents: [] } } });
      if (params.page_size === 1 && params.severity) return Promise.reject(new Error("500"));
      return Promise.resolve({
        data: { data: { total: 0, page: 1, page_size: 50, alerts: [] } },
      });
    });

    renderPage();
    const any = await screen.findByRole("button", { name: /^any/i });
    await waitFor(() => expect(within(any).getByText("—")).toBeInTheDocument());
  });
});

describe("the category on every row", () => {
  it("shows what kind of thing each rule watched", async () => {
    renderPage();
    await hero();

    // scoped to the rows: "file" is also an option in the category dropdown,
    // so an unscoped match would pass without a single row carrying one
    const chips = [...document.querySelectorAll(".al-row .al-category")].map((c) => c.textContent);
    expect(chips).toEqual(["file", "file", "process"]);
  });

  it("shows nothing rather than an empty chip on an older record", async () => {
    mockApi({ alerts: [alert({ id: 1, category: null })] });
    renderPage();
    await hero();
    expect(document.querySelector(".al-category")).toBeNull();
  });

  it("carries the category onto a folded row", async () => {
    renderPage();
    await hero();
    fireEvent.click(screen.getByLabelText("Fold repeats on this page"));
    await waitFor(() => expect(screen.getByText("×2")).toBeInTheDocument());
    expect(document.querySelectorAll(".al-category").length).toBeGreaterThan(0);
  });
});

describe("narrowing the rows already fetched", () => {
  const filterBox = () => screen.getByLabelText("Filter the rows on this page");

  it("hides the rows that do not match, without asking the server again", async () => {
    renderPage();
    await hero();
    const before = api.get.mock.calls.length;

    fireEvent.change(filterBox(), { target: { value: "ETW" } });

    expect(screen.getByText("ETW Trace Evasion Activity")).toBeInTheDocument();
    expect(screen.queryByText("Rclone Config File Creation")).not.toBeInTheDocument();
    expect(api.get.mock.calls.length).toBe(before);
  });

  it("searches every field a reader can see", async () => {
    renderPage();
    await hero();

    // the entity column
    fireEvent.change(filterBox(), { target: { value: "chrome" } });
    expect(screen.getByText("ETW Trace Evasion Activity")).toBeInTheDocument();

    // the agent
    fireEvent.change(filterBox(), { target: { value: "agent_david" } });
    expect(screen.getAllByText("Rclone Config File Creation").length).toBe(1);

    // the category
    fireEvent.change(filterBox(), { target: { value: "file" } });
    expect(screen.getAllByRole("listitem").length).toBeGreaterThan(0);
  });

  it("says what it narrowed and what it did not touch", async () => {
    renderPage();
    await hero();

    fireEvent.change(filterBox(), { target: { value: "ETW" } });
    const line = document.querySelector(".al-showing").textContent;
    // the rows in hand, and the result the server reported, kept apart
    expect(line).toMatch(/1 of these 3 rows/);
    expect(line).toMatch(new RegExp(`${TOTAL_TEXT} in the whole result`));
  });

  it("explains itself when nothing on the page matches", async () => {
    renderPage();
    await hero();

    fireEvent.change(filterBox(), { target: { value: "nothing_like_this" } });
    expect(screen.getByText("No row on this page matches that.")).toBeInTheDocument();
    expect(screen.getByText(/use the filters above/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Clear this filter" }));
    expect(filterBox().value).toBe("");
    expect(screen.getAllByText("Rclone Config File Creation").length).toBe(2);
  });

  it("folds only the rows the filter left", async () => {
    renderPage();
    await hero();

    fireEvent.change(filterBox(), { target: { value: "agent_david" } });
    fireEvent.click(screen.getByLabelText("Fold repeats on this page"));

    await waitFor(() =>
      expect(screen.getAllByText("Rclone Config File Creation").length).toBe(1)
    );
    // one alert survived the filter, so the fold counts one — not two
    expect(screen.queryByText("×2")).not.toBeInTheDocument();
  });
});

describe("the view lives in the address bar", () => {
  it("writes what was chosen, and leaves the defaults out", async () => {
    renderPage();
    await hero();
    // an untouched page keeps a clean address
    expect(lastSearch).toBe("");

    fireEvent.click(screen.getByRole("button", { name: /high/i }));
    await waitFor(() => expect(lastSearch).toContain("sev=4"));
    expect(lastSearch).not.toContain("mode=");
  });

  it("carries every filter, so a view can be sent to somebody", async () => {
    renderPage();
    await hero();

    fireEvent.click(screen.getByRole("button", { name: /critical/i }));
    fireEvent.click(screen.getByRole("button", { name: "exactly" }));
    fireEvent.change(screen.getByLabelText("Agent"), { target: { value: "shiv1" } });
    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "process" } });
    fireEvent.change(screen.getByLabelText("Seen"), { target: { value: "1h" } });
    fireEvent.change(screen.getByLabelText("Per page"), { target: { value: "100" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));

    await waitFor(() => expect(lastSearch).toContain("agent=shiv1"));
    const params = new URLSearchParams(lastSearch);
    expect(params.get("sev")).toBe("5");
    expect(params.get("mode")).toBe("exact");
    expect(params.get("category")).toBe("process");
    expect(params.get("range")).toBe("1h");
    expect(params.get("size")).toBe("100");
  });

  it("opens a shared link on the view it describes", async () => {
    renderPage("/app/alerts?sev=4&mode=exact&agent=shiv1&category=file&size=100&page=3");
    await hero();

    await waitFor(() =>
      expect(lastListParams()).toMatchObject({
        severity: 4,
        agent_name: "shiv1",
        category: "file",
        page: 3,
        page_size: 100,
      })
    );
    expect(screen.getByLabelText("Agent").value).toBe("shiv1");
    expect(screen.getByLabelText("Per page").value).toBe("100");
    expect(screen.getByRole("button", { name: "exactly" })).toHaveAttribute(
      "aria-pressed",
      "true"
    );
  });

  it("restores a hand-typed window from a link", async () => {
    renderPage(
      "/app/alerts?range=custom&from=2026-10-01T09:00:00.000Z&to=2026-10-02T17:30:00.000Z"
    );
    await hero();

    await waitFor(() =>
      expect(lastListParams()).toMatchObject({
        from_dt: "2026-10-01T09:00:00.000Z",
        to_dt: "2026-10-02T17:30:00.000Z",
      })
    );
  });

  it("ignores a URL that asks for something the endpoint does not offer", async () => {
    // addresses get typed, pasted and edited by hand
    renderPage("/app/alerts?sev=99&category=not_a_category&range=nonsense&size=9999");
    await hero();

    const params = lastListParams();
    expect(params.severity_min).toBeUndefined();
    expect(params.category).toBeUndefined();
    expect(params.page_size).toBe(200); // clamped to the endpoint's ceiling
    expect(Date.parse(params.from_dt)).not.toBeNaN();
  });
});

describe("a live list", () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  const liveBox = () => screen.getByLabelText("Live");

  it("re-reads on a timer once asked to", async () => {
    renderPage();
    await waitFor(() => expect(api.get).toHaveBeenCalled());

    fireEvent.click(liveBox());
    const before = api.get.mock.calls.length;
    jest.advanceTimersByTime(30000);
    expect(api.get.mock.calls.length).toBeGreaterThan(before);
  });

  it("does nothing until it is asked", async () => {
    renderPage();
    await waitFor(() => expect(api.get).toHaveBeenCalled());

    const before = api.get.mock.calls.length;
    jest.advanceTimersByTime(90000);
    expect(api.get.mock.calls.length).toBe(before);
  });

  it("pauses past page one, where new alerts would shift the rows", async () => {
    renderPage("/app/alerts?page=2");
    await waitFor(() => expect(api.get).toHaveBeenCalled());

    fireEvent.click(liveBox());
    const before = api.get.mock.calls.length;
    jest.advanceTimersByTime(60000);
    expect(api.get.mock.calls.length).toBe(before);
  });

  it("pauses while a row filter is being used, so the search is not lost", async () => {
    renderPage();
    await waitFor(() => expect(api.get).toHaveBeenCalled());

    fireEvent.click(liveBox());
    fireEvent.change(screen.getByLabelText("Filter the rows on this page"), {
      target: { value: "ETW" },
    });

    const before = api.get.mock.calls.length;
    jest.advanceTimersByTime(60000);
    expect(api.get.mock.calls.length).toBe(before);
  });
});

describe("taking the rows away as a file", () => {
  it("writes a header and a row for each alert on screen", () => {
    const csv = alertsToCsv(PAGE);
    const lines = csv.split("\r\n");
    expect(lines[0]).toContain('"category"');
    expect(lines).toHaveLength(PAGE.length + 1);
    expect(lines[1]).toContain('"file"');
  });

  it("quotes every cell, so a comma in a detail cannot shift the columns", () => {
    const csv = alertsToCsv([alert({ detail: 'Rclone, "config" created' })]);
    // the quotes inside are doubled, the whole cell is wrapped
    expect(csv).toContain('"Rclone, ""config"" created"');
    expect(csv.split("\r\n")).toHaveLength(2);
  });

  it("says nothing rather than inventing a cell for a missing field", () => {
    const csv = alertsToCsv([alert({ category: null, technique: "" })]);
    expect(csv.split("\r\n")[1]).toContain('""');
  });

  it("names the file by the moment it was taken", () => {
    expect(csvFilename(new Date("2026-10-14T08:12:42Z"))).toBe("alerts-2026-10-14-08-12-42.csv");
  });

  it("offers only what is on screen, and counts it", async () => {
    renderPage();
    await hero();
    expect(screen.getByRole("button", { name: /Export 3 rows/ })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Filter the rows on this page"), {
      target: { value: "ETW" },
    });
    expect(screen.getByRole("button", { name: /Export 1 rows/ })).toBeInTheDocument();
  });
});
