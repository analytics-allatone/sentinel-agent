/**
 * The disk partitions page of the exported report.
 *
 * Both export routes render this same page — "Export to PDF" prints the
 * `.capacity-dash__print` tree, and "Send Report" rasterises each
 * `.capacity-dash__print-page` — so the class on the outer section is part of
 * the contract, not decoration: lose it and the page silently stops being
 * exported.
 */
import React from "react";
import { render, screen } from "@testing-library/react";

import DiskPartitionsPrint from "./DiskPartitionsPrint";
import { readPartitions } from "./diskPartitions";

const PARTITIONS = readPartitions({
  disk_partitions: [
    {
      device: "/dev/sda2",
      mountpoint: "/",
      fstype: "ext4",
      percent: 80.1,
      used_gb: 36.4,
      total_gb: 48.2,
      free_gb: 11.8,
    },
    {
      device: "/dev/sdb1",
      mountpoint: "/var/log",
      fstype: "xfs",
      percent: 96.3,
      used_gb: 19.2,
      total_gb: 20,
      free_gb: 0.8,
    },
    {
      device: "/dev/sda1",
      mountpoint: "/boot/efi",
      fstype: "vfat",
      percent: 12.5,
      used_gb: 0.06,
      total_gb: 0.5,
      free_gb: 0.44,
    },
  ],
});

const renderPage = (partitions = PARTITIONS) =>
  render(
    <DiskPartitionsPrint partitions={partitions} pageNumber={7} pageCount={7} />
  );

test("it is a page of the printed tree, so both exports carry it", () => {
  const { container } = renderPage();

  const page = container.querySelector(".capacity-dash__print-page");
  expect(page).toBeInTheDocument();
  expect(page).toHaveClass("capacity-dash__print-evidence-page");
});

test("every volume is listed, fullest first", () => {
  renderPage();

  const mounts = screen
    .getAllByRole("row")
    .slice(1) // the header
    .map((row) => row.cells[0].textContent);

  expect(mounts[0]).toMatch(/^\/var\/log/);
  expect(mounts[1]).toMatch(/^\//);
  expect(mounts[2]).toMatch(/^\/boot\/efi/);
});

test("a row carries the figures a reader needs", () => {
  renderPage();

  const worst = screen.getAllByRole("row")[1];
  const text = worst.textContent;

  expect(text).toContain("/var/log");
  expect(text).toContain("/dev/sdb1");
  expect(text).toContain("xfs");
  expect(text).toContain("19.2 GB"); // used
  expect(text).toContain("0.8 GB"); // free
  expect(text).toContain("20.0 GB"); // total
  expect(text).toContain("96.3%");
  expect(text).toContain("Critical"); // stated in words, not only in colour
});

test("the mount point says what the volume is for", () => {
  renderPage();

  expect(screen.getByText("Logs & variable data")).toBeInTheDocument();
  expect(screen.getByText("System root")).toBeInTheDocument();
  expect(screen.getByText("EFI boot partition")).toBeInTheDocument();
});

test("the page opens with the count in each band", () => {
  renderPage();

  expect(screen.getByText("1 critical")).toBeInTheDocument();
  expect(screen.getByText("1 to watch")).toBeInTheDocument();
  expect(screen.getByText("1 healthy")).toBeInTheDocument();
  expect(screen.getByText(/13\.0 GB free of 68\.7 GB/)).toBeInTheDocument();
});

test("the thresholds are stated, so the bands are not a mystery", () => {
  renderPage();

  expect(screen.getByText(/at or above 85%/)).toBeInTheDocument();
  expect(screen.getByText(/at or above 70%/)).toBeInTheDocument();
});

test("the footer numbers the page", () => {
  renderPage();

  expect(screen.getByText(/Page 7 of 7/)).toBeInTheDocument();
});

// "No partition data" and "this machine has no disks" are different claims.
test.each([[[]], [null], [undefined]])(
  "nothing is printed when there is nothing to print (%s)",
  (partitions) => {
    const { container } = render(
      <DiskPartitionsPrint partitions={partitions} pageNumber={7} pageCount={7} />
    );

    expect(container).toBeEmptyDOMElement();
  }
);
