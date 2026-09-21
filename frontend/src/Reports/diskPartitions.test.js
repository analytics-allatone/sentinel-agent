/**
 * Reading the capacity API's disk_partitions.
 *
 * The shape comes from the agent (agent/collectors/capacity_monitoring_collector.py,
 * _disk_metrics): device, mountpoint, fstype, percent, used_gb, total_gb, free_gb.
 * An older agent sends no such field at all, which must not break the page.
 */
import {
  DISK_CRITICAL,
  DISK_WARN,
  bandCounts,
  diskLevel,
  formatGb,
  partitionRole,
  readPartitions,
  sumGb,
} from "./diskPartitions";

const PAYLOAD = {
  agent_name: "Linux_testing",
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
      device: "/dev/sda1",
      mountpoint: "/boot/efi",
      fstype: "vfat",
      percent: 12.5,
      used_gb: 0.06,
      total_gb: 0.5,
      free_gb: 0.44,
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
  ],
};

describe("reading the list", () => {
  test("the fullest volume comes first, because it is the one that matters", () => {
    const partitions = readPartitions(PAYLOAD);

    expect(partitions.map((p) => p.mountpoint)).toEqual([
      "/var/log",
      "/",
      "/boot/efi",
    ]);
  });

  test("each field is carried across", () => {
    const [worst] = readPartitions(PAYLOAD);

    expect(worst).toEqual({
      device: "/dev/sdb1",
      mountpoint: "/var/log",
      fstype: "xfs",
      percent: 96.3,
      usedGb: 19.2,
      totalGb: 20,
      freeGb: 0.8,
    });
  });

  test.each([
    ["an older agent that sends nothing", {}],
    ["a null field", { disk_partitions: null }],
    ["an object where a list was expected", { disk_partitions: {} }],
    ["no payload at all", null],
  ])("%s reads as an empty list, not a crash", (_name, payload) => {
    expect(readPartitions(payload)).toEqual([]);
  });

  test("entries with neither a device nor a mount point are dropped", () => {
    const partitions = readPartitions({
      disk_partitions: [{ fstype: "tmpfs" }, null, { mountpoint: "/" }],
    });

    expect(partitions).toHaveLength(1);
    expect(partitions[0].mountpoint).toBe("/");
  });

  test("an unreadable percent counts as zero rather than NaN", () => {
    const [only] = readPartitions({
      disk_partitions: [{ mountpoint: "/data", percent: null }],
    });

    expect(only.percent).toBe(0);
  });
});

describe("usage bands", () => {
  test.each([
    [0, "ok"],
    [69.9, "ok"],
    [DISK_WARN, "warn"],
    [84.9, "warn"],
    [DISK_CRITICAL, "critical"],
    [100, "critical"],
  ])("%s%% reads as %s", (percent, expected) => {
    expect(diskLevel(percent)).toBe(expected);
  });
});

describe("sizes", () => {
  test.each([
    [0.44, "0.4 GB"],
    [48.2, "48.2 GB"],
    [512, "512 GB"], // no false precision once the number is large
    [2048, "2.00 TB"],
  ])("%s reads as %s", (value, expected) => {
    expect(formatGb(value)).toBe(expected);
  });

  test.each([null, undefined, "", "nonsense"])(
    "%s reads as a dash, never NaN",
    (value) => {
      expect(formatGb(value)).toBe("—");
    }
  );

  test("totals skip what the agent could not measure", () => {
    const partitions = readPartitions({
      disk_partitions: [
        { mountpoint: "/", total_gb: 48.2 },
        { mountpoint: "/data", total_gb: null },
        { mountpoint: "/var", total_gb: 20 },
      ],
    });

    expect(sumGb(partitions, "totalGb")).toBeCloseTo(68.2, 5);
  });
});

describe("counting the bands", () => {
  test("each volume lands in exactly one band", () => {
    expect(bandCounts(readPartitions(PAYLOAD))).toEqual({
      ok: 1,
      warn: 1,
      critical: 1,
    });
  });

  test("no volumes counts as nothing, not as healthy", () => {
    expect(bandCounts([])).toEqual({ ok: 0, warn: 0, critical: 0 });
  });
});

describe("what a mount point is for", () => {
  test.each([
    ["/", "System root"],
    ["/boot/efi", "EFI boot partition"],
    ["/var/log", "Logs & variable data"],
    ["/var/log/journal", "Logs & variable data"],
    ["/home", "User data"],
    ["/home/naresh", "User data"],
    ["/mnt/backup", "Mounted storage"],
    ["/var/lib/docker", "Container storage"],
    ["C:\\", "System drive"],
    ["D:\\", "Secondary drive"],
    ["/", "System root"],
  ])("%s reads as %s", (mount, expected) => {
    expect(partitionRole(mount)).toBe(expected);
  });

  test("a trailing slash does not change the answer", () => {
    expect(partitionRole("/var/log/")).toBe(partitionRole("/var/log"));
  });

  // Silence beats a wrong guess: a label nobody can trust is worse than none.
  test.each([["/srv/customer-uploads-2019"], ["/weird/path"], [""], [null]])(
    "%s gets no label rather than a guess",
    (mount) => {
      expect(partitionRole(mount)).toBe("");
    }
  );
});
