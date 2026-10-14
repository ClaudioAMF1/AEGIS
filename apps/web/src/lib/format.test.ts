import { describe, expect, it } from "vitest";

import { formatDuration, formatNumber, relative, severityLabel } from "./format";
import { cn } from "./utils";

describe("format", () => {
  it("formats relative times in Portuguese", () => {
    const now = Date.parse("2026-10-14T12:00:00Z");
    expect(relative("2026-10-14T11:59:58Z", now)).toBe("agora");
    expect(relative("2026-10-14T11:59:30Z", now)).toBe("há 30s");
    expect(relative("2026-10-14T11:59:00Z", now)).toBe("há 1min");
    expect(relative("2026-10-14T11:30:00Z", now)).toBe("há 30min");
    expect(relative("2026-10-14T06:00:00Z", now)).toBe("há 6h");
    expect(relative(null, now)).toBe("nunca");
  });

  it("formats durations and numbers", () => {
    expect(formatDuration(null)).toBe("—");
    expect(formatDuration(42)).toBe("42s");
    expect(formatDuration(90)).toBe("1.5min");
    expect(formatDuration(7200)).toBe("2.0h");
    expect(formatNumber(12345)).toBe("12.345");
  });

  it("labels severities", () => {
    expect(severityLabel.critical).toBe("crítica");
  });

  it("merges tailwind classes including the custom 2xs size", () => {
    expect(cn("text-xs text-muted", "text-2xs")).toBe("text-muted text-2xs");
    expect(cn("text-xs", "text-accent")).toBe("text-xs text-accent");
  });
});
