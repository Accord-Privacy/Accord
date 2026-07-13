import { describe, it, expect, beforeEach } from "vitest";
import {
  getNodeRetention,
  setNodeRetention,
  getChannelRetentionOverride,
  setChannelRetention,
  effectiveTtl,
  expiryForNow,
  isExpired,
  wipeOldCutoff,
  serializeNodeSettings,
  applyNodeSettings,
  getNodeScreenshotProtect,
  setNodeScreenshotProtect,
  getChannelScreenshotOverride,
  setChannelScreenshotProtect,
  effectiveScreenshotProtect,
  getNodeAutoMod,
  setNodeAutoMod,
  checkAutoMod,
} from "./retention";

const NODE = "node-1";
const CHAN = "chan-1";

describe("retention policy", () => {
  beforeEach(() => localStorage.clear());

  it("defaults to keep-forever", () => {
    expect(getNodeRetention(NODE)).toBe(0);
    expect(getChannelRetentionOverride(CHAN)).toBeNull();
    expect(effectiveTtl(NODE, CHAN)).toBe(0);
  });

  it("node default applies to channels without an override", () => {
    setNodeRetention(NODE, 86400);
    expect(getNodeRetention(NODE)).toBe(86400);
    expect(effectiveTtl(NODE, CHAN)).toBe(86400);
  });

  it("channel override wins over the node default", () => {
    setNodeRetention(NODE, 86400);
    setChannelRetention(CHAN, 3600);
    expect(effectiveTtl(NODE, CHAN)).toBe(3600);
  });

  it("channel override of 0 keeps forever even when the node expires", () => {
    setNodeRetention(NODE, 86400);
    setChannelRetention(CHAN, 0);
    expect(getChannelRetentionOverride(CHAN)).toBe(0);
    expect(effectiveTtl(NODE, CHAN)).toBe(0);
  });

  it("clearing an override falls back to the node default", () => {
    setNodeRetention(NODE, 86400);
    setChannelRetention(CHAN, 3600);
    setChannelRetention(CHAN, null);
    expect(getChannelRetentionOverride(CHAN)).toBeNull();
    expect(effectiveTtl(NODE, CHAN)).toBe(86400);
  });

  it("DM channels (no node) use only their own override", () => {
    expect(effectiveTtl(undefined, CHAN)).toBe(0);
    setChannelRetention(CHAN, 3600);
    expect(effectiveTtl(undefined, CHAN)).toBe(3600);
  });

  it("rejects negative TTLs", () => {
    expect(() => setNodeRetention(NODE, -1)).toThrow();
    expect(() => setChannelRetention(CHAN, -5)).toThrow();
  });

  it("computes expiry only when a TTL is set", () => {
    expect(expiryForNow(0, 1000)).toBeUndefined();
    expect(expiryForNow(3600, 1000)).toBe(4600);
  });

  it("isExpired respects the TTL window", () => {
    // created at 1000, ttl 3600 → expires at 4600
    expect(isExpired(3600, 1000, 4599)).toBe(false);
    expect(isExpired(3600, 1000, 4600)).toBe(true);
    expect(isExpired(3600, 1000, 5000)).toBe(true);
    // never expires when ttl is 0
    expect(isExpired(0, 1000, 9_999_999)).toBe(false);
  });

  it("wipe-old cutoff is now minus the TTL", () => {
    expect(wipeOldCutoff(3600, 10000)).toBe(6400);
    expect(wipeOldCutoff(0, 10000)).toBe(0);
  });

  it("tolerates corrupt stored values", () => {
    localStorage.setItem("accord_retention_node_" + NODE, "not-a-number");
    expect(getNodeRetention(NODE)).toBe(0);
  });
});

describe("screenshot protection", () => {
  beforeEach(() => localStorage.clear());

  it("defaults to off; node default applies without an override", () => {
    expect(getNodeScreenshotProtect(NODE)).toBe(false);
    expect(effectiveScreenshotProtect(NODE, CHAN)).toBe(false);
    setNodeScreenshotProtect(NODE, true);
    expect(effectiveScreenshotProtect(NODE, CHAN)).toBe(true);
  });

  it("channel override wins and can be cleared", () => {
    setNodeScreenshotProtect(NODE, true);
    setChannelScreenshotProtect(CHAN, false);
    expect(getChannelScreenshotOverride(CHAN)).toBe(false);
    expect(effectiveScreenshotProtect(NODE, CHAN)).toBe(false);
    setChannelScreenshotProtect(CHAN, null);
    expect(getChannelScreenshotOverride(CHAN)).toBeNull();
    expect(effectiveScreenshotProtect(NODE, CHAN)).toBe(true);
  });

  it("DM channels (no node) use only their own override", () => {
    expect(effectiveScreenshotProtect(undefined, CHAN)).toBe(false);
    setChannelScreenshotProtect(CHAN, true);
    expect(effectiveScreenshotProtect(undefined, CHAN)).toBe(true);
  });
});

describe("node settings distribution", () => {
  beforeEach(() => localStorage.clear());

  it("serializes retention + screenshot with only the overridden channels", () => {
    setNodeRetention(NODE, 86400);
    setChannelRetention("c1", 3600);
    setNodeScreenshotProtect(NODE, true);
    setChannelScreenshotProtect("c1", false);
    const parsed = JSON.parse(serializeNodeSettings(NODE, ["c1", "c2"]));
    expect(parsed).toEqual({
      v: 1,
      retention: { node: 86400, channels: { c1: 3600 } },
      screenshot: { node: true, channels: { c1: false } },
      automod: [],
    });
  });

  it("applies a distributed settings blob into the local store", () => {
    const json = JSON.stringify({
      v: 1,
      retention: { node: 86400, channels: { c1: 0 } },
      screenshot: { node: true, channels: { c1: false } },
    });
    expect(applyNodeSettings(NODE, json)).toBe(true);
    expect(getNodeRetention(NODE)).toBe(86400);
    expect(getChannelRetentionOverride("c1")).toBe(0);
    expect(getNodeScreenshotProtect(NODE)).toBe(true);
    expect(getChannelScreenshotOverride("c1")).toBe(false);
  });

  it("round-trips serialize → apply", () => {
    setNodeRetention(NODE, 604800);
    setNodeScreenshotProtect(NODE, true);
    setChannelScreenshotProtect("c1", true);
    const json = serializeNodeSettings(NODE, ["c1", "c2"]);
    localStorage.clear();
    applyNodeSettings(NODE, json);
    expect(getNodeRetention(NODE)).toBe(604800);
    expect(getNodeScreenshotProtect(NODE)).toBe(true);
    expect(getChannelScreenshotOverride("c1")).toBe(true);
  });

  it("still reads the legacy retention-only blob format", () => {
    expect(applyNodeSettings(NODE, JSON.stringify({ v: 1, node: 3600, channels: { c1: 60 } }))).toBe(true);
    expect(getNodeRetention(NODE)).toBe(3600);
    expect(getChannelRetentionOverride("c1")).toBe(60);
  });

  it("ignores malformed or unknown-version payloads", () => {
    expect(applyNodeSettings(NODE, "not json")).toBe(false);
    expect(applyNodeSettings(NODE, JSON.stringify({ v: 2 }))).toBe(false);
    expect(getNodeRetention(NODE)).toBe(0);
  });
});

describe("auto-mod word filter (client-side)", () => {
  beforeEach(() => localStorage.clear());

  it("normalizes: lowercases, trims, dedupes, drops overlong", () => {
    setNodeAutoMod(NODE, [
      { word: "  Spam ", action: "block" },
      { word: "spam", action: "warn" }, // dup by normalized word — dropped
      { word: "w".repeat(101), action: "block" }, // too long — dropped
      { word: "Rude", action: "warn" },
    ]);
    expect(getNodeAutoMod(NODE)).toEqual([
      { word: "spam", action: "block" },
      { word: "rude", action: "warn" },
    ]);
  });

  it("checkAutoMod matches case-insensitively and reports the action", () => {
    setNodeAutoMod(NODE, [{ word: "badword", action: "block" }]);
    expect(checkAutoMod(NODE, "this has a BADWORD in it")).toEqual({ word: "badword", action: "block" });
    expect(checkAutoMod(NODE, "totally clean")).toBeNull();
  });

  it("rides the NMK settings blob: serialize → apply", () => {
    setNodeAutoMod(NODE, [{ word: "secret", action: "warn" }]);
    const json = serializeNodeSettings(NODE, []);
    localStorage.clear();
    applyNodeSettings(NODE, json);
    expect(getNodeAutoMod(NODE)).toEqual([{ word: "secret", action: "warn" }]);
  });

  it("a legacy blob without automod leaves the list empty", () => {
    applyNodeSettings(NODE, JSON.stringify({ v: 1, node: 3600, channels: {} }));
    expect(getNodeAutoMod(NODE)).toEqual([]);
  });
});
