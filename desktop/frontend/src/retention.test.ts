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
  serializeNodeRetention,
  applyNodeRetention,
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

describe("retention distribution", () => {
  beforeEach(() => localStorage.clear());

  it("serializes node default + only the channels with overrides", () => {
    setNodeRetention(NODE, 86400);
    setChannelRetention("c1", 3600);
    // c2 has no override; c3 isn't in the node's channel list.
    setChannelRetention("c3", 60);
    const json = serializeNodeRetention(NODE, ["c1", "c2"]);
    const parsed = JSON.parse(json);
    expect(parsed).toEqual({ v: 1, node: 86400, channels: { c1: 3600 } });
  });

  it("applies a distributed policy into the local store", () => {
    const json = JSON.stringify({ v: 1, node: 86400, channels: { c1: 3600, c2: 0 } });
    expect(applyNodeRetention(NODE, json)).toBe(true);
    expect(getNodeRetention(NODE)).toBe(86400);
    expect(getChannelRetentionOverride("c1")).toBe(3600);
    expect(getChannelRetentionOverride("c2")).toBe(0);
    expect(effectiveTtl(NODE, "c1")).toBe(3600);
  });

  it("round-trips serialize → apply", () => {
    setNodeRetention(NODE, 604800);
    setChannelRetention("c1", 3600);
    const json = serializeNodeRetention(NODE, ["c1", "c2"]);
    localStorage.clear();
    applyNodeRetention(NODE, json);
    expect(getNodeRetention(NODE)).toBe(604800);
    expect(getChannelRetentionOverride("c1")).toBe(3600);
  });

  it("reports no change when applying an identical policy", () => {
    setNodeRetention(NODE, 3600);
    expect(applyNodeRetention(NODE, JSON.stringify({ v: 1, node: 3600, channels: {} }))).toBe(false);
  });

  it("ignores malformed or unknown-version payloads", () => {
    expect(applyNodeRetention(NODE, "not json")).toBe(false);
    expect(applyNodeRetention(NODE, JSON.stringify({ v: 2, node: 3600 }))).toBe(false);
    expect(getNodeRetention(NODE)).toBe(0);
  });
});
