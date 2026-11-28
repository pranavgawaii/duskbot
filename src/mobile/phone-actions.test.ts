import { describe, expect, it } from "vitest";

import { phoneActionFrom } from "./phone-actions";

const dusk = { dusk: { id: "n1", kind: "approval", botId: "b1", threadId: "t1", requestId: "req-1" }, aps: { category: "dusk.approval" } };

describe("phone actions", () => {
  it("approves or denies the exact ask, from the bot host's or the relay's block", () => {
    expect(phoneActionFrom({ actionId: "dusk.approve", data: dusk })).toEqual({ kind: "decide", target: { botId: "b1", threadId: "t1" }, requestId: "req-1", behavior: "allow" });
    expect(phoneActionFrom({ actionId: "dusk.deny", data: { omb: dusk.dusk } })).toMatchObject({ kind: "decide", behavior: "deny" });
  });

  it("takes a Live Activity's ids at the top level", () => {
    expect(phoneActionFrom({ actionId: "dusk.approve", data: { botId: "b1", threadId: "t1", requestId: "r2" } })).toMatchObject({ kind: "decide", requestId: "r2" });
  });

  it("keeps the source place from Android and iPhone taps", () => {
    const placed = { ...dusk.dusk, environmentId: "env-cloud" };
    expect(phoneActionFrom({ actionId: "tap", data: placed })).toMatchObject({ target: { environmentId: "env-cloud" } });
    expect(phoneActionFrom({ actionId: "tap", data: { dusk: placed } })).toMatchObject({ target: { environmentId: "env-cloud" } });
  });

  it("opens the chat when the ask id is missing, for Answer, and for a plain tap", () => {
    expect(phoneActionFrom({ actionId: "dusk.approve", data: { dusk: { botId: "b1", threadId: "t1" } } })).toEqual({ kind: "open", target: { botId: "b1", threadId: "t1" } });
    expect(phoneActionFrom({ actionId: "dusk.answer", data: dusk })?.kind).toBe("open");
    expect(phoneActionFrom({ actionId: "tap", data: { dusk: { groupId: "g1", threadId: "t2" } } })).toEqual({ kind: "open", target: { groupId: "g1", threadId: "t2" } });
  });

  it("replies with the typed text in a bot's own chat, never into a room", () => {
    expect(phoneActionFrom({ actionId: "dusk.reply", inputValue: "  thanks  ", data: dusk })).toEqual({ kind: "reply", target: { botId: "b1", threadId: "t1" }, text: "thanks" });
    expect(phoneActionFrom({ actionId: "dusk.reply", inputValue: "   ", data: dusk })?.kind).toBe("open");
    expect(phoneActionFrom({ actionId: "dusk.reply", inputValue: "hi", data: { dusk: { botId: "b1", groupId: "g1", threadId: "t1" } } })?.kind).toBe("open");
  });

  it("ignores data it cannot route", () => {
    expect(phoneActionFrom({ actionId: "dusk.approve", data: {} })).toBeNull();
    expect(phoneActionFrom({ actionId: "dusk.approve", data: { dusk: { botId: "b/1", threadId: "t1" } } })).toBeNull();
  });
});
