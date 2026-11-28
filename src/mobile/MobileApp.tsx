import { useProductScreen } from "@/lib/product-analytics-app";
import { PhoneUpdatedLine } from "./PhoneUpdatedLine";
import { useCallback, useContext, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { MotionConfig } from "motion/react";
import { openBot, openBotThread, openRoomThread, rereadWithoutStream, StoreProvider, useStore } from "@/state/store";
import { useTeamChats } from "@/state/team-chats";
import { useWarmChatImages } from "@/components/use-warm-chat-images";
import { ThreadRefsProvider } from "@/components/ThreadRefs";
import { DesktopCapabilitiesProvider } from "@/components/DesktopCapabilities";
import { LiveCallHost } from "@/components/LiveCallHost";
import { liveCallEnabled } from "@/lib/feature-flags";
import { ConnectAppsHost, connectAppsPageFor, openConnectApps } from "@/components/connect-apps";
import { closeConnectApps, connectAppsState } from "@/components/connect-apps/open";
import { openChatLink } from "@/components/ThreadRefs";
import { parseBotRefUrl, parseThreadRefUrl } from "@/lib/thread-refs"; import { completeSlackOAuth } from "@/lib/slack-oauth-link"; import { parseSlackOAuthLink } from "../../shared/slack";
import { effectiveLanguage, useLanguageChoice, usePageLanguage } from "@/lib/language-preference";
import { parseMobileOpenLink, type MobileOpenTarget } from "../../shared/mobile-link";
import { setAppAway, setChatCovered } from "@/lib/chat-in-front";
import { readSkinChoice, subscribeSkin, THEME_SKINS } from "@/lib/skins";
import { AiConsentProvider, AiConsentSheet } from "./consent/AiConsent";
import { installAiReport } from "@/lib/ai-report";
import { registerPushForConnection } from "./connection/push";
import { ActiveConnection } from "./connection/active"; import { useConnections } from "./connection/connections";
import { useExternalPages } from "./external-pages";
import { setPresenceThread } from "./connection/presence";
import { useNotificationAvatars } from "./notification-avatars";
import { useSeenNotifications } from "./connection/seen-notifications";
import { visibleNotificationThread } from "@/state/thread-navigation";
import { supportMail } from "./legal";
import { NavStack } from "./NavStack";
import { ChatScreen } from "./ChatScreen";
import { placeForTarget, readOpenChat, rememberOpenChat, rereadDue, restoredChat } from "./open-chat-restore";
import { HomeScreen, releasePressed } from "./HomeScreen";
import { panelOpenAction, SheetHost } from "./SheetHost";
import { backLayerCount, closeTopSheet, Sheet, subscribeBackLayers } from "./Sheet";
import { t } from "@/lib/i18n";
import { systemDialogs } from "@/lib/system-dialog";
import { dismissKeyboard, useKeyboardDismiss, useKeyboardSync } from "./keyboard";
import { useNativeGlass } from "./native-glass";
import { useNativeHomeGlass } from "./native-home-glass";
import { haptic } from "./haptics";
import { useChatHaptics } from "./use-chat-haptics";
import { usePhoneActions } from "./use-phone-actions";
import { useShortcuts } from "./shortcuts";
import { useTurnActivities } from "./use-turn-activities";
import { useOutbox } from "./outbox";
import { installPress } from "./press";
import { MessageHold } from "./MessageHold";
import { ViewerHost } from "./viewers/ViewerHost";
import { opensBrowserTakeoverDirectly, PhoneBrowserTakeover } from "./PhoneBrowserTakeover";
import { usePlatform } from "./platform";
import type { MobileSheet } from "./sheets";
import { PanelDetailsTab } from "@/components/bot-panel/PanelShell";
import { loadLimits } from "@/lib/limit-resets";

const SHEET_WARM_MS = 600;
/** While the live stream is down the open chat is read again this often, so a reply still shows without a reopen. */
export const STREAM_DOWN_READ_MS = 4000;

function Shell() {
  const platform = usePlatform();
  const { state, dispatch } = useStore();
  const rootRef = useRef<HTMLDivElement>(null);
  const [chatId, setChatId] = useState<string | null>(null);
  const place = useContext(ActiveConnection);
  const places = useConnections();
  const saved = useRef(places);
  saved.current = places;
  const restoring = useRef(readOpenChat(place));
  useEffect(() => { if (!restoring.current) rememberOpenChat(chatId, place); }, [chatId, place]);
  const [sheet, setSheet] = useState<MobileSheet | null>(null);
  const [sheetOpen, setSheetOpen] = useState(false);
  useProductScreen(sheetOpen && sheet ? `/${sheet.kind}` : chatId ? "/chats/:id" : "/", chatId);
  useTeamChats(state.config);
  useWarmChatImages(state.bots);
  useNotificationAvatars(platform, state.bots);
  usePageLanguage(effectiveLanguage(useLanguageChoice(), state.config?.language));
  useKeyboardSync(platform, rootRef);
  useExternalPages(platform);
  useKeyboardDismiss(platform, rootRef);
  const startTurnActivity = useTurnActivities(platform, state);
  const shownChat = useRef(chatId);
  shownChat.current = chatId;
  // notifications are asked for when they mean something: once a message is on its way and its reply will follow
  useChatHaptics(state, chatId, useCallback(() => {
    if (platform.native) void registerPushForConnection(platform, { prompt: true });
    const bot = latest.current.bots.find((one) => one.id === shownChat.current);
    if (bot) startTurnActivity(bot);
  }, [platform, startTurnActivity]));
  useOutbox();
  useEffect(() => { const root = rootRef.current; return root ? installPress(root) : undefined; }, []);
  // a bot's reply someone finds harmful or wrong goes to a person at dusk bot, with the reply in the mail they send
  useEffect(() => installAiReport(({ text, messageId }) => {
    void platform.openExternal(supportMail(t("mobile.report.subject"), t("mobile.report.body", { text: text.slice(0, 1500), id: messageId })));
  }), [platform]);

  const latest = useRef(state);
  latest.current = state;

  // the status bar's clock and battery follow the look, when it is changed in Settings and when the system's changes
  const skin = useSyncExternalStore(subscribeSkin, readSkinChoice, () => "system");
  useEffect(() => {
    // an open sheet steps the page back onto a dark ground, so the clock turns light over it
    // (the system's sheet dims the page itself and the status bar follows it)
    const apply = () => platform.setStatusBar?.((sheetOpen && !platform.chrome) || document.documentElement.dataset.skin === THEME_SKINS.dark ? "light" : "dark");
    apply();
    const system = window.matchMedia?.("(prefers-color-scheme: dark)");
    const later = () => setTimeout(apply, 0);
    system?.addEventListener("change", later);
    return () => system?.removeEventListener("change", later);
  }, [platform, skin, sheetOpen]);

  useEffect(() => platform.setAppearance?.(skin === THEME_SKINS.dark ? "dark" : skin === THEME_SKINS.light ? "light" : "system"), [platform, skin]);

  // with the list in front, the chat last opened is not being read: its replies stay unread and still notify
  useEffect(() => { setChatCovered(chatId === null); return () => setChatCovered(false); }, [chatId]);
  useEffect(() => {
    const stops = [platform.onPause?.(() => setAppAway(true)), platform.onResume?.(() => setAppAway(false))];
    return () => { for (const stop of stops) stop?.(); setAppAway(false); };
  }, [platform]);
  // the conversation on screen never pushes or shows a banner here; pushes already seen leave Notification Center
  const viewingThread = chatId ? visibleNotificationThread(state) : null;
  useEffect(() => { setPresenceThread(viewingThread); return () => setPresenceThread(null); }, [viewingThread]);
  useSeenNotifications(platform, state.notifications, viewingThread);

  const openChat = useCallback((id: string) => {
    const current = latest.current;
    const bot = current.bots.find((b) => b.id === id);
    if (bot) openBot(dispatch, bot);
    else dispatch({ type: "select", id });
    setChatId(id);
  }, [dispatch]);
  const tapChat = useCallback((id: string) => { haptic("openChat"); openChat(id); }, [openChat]);
  const backToList = useCallback(() => { haptic("back"); setChatId(null); }, []);

  // a reload comes back to the chat that was open, opened as a tap would once the snapshot shows it is still here
  useEffect(() => {
    const id = restoring.current;
    if (!id) return;
    const restored = restoredChat(id, latest.current);
    if (restored === "wait") return;
    restoring.current = null;
    if (restored && shownChat.current === null) openChat(restored);
    else rememberOpenChat(shownChat.current, place);
  }, [state.hydrated, state.bots, state.groups, openChat, place]);

  const openSheet = useCallback((next: MobileSheet) => {
    const panel = panelOpenAction(next);
    if (panel) dispatch(panel);
    setSheet(next);
    setSheetOpen(true);
  }, [dispatch]);
  const closeSheet = useCallback(() => setSheetOpen(false), []);

  const [browserTakeover, setBrowserTakeover] = useState<{
    botId: string;
    signIn: { url: string; site: string; nonce: number } | null;
  } | null>(null);
  const openBrowserTakeover = useCallback((botId: string, signIn: { url: string; site: string; nonce: number } | null = null) => {
    if (rootRef.current) dismissKeyboard(platform, rootRef.current);
    setBrowserTakeover({ botId, signIn });
  }, [platform]);
  const lastBrowserSignIn = useRef(0);
  useEffect(() => {
    const focus = state.signInFocus;
    if (!focus || focus.consumed || focus.place !== "browser") return;
    if (lastBrowserSignIn.current === focus.requestId) return;
    lastBrowserSignIn.current = focus.requestId;
    openBrowserTakeover(focus.botId, { url: focus.url, site: focus.site, nonce: focus.requestId });
    dispatch({ type: "signInFocusConsumed", requestId: focus.requestId });
    dispatch({ type: "toggleSettings", open: false });
  }, [state.signInFocus, dispatch, openBrowserTakeover]);

  const lastComputerRequest = useRef(state.computerTabRequest);
  useEffect(() => {
    if (state.computerTabRequest === lastComputerRequest.current) return;
    lastComputerRequest.current = state.computerTabRequest;
    if (!state.settingsOpen) return;
    if (state.signInFocus?.place === "browser" && (!state.signInFocus.consumed || lastBrowserSignIn.current === state.signInFocus.requestId)) return;
    const targetId = (state.signInFocus && !state.signInFocus.consumed ? state.signInFocus.botId : null)
      ?? state.selectedId
      ?? shownChat.current;
    if (!targetId) return;
    setSheet((current) => (current?.kind === "computer" && current.botId === targetId ? current : { kind: "computer", botId: targetId }));
    setSheetOpen(true);
  }, [state.computerTabRequest, state.settingsOpen, state.selectedId, state.signInFocus]);

  // a shared card that opens the computer app's settings (connect an AI, add a key) has nothing to open on a phone: it
  // says where that lives instead of doing nothing
  const [desktopOnly, setDesktopOnly] = useState(false);
  useEffect(() => {
    if (!state.appSettingsOpen) return;
    dispatch({ type: "toggleAppSettings", open: false });
    // voice input is set up on the phone itself: its own settings sheet has the page
    if (state.appSettingsSection === "voice") openSheet({ kind: "settings", page: "voice" });
    else {
      const dialogs = systemDialogs();
      if (dialogs) {
        void dialogs.alert({
          title: t("mobile.desktopOnly.title"),
          message: t("mobile.desktopOnly.body"),
          confirmLabel: t("mobile.desktopOnly.done"),
          singleAction: true,
        });
      } else {
        setDesktopOnly(true);
      }
    }
  }, [state.appSettingsOpen, state.appSettingsSection, dispatch, openSheet]);

  useEffect(() => {
    if (!state.pluginsOpen) return;
    openConnectApps(connectAppsPageFor(state.pluginsSurface));
    dispatch({ type: "togglePlugins", open: false });
  }, [state.pluginsOpen, state.pluginsSurface, dispatch]);

  const wasSheetOpen = useRef(sheetOpen);
  useEffect(() => {
    if (wasSheetOpen.current && !sheetOpen && connectAppsState().open) closeConnectApps();
    wasSheetOpen.current = sheetOpen;
  }, [sheetOpen]);

  const openTarget = useCallback((target: MobileOpenTarget) => {
    const id = target.botId ?? target.groupId;
    const elsewhere = id ? placeForTarget(target.environmentId, saved.current.connections, place) : null;
    if (id && elsewhere) { rememberOpenChat(id, elsewhere); void saved.current.switchTo(elsewhere); return; }
    if (id) {
      const bot = latest.current.bots.find((b) => b.id === id);
      if (bot && target.threadId) { openBotThread(dispatch, bot, target.threadId, true); setChatId(bot.id); }
      else if (target.groupId && target.threadId) { openRoomThread(dispatch, { groupId: target.groupId, threadId: target.threadId }, latest.current.groups); setChatId(target.groupId); }
      else openChat(id);
      if (target.messageId && target.threadId) dispatch({ type: "focusMessage", threadId: target.threadId, messageId: target.messageId });
    }
    if (target.view === "computer" && target.botId) {
      const targetBot = latest.current.bots.find((b) => b.id === target.botId);
      if (targetBot && opensBrowserTakeoverDirectly(targetBot, latest.current)) openBrowserTakeover(targetBot.id);
      else openSheet({ kind: "computer", botId: target.botId });
    }
    else if (target.view === "profile" && id) openSheet({ kind: "profile", id });
    else if (target.view === "settings") openSheet({ kind: "settings" });
    else if (target.view === "notifications") openSheet({ kind: "notifications" });
    else if (target.view === "routines") openSheet({ kind: "routines", botId: target.botId });
  }, [dispatch, openBrowserTakeover, openChat, openSheet, place]);

  useEffect(() => platform.onAppUrl?.((url) => {
    if (parseSlackOAuthLink(url)) { void completeSlackOAuth(url); return true; }
    const target = parseMobileOpenLink(url);
    if (target) { openTarget(target); return true; }
    // the desktop's own chat links open the same chat here
    const bot = parseBotRefUrl(url);
    const thread = parseThreadRefUrl(url);
    if (!bot && !thread) return false;
    if (openChatLink(dispatch, url, latest.current, true)) {
      const owner = bot?.botId ?? thread?.botId ?? latest.current.groups.find((g) => g.threadId === thread?.threadId || g.tasks?.some((task) => task.threadId === thread?.threadId))?.id
        ?? latest.current.bots.find((b) => b.threadId === thread?.threadId || b.tasks?.some((task) => task.threadId === thread?.threadId))?.id;
      if (owner) setChatId(owner);
    }
    return true;
  }), [platform, openTarget, dispatch]);
  useEffect(() => platform.onNotificationOpen?.(openTarget), [platform, openTarget]);
  usePhoneActions(platform, state, dispatch, openTarget, { place, connections: places.connections, loaded: places.loaded, switchTo: places.switchTo });
  useShortcuts({ platform, state, dispatch, place, connections: places.connections, loaded: places.loaded, switchTo: places.switchTo, openChat });

  // registered once, so a layer that opens later (a full screen computer, adding a place) is asked before it
  const openChatId = useRef(chatId);
  openChatId.current = chatId;
  const back = useRef(() => {
    if (closeTopSheet()) return true;
    if (openChatId.current) { setChatId(null); return true; }
    return false;
  });
  useEffect(() => platform.onBack?.(back.current), [platform]);
  const backLayers = useSyncExternalStore(subscribeBackLayers, backLayerCount, () => 0);
  useEffect(() => platform.backAtRoot?.(back.current, !chatId && backLayers === 0), [platform, chatId, backLayers]);
  // with a chat open and nothing over it, Android's back gesture slides the chat itself (NavStack)
  useEffect(() => {
    const listener = back.current;
    platform.backGesture?.(listener, Boolean(chatId) && backLayers === 0);
    return () => platform.backGesture?.(listener, false);
  }, [platform, chatId, backLayers]);

  // a resumed app reads the chat on screen, as a refocused desktop window does
  useEffect(() => platform.onResume?.(() => { if (chatId) dispatch({ type: "select", id: chatId }); }), [platform, chatId, dispatch]);
  const streamDown = state.hydrated === true && state.connected === false;
  useEffect(() => {
    if (!chatId || !streamDown) return;
    const read = setInterval(() => { if (rereadDue(latest.current, document.hidden)) rereadWithoutStream(); }, STREAM_DOWN_READ_MS);
    return () => clearInterval(read);
  }, [chatId, streamDown]);

  // the bot's sheet is a tap away from an open chat: its first tab's code and the usage it shows load once the chat has
  // landed, so the tap only has to draw it
  useEffect(() => {
    if (!chatId) return;
    const warm = setTimeout(() => { void PanelDetailsTab.preload().catch(() => {}); void loadLimits(); }, SHEET_WARM_MS);
    return () => clearTimeout(warm);
  }, [chatId]);

  const group = chatId ? state.groups.find((g) => g.id === chatId) : undefined;
  const bot = chatId && !group ? state.bots.find((b) => b.id === chatId) : undefined;
  const members = useMemo(() => group ? state.bots.filter((b) => group.memberIds.includes(b.id)) : [], [group, state.bots]);
  useEffect(() => { if (chatId && state.hydrated && !group && !bot) setChatId(null); }, [chatId, state.hydrated, group, bot]);

  // the native chrome stays with a chat until its page has slid away, so the page never draws its own on the way out
  const [glassHeld, setGlassHeld] = useState(false);
  if ((bot || group) && !glassHeld) setGlassHeld(true);
  const pageSettled = useCallback((shown: boolean) => { if (!shown) setGlassHeld(false); releasePressed(); }, []);
  const slideGlass = useNativeGlass(platform, rootRef, Boolean(bot || group) || glassHeld);
  useNativeHomeGlass(platform, rootRef);
  const leaveChat = useCallback(() => { if (rootRef.current) dismissKeyboard(platform, rootRef.current); }, [platform]);

  const takeoverBot = browserTakeover ? state.bots.find((b) => b.id === browserTakeover.botId) : undefined;
  useEffect(() => {
    if (browserTakeover && state.hydrated && !takeoverBot) setBrowserTakeover(null);
  }, [browserTakeover, state.hydrated, takeoverBot]);

  const page = bot || group ? (
    <ChatScreen
      bot={bot}
      group={group}
      members={members}
      onBack={backToList}
      onProfile={() => openSheet({ kind: "profile", id: chatId! })}
      onComputer={() => {
        if (bot && opensBrowserTakeoverDirectly(bot, state)) openBrowserTakeover(bot.id);
        else openSheet({ kind: "computer", botId: chatId! });
      }}
    />
  ) : null;

  return (
    <div ref={rootRef} className="dusk-mobile relative">
      <NavStack
        base={<HomeScreen onOpenChat={tapChat} onOpenSheet={openSheet} />}
        page={page}
        pageKey={page ? chatId : null}
        onBack={backToList}
        onSettled={pageSettled}
        onSlide={slideGlass}
        onLeave={leaveChat}
      />
      <SheetHost sheet={sheet} open={sheetOpen} onClose={closeSheet} onOpenSheet={openSheet} onOpenChat={(id) => { closeSheet(); tapChat(id); }} />
      <ConnectAppsHost />
      <MessageHold rootRef={rootRef} />
      <ViewerHost rootRef={rootRef} />
      {browserTakeover && takeoverBot && (
        <PhoneBrowserTakeover bot={takeoverBot} signIn={browserTakeover.signIn} onClose={() => setBrowserTakeover(null)} />
      )}
      <AiConsentSheet />
      <PhoneUpdatedLine />
      <Sheet open={desktopOnly} onClose={() => setDesktopOnly(false)} title={t("mobile.desktopOnly.title")}>
        <div className="px-5 pb-[calc(var(--m-safe-bottom)+16px)]">
          <p className="text-[15px] leading-6 text-ink-secondary">{t("mobile.desktopOnly.body")}</p>
          <button type="button" onClick={() => setDesktopOnly(false)} className="mobile-press mt-5 flex min-h-12 w-full items-center justify-center rounded-full bg-ink text-[16px] font-semibold text-app">{t("mobile.desktopOnly.done")}</button>
        </div>
      </Sheet>
    </div>
  );
}

export function MobileApp() {
  return (
    <MotionConfig reducedMotion="user">
      <DesktopCapabilitiesProvider>
        <StoreProvider>
          <ThreadRefsProvider>
            <AiConsentProvider><Shell /></AiConsentProvider>
          </ThreadRefsProvider>
          {liveCallEnabled() && <LiveCallHost />}
        </StoreProvider>
      </DesktopCapabilitiesProvider>
    </MotionConfig>
  );
}
