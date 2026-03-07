// Notification system for Accord

import { Message } from './types';
import { playMessageSound, playMentionSound } from './utils/sounds';

export interface NotificationPreferences {
  enabled: boolean;
  mode: 'all' | 'mentions' | 'dms' | 'none';
  sounds: boolean;
  flashTaskbar: boolean;
  showPreview: boolean;
}

export interface UnreadState {
  lastReadMessageId: string | null;
  count: number;
  mentions: number;
  lastMessageTimestamp: number;
}

export interface ChannelUnreads {
  [channelId: string]: UnreadState;
}

export interface NodeUnreads {
  [nodeId: string]: {
    totalUnreads: number;
    totalMentions: number;
    channels: ChannelUnreads;
  };
}

// ---- Mute Manager (localStorage-backed, singleton) ----

export interface MuteEntry {
  expiresAt: number | null;
}

export type MuteMap = Record<string, MuteEntry>;

export interface MuteDuration {
  label: string;
  minutes: number | null;
}

export const MUTE_DURATIONS: MuteDuration[] = [
  { label: '15 Minutes', minutes: 15 },
  { label: '1 Hour', minutes: 60 },
  { label: '8 Hours', minutes: 480 },
  { label: '24 Hours', minutes: 1440 },
  { label: 'Until I turn it back on', minutes: null },
];

function loadMuteMap(key: string): MuteMap {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function saveMuteMap(key: string, map: MuteMap): void {
  localStorage.setItem(key, JSON.stringify(map));
}

function isEntryActive(entry: MuteEntry | undefined): boolean {
  if (!entry) return false;
  if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) return false;
  return true;
}

const MUTED_CHANNELS_KEY = 'accord_muted_channels';
const MUTED_NODES_KEY = 'accord_muted_nodes';

class MuteManager {
  private channels: MuteMap;
  private nodes: MuteMap;

  constructor() {
    this.channels = loadMuteMap(MUTED_CHANNELS_KEY);
    this.nodes = loadMuteMap(MUTED_NODES_KEY);
  }

  isChannelMuted(channelId: string): boolean {
    return isEntryActive(this.channels[channelId]);
  }

  isNodeMuted(nodeId: string): boolean {
    return isEntryActive(this.nodes[nodeId]);
  }

  isEffectivelyMuted(channelId: string, nodeId: string | null): boolean {
    if (this.isChannelMuted(channelId)) return true;
    if (nodeId && this.isNodeMuted(nodeId)) return true;
    return false;
  }

  muteChannel(channelId: string, durationMinutes: number | null): void {
    this.channels[channelId] = {
      expiresAt: durationMinutes != null ? Date.now() + durationMinutes * 60_000 : null,
    };
    saveMuteMap(MUTED_CHANNELS_KEY, this.channels);
  }

  unmuteChannel(channelId: string): void {
    delete this.channels[channelId];
    saveMuteMap(MUTED_CHANNELS_KEY, this.channels);
  }

  muteNode(nodeId: string, durationMinutes: number | null): void {
    this.nodes[nodeId] = {
      expiresAt: durationMinutes != null ? Date.now() + durationMinutes * 60_000 : null,
    };
    saveMuteMap(MUTED_NODES_KEY, this.nodes);
  }

  unmuteNode(nodeId: string): void {
    delete this.nodes[nodeId];
    saveMuteMap(MUTED_NODES_KEY, this.nodes);
  }
}

export const muteManager = new MuteManager();

// ---- Notification Manager ----

export class NotificationManager {
  private preferences: NotificationPreferences;
  private unreads: NodeUnreads = {};
  public currentUsername = '';
  private windowFocused = true;
  private activeChannelId: string | null = null;
  public doNotDisturb = false;
  private titleFlashInterval: ReturnType<typeof setInterval> | null = null;
  private originalTitle = 'Accord';

  constructor() {
    this.preferences = this.loadPreferences();
    this.setupWindowFocusHandlers();
    this.requestNotificationPermission();
  }

  private loadPreferences(): NotificationPreferences {
    const stored = localStorage.getItem('accord_notification_preferences');
    if (stored) {
      return JSON.parse(stored);
    }
    return {
      enabled: true,
      mode: 'all',
      sounds: true,
      flashTaskbar: true,
      showPreview: true,
    };
  }

  private savePreferences(): void {
    localStorage.setItem('accord_notification_preferences', JSON.stringify(this.preferences));
  }

  private loadUnreads(): NodeUnreads {
    const stored = localStorage.getItem('accord_unreads');
    if (stored) {
      return JSON.parse(stored);
    }
    return {};
  }

  private saveUnreads(): void {
    localStorage.setItem('accord_unreads', JSON.stringify(this.unreads));
  }

  private setupWindowFocusHandlers(): void {
    window.addEventListener('focus', () => {
      this.windowFocused = true;
      this.clearTitleBadge();
    });

    window.addEventListener('blur', () => {
      this.windowFocused = false;
    });

    // Check initial focus state
    this.windowFocused = document.hasFocus();
  }

  private async requestNotificationPermission(): Promise<void> {
    if ('Notification' in window && Notification.permission === 'default') {
      await Notification.requestPermission();
    }
  }

  public setActiveChannel(channelId: string | null): void {
    this.activeChannelId = channelId;
  }

  public setCurrentUsername(username: string): void {
    this.currentUsername = username;
    this.unreads = this.loadUnreads();
  }

  public getPreferences(): NotificationPreferences {
    return { ...this.preferences };
  }

  public updatePreferences(preferences: Partial<NotificationPreferences>): void {
    this.preferences = { ...this.preferences, ...preferences };
    this.savePreferences();
  }

  public getNodeUnreads(nodeId: string): { totalUnreads: number; totalMentions: number } {
    const nodeData = this.unreads[nodeId];
    if (!nodeData) {
      return { totalUnreads: 0, totalMentions: 0 };
    }
    return {
      totalUnreads: nodeData.totalUnreads,
      totalMentions: nodeData.totalMentions
    };
  }

  public getChannelUnreads(nodeId: string, channelId: string): UnreadState {
    const nodeData = this.unreads[nodeId];
    if (!nodeData || !nodeData.channels[channelId]) {
      return {
        lastReadMessageId: null,
        count: 0,
        mentions: 0,
        lastMessageTimestamp: 0
      };
    }
    return nodeData.channels[channelId];
  }

  public markChannelAsRead(nodeId: string, channelId: string, lastMessageId?: string): void {
    if (!this.unreads[nodeId]) {
      this.unreads[nodeId] = {
        totalUnreads: 0,
        totalMentions: 0,
        channels: {}
      };
    }

    if (!this.unreads[nodeId].channels[channelId]) {
      this.unreads[nodeId].channels[channelId] = {
        lastReadMessageId: null,
        count: 0,
        mentions: 0,
        lastMessageTimestamp: 0
      };
    }

    const channel = this.unreads[nodeId].channels[channelId];
    
    // Subtract current counts from node totals
    this.unreads[nodeId].totalUnreads -= channel.count;
    this.unreads[nodeId].totalMentions -= channel.mentions;

    // Reset channel counts
    channel.count = 0;
    channel.mentions = 0;
    
    if (lastMessageId) {
      channel.lastReadMessageId = lastMessageId;
      channel.lastMessageTimestamp = Date.now();
    }

    // Ensure node totals don't go negative
    this.unreads[nodeId].totalUnreads = Math.max(0, this.unreads[nodeId].totalUnreads);
    this.unreads[nodeId].totalMentions = Math.max(0, this.unreads[nodeId].totalMentions);

    this.saveUnreads();
  }

  public addMessage(nodeId: string, channelId: string, message: Message, isDm: boolean = false): void {
    // Don't count our own messages as unread
    if (message.author === this.currentUsername) {
      return;
    }

    if (!this.unreads[nodeId]) {
      this.unreads[nodeId] = {
        totalUnreads: 0,
        totalMentions: 0,
        channels: {}
      };
    }

    if (!this.unreads[nodeId].channels[channelId]) {
      this.unreads[nodeId].channels[channelId] = {
        lastReadMessageId: null,
        count: 0,
        mentions: 0,
        lastMessageTimestamp: 0
      };
    }

    const channel = this.unreads[nodeId].channels[channelId];
    
    // Only count as unread if this message is newer than our last read message
    const isNewer = !channel.lastReadMessageId || 
      message.timestamp > channel.lastMessageTimestamp;

    if (isNewer) {
      const isMention = this.containsMention(message.content);
      
      channel.count++;
      this.unreads[nodeId].totalUnreads++;

      if (isMention) {
        channel.mentions++;
        this.unreads[nodeId].totalMentions++;
      }

      channel.lastMessageTimestamp = Math.max(channel.lastMessageTimestamp, message.timestamp);

      this.saveUnreads();

      // Handle desktop notification and sound
      this.handleMessageNotification(message, channelId, isMention, isDm);
    }
  }

  public containsMention(content: string): boolean {
    if (!this.currentUsername) return false;
    
    const lowerContent = content.toLowerCase();
    const lowerUsername = this.currentUsername.toLowerCase();
    
    // Check for @username or @everyone
    return lowerContent.includes(`@${lowerUsername}`) || lowerContent.includes('@everyone');
  }

  public highlightMentions(content: string): string {
    if (!this.currentUsername) return content;
    
    // SECURITY: Sanitize content first to prevent XSS before inserting HTML
    const DOMPurify = (window as any).DOMPurify;
    let sanitized = DOMPurify ? DOMPurify.sanitize(content, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }) : this.escapeHtml(content);
    
    let highlighted = sanitized;
    const username = this.escapeRegExp(this.currentUsername);
    
    // Highlight @username (case insensitive)
    const usernameRegex = new RegExp(`(@${username})`, 'gi');
    highlighted = highlighted.replace(usernameRegex, '<span class="mention">$1</span>');
    
    // Highlight @everyone
    const everyoneRegex = new RegExp(`(@everyone)`, 'gi');
    highlighted = highlighted.replace(everyoneRegex, '<span class="mention mention-everyone">$1</span>');
    
    return highlighted;
  }

  private escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  private escapeRegExp(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  private handleMessageNotification(message: Message, channelId: string, isMention: boolean, isDm: boolean = false): void {
    // Don't notify for the channel the user is currently viewing, or if DND
    if (this.doNotDisturb || !this.preferences.enabled || (this.windowFocused && this.activeChannelId === channelId)) {
      return;
    }

    // Don't notify for muted channels/nodes (check all node entries for this channel)
    for (const nodeId of Object.keys(this.unreads)) {
      if (this.unreads[nodeId]?.channels[channelId] && muteManager.isEffectivelyMuted(channelId, nodeId)) {
        return;
      }
    }

    const shouldNotify = 
      this.preferences.mode === 'all' || 
      (this.preferences.mode === 'mentions' && isMention) ||
      (this.preferences.mode === 'dms' && (isDm || isMention));

    if (shouldNotify) {
      this.showDesktopNotification(message, channelId, isMention, isDm);
      
      // Play appropriate sound
      if (this.preferences.sounds) {
        if (isMention) {
          playMentionSound();
        } else {
          playMessageSound();
        }
      }

      // Update title badge when window is not focused
      if (!this.windowFocused && this.preferences.flashTaskbar) {
        this.updateTitleBadge();
      }
    }
  }

  private showDesktopNotification(message: Message, channelId: string, isMention: boolean, isDm: boolean = false): void {
    if ('Notification' in window && Notification.permission === 'granted') {
      const title = isMention ? `${message.author} mentioned you` : isDm ? `DM from ${message.author}` : `${message.author}`;
      const body = this.preferences.showPreview
        ? (message.content.length > 100 ? message.content.substring(0, 100) + '...' : message.content)
        : 'New message received';

      const notification = new Notification(title, {
        body,
        icon: '/favicon.ico', // Assuming there's a favicon
        badge: '/favicon.ico',
        tag: channelId // Group notifications by channel
      });

      // Auto-close after 5 seconds
      setTimeout(() => {
        notification.close();
      }, 5000);

      notification.onclick = () => {
        window.focus();
        notification.close();
      };
    }
  }

  /** Compute total unreads across all nodes and update the document title. */
  private updateTitleBadge(): void {
    let total = 0;
    for (const nodeId of Object.keys(this.unreads)) {
      total += this.unreads[nodeId].totalUnreads;
    }

    if (total <= 0) {
      this.clearTitleBadge();
      return;
    }

    // Start flashing between "(N) Accord" and "(N) channel"
    if (this.titleFlashInterval) clearInterval(this.titleFlashInterval);

    let showChannel = false;
    const channelName = this.activeChannelId ?? '';

    const update = () => {
      if (showChannel && channelName) {
        document.title = `(${total}) ${channelName}`;
      } else {
        document.title = `(${total}) ${this.originalTitle}`;
      }
      showChannel = !showChannel;
    };

    update();
    this.titleFlashInterval = setInterval(update, 1500);
  }

  private clearTitleBadge(): void {
    if (this.titleFlashInterval) {
      clearInterval(this.titleFlashInterval);
      this.titleFlashInterval = null;
    }
    document.title = this.originalTitle;
  }

  /** Play a test notification sound (for settings UI). */
  public playTestSound(): void {
    playMessageSound();
  }

  public getAllUnreads(): NodeUnreads {
    return { ...this.unreads };
  }

  public clearAllUnreads(): void {
    this.unreads = {};
    this.saveUnreads();
  }

  public clearNodeUnreads(nodeId: string): void {
    delete this.unreads[nodeId];
    this.saveUnreads();
  }

  /** Mark all channels in a node as read without deleting the node entry */
  public markAllNodeChannelsAsRead(nodeId: string): void {
    const nodeData = this.unreads[nodeId];
    if (!nodeData) return;
    for (const channelId of Object.keys(nodeData.channels)) {
      const ch = nodeData.channels[channelId];
      ch.count = 0;
      ch.mentions = 0;
    }
    nodeData.totalUnreads = 0;
    nodeData.totalMentions = 0;
    this.saveUnreads();
  }

  /** Check if a channel is muted (directly or via node mute) */
  public isChannelMuted(nodeId: string, channelId: string): boolean {
    return muteManager.isEffectivelyMuted(channelId, nodeId);
  }

  /** Check if a node is muted */
  public isNodeMuted(nodeId: string): boolean {
    return muteManager.isNodeMuted(nodeId);
  }
}

// Global notification manager instance
export const notificationManager = new NotificationManager();