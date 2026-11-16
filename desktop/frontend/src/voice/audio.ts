/**
 * Audio output for relay-mode voice: the shared playback AudioContext, a gain
 * node per remote participant and the master volume and deafen state.
 *
 * Only authenticated, decrypted audio reaches it (SPEC-03 REQ-3). The P2P
 * output path (an `<audio>` element per peer stream) was removed with the P2P
 * code (REQ-39, C215).
 */

export class AudioManager {
  private audioContext: AudioContext | null = null;
  private userGains: Map<string, { gainNode: GainNode; volume: number }> = new Map();
  private masterVolume = 1.0;
  private isDeafened = false;

  /** Get or create the shared AudioContext, resuming if suspended (autoplay policy). */
  async getContext(): Promise<AudioContext> {
    if (!this.audioContext || this.audioContext.state === 'closed') {
      this.audioContext = new AudioContext({ sampleRate: 48000 });
    }
    if (this.audioContext.state === 'suspended') {
      await this.audioContext.resume();
    }
    return this.audioContext;
  }

  /** Resume AudioContext — call this from a user gesture handler. */
  async resume(): Promise<void> {
    if (this.audioContext && this.audioContext.state === 'suspended') {
      await this.audioContext.resume();
    }
  }

  /** Set volume for a specific user (0.0 – 2.0). */
  setUserVolume(userId: string, volume: number): void {
    const entry = this.userGains.get(userId);
    if (entry) {
      entry.volume = volume;
      entry.gainNode.gain.value = this.isDeafened ? 0 : volume * this.masterVolume;
    }
  }

  /** Set master volume (0.0 – 1.0). */
  setMasterVolume(volume: number): void {
    this.masterVolume = Math.max(0, Math.min(1, volume));
    this.userGains.forEach(entry => {
      entry.gainNode.gain.value = this.isDeafened ? 0 : entry.volume * this.masterVolume;
    });
  }

  getMasterVolume(): number {
    return this.masterVolume;
  }

  /** Set deafened state — mutes all output when true. */
  setDeafened(deafened: boolean): void {
    this.isDeafened = deafened;
    this.userGains.forEach(entry => {
      entry.gainNode.gain.value = deafened ? 0 : entry.volume * this.masterVolume;
    });
  }

  /** List available audio output devices. */
  async getOutputDevices(): Promise<MediaDeviceInfo[]> {
    const devices = await navigator.mediaDevices.enumerateDevices();
    return devices.filter(d => d.kind === 'audiooutput');
  }

  /** Check if a gain node exists for a user. */
  hasUser(userId: string): boolean {
    return this.userGains.has(userId);
  }

  /** Create a gain node for relay-mode playback (no MediaStream needed). */
  createRelayUserGain(userId: string): GainNode | null {
    if (!this.audioContext || this.audioContext.state === 'closed') return null;
    const existing = this.userGains.get(userId);
    if (existing) return existing.gainNode;

    const gainNode = this.audioContext.createGain();
    gainNode.gain.value = this.isDeafened ? 0 : this.masterVolume;
    gainNode.connect(this.audioContext.destination);
    this.userGains.set(userId, { gainNode, volume: 1.0 });
    return gainNode;
  }

  /** Get the gain node for a user (used by relay playback). */
  getUserGainNode(userId: string): GainNode | null {
    return this.userGains.get(userId)?.gainNode ?? null;
  }

  /** Remove a user's audio output. */
  removeUser(userId: string): void {
    const entry = this.userGains.get(userId);
    if (entry) {
      entry.gainNode.disconnect();
      this.userGains.delete(userId);
    }
  }

  /** Clean up everything. */
  destroy(): void {
    this.userGains.forEach(entry => entry.gainNode.disconnect());
    this.userGains.clear();
    if (this.audioContext && this.audioContext.state !== 'closed') {
      this.audioContext.close();
    }
    this.audioContext = null;
  }
}
