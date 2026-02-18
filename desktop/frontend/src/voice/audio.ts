/**
 * Audio management for voice chat.
 * Handles output device selection, per-user volume control, and AudioContext lifecycle.
 */

export class AudioManager {
  private audioContext: AudioContext | null = null;
  private outputDeviceId: string = 'default';
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

  /** Create a GainNode for a remote user's audio stream. */
  async createUserOutput(userId: string, stream: MediaStream): Promise<HTMLAudioElement> {
    const audio = new Audio();
    audio.srcObject = stream;
    audio.autoplay = true;

    // Set output device if supported
    if ('setSinkId' in audio && this.outputDeviceId !== 'default') {
      try {
        await (audio as any).setSinkId(this.outputDeviceId);
      } catch (e) {
        console.warn('Failed to set output device:', e);
      }
    }

    // Per-user volume via Web Audio
    const ctx = await this.getContext();
    const source = ctx.createMediaStreamSource(stream);
    const gainNode = ctx.createGain();
    const existing = this.userGains.get(userId);
    const volume = existing?.volume ?? 1.0;
    gainNode.gain.value = this.isDeafened ? 0 : volume * this.masterVolume;
    source.connect(gainNode);
    gainNode.connect(ctx.destination);

    this.userGains.set(userId, { gainNode, volume });

    return audio;
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

  /** Set output device by device ID. */
  async setOutputDevice(deviceId: string): Promise<void> {
    this.outputDeviceId = deviceId;
  }

  /** List available audio output devices. */
  async getOutputDevices(): Promise<MediaDeviceInfo[]> {
    const devices = await navigator.mediaDevices.enumerateDevices();
    return devices.filter(d => d.kind === 'audiooutput');
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
