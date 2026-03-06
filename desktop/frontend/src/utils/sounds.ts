/**
 * Notification sound system for Accord.
 * Uses Web Audio API OscillatorNode to generate pleasant notification tones.
 */

let audioContext: AudioContext | null = null;

function getAudioContext(): AudioContext | null {
  if (!audioContext) {
    if (typeof AudioContext !== 'undefined' || typeof (window as any).webkitAudioContext !== 'undefined') {
      audioContext = new (AudioContext || (window as any).webkitAudioContext)();
    }
  }
  return audioContext;
}

/** Get the user's preferred volume (0–1) from localStorage, defaulting to 0.5. */
export function getVolume(): number {
  const stored = localStorage.getItem('accord_notification_volume');
  if (stored !== null) {
    const v = parseFloat(stored);
    if (!isNaN(v) && v >= 0 && v <= 1) return v;
  }
  return 0.5;
}

/** Set the notification volume (0–1). */
export function setVolume(v: number): void {
  localStorage.setItem('accord_notification_volume', String(Math.max(0, Math.min(1, v))));
}

/**
 * Play a short double-chirp (message received).
 * Two quick ascending tones — similar feel to Discord's message pop.
 */
export function playMessageSound(): void {
  const ctx = getAudioContext();
  if (!ctx) return;

  try {
    const vol = getVolume();
    const now = ctx.currentTime;

    // First chirp
    const osc1 = ctx.createOscillator();
    const gain1 = ctx.createGain();
    osc1.type = 'sine';
    osc1.frequency.setValueAtTime(880, now);
    osc1.frequency.exponentialRampToValueAtTime(1320, now + 0.06);
    gain1.gain.setValueAtTime(0, now);
    gain1.gain.linearRampToValueAtTime(vol * 0.15, now + 0.005);
    gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.1);
    osc1.connect(gain1);
    gain1.connect(ctx.destination);
    osc1.start(now);
    osc1.stop(now + 0.1);

    // Second chirp (slightly higher, 80ms later)
    const osc2 = ctx.createOscillator();
    const gain2 = ctx.createGain();
    osc2.type = 'sine';
    osc2.frequency.setValueAtTime(1100, now + 0.08);
    osc2.frequency.exponentialRampToValueAtTime(1540, now + 0.14);
    gain2.gain.setValueAtTime(0, now + 0.08);
    gain2.gain.linearRampToValueAtTime(vol * 0.15, now + 0.085);
    gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.18);
    osc2.connect(gain2);
    gain2.connect(ctx.destination);
    osc2.start(now + 0.08);
    osc2.stop(now + 0.18);
  } catch (error) {
    console.warn('Failed to play message sound:', error);
  }
}

/**
 * Play a mention notification — slightly louder, three-tone rising arpeggio.
 */
export function playMentionSound(): void {
  const ctx = getAudioContext();
  if (!ctx) return;

  try {
    const vol = getVolume();
    const now = ctx.currentTime;
    const notes = [660, 880, 1100];

    notes.forEach((freq, i) => {
      const offset = i * 0.1;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(freq, now + offset);
      gain.gain.setValueAtTime(0, now + offset);
      gain.gain.linearRampToValueAtTime(vol * 0.25, now + offset + 0.01);
      gain.gain.exponentialRampToValueAtTime(0.001, now + offset + 0.15);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now + offset);
      osc.stop(now + offset + 0.15);
    });
  } catch (error) {
    console.warn('Failed to play mention sound:', error);
  }
}

/**
 * Play a repeating ring tone for incoming calls.
 * Returns a stop function to cancel the ringing.
 */
export function playCallSound(): () => void {
  const ctx = getAudioContext();
  if (!ctx) return () => {};

  let stopped = false;
  const oscillators: OscillatorNode[] = [];
  const vol = getVolume();

  function ring() {
    if (stopped || !ctx) return;

    const now = ctx.currentTime;

    // Two-tone ring (like a phone): 440Hz + 480Hz for 0.4s, silence 0.2s, repeat
    for (const freq of [440, 480]) {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, now);
      gain.gain.setValueAtTime(vol * 0.12, now);
      gain.gain.setValueAtTime(vol * 0.12, now + 0.4);
      gain.gain.linearRampToValueAtTime(0, now + 0.42);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now);
      osc.stop(now + 0.42);
      oscillators.push(osc);
    }

    // Second burst after a short gap
    for (const freq of [440, 480]) {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, now + 0.6);
      gain.gain.setValueAtTime(vol * 0.12, now + 0.6);
      gain.gain.setValueAtTime(vol * 0.12, now + 1.0);
      gain.gain.linearRampToValueAtTime(0, now + 1.02);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now + 0.6);
      osc.stop(now + 1.02);
      oscillators.push(osc);
    }

    // Schedule next ring cycle (2s total period)
    setTimeout(() => ring(), 2000);
  }

  ring();

  return () => {
    stopped = true;
    oscillators.forEach(o => {
      try { o.stop(); } catch (_) { /* already stopped */ }
    });
  };
}
