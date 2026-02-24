import React, { useState, useEffect, useCallback, useRef } from 'react';
import clsx from 'clsx';
import { notificationManager, NotificationPreferences } from './notifications';
import { api } from './api';
import { loadKeyWithPassword, setActiveIdentity } from './crypto';
import { CLIENT_BUILD_HASH, ACCORD_VERSION, shortHash, verifyBuildHash, getCombinedTrust, getTrustIndicator, KnownBuild } from './buildHash';
import { UpdateSection } from './UpdateChecker';
import { themes, applyTheme, getSavedTheme } from './themes';
import QRCode from 'qrcode';
import jsQR from 'jsqr';
import s from './Settings.module.css';
import btnStyles from './components/uikit/button/Button.module.css';

// Types for settings
interface AccountSettings {
  displayName: string;
  bio: string;
  status: 'online' | 'away' | 'busy' | 'invisible';
}

interface AppearanceSettings {
  theme: string;
  fontSize: number; // px value for slider
  messageDensity: 'compact' | 'comfortable' | 'cozy';
}

interface VoiceSettings {
  inputDevice: string;
  outputDevice: string;
  inputVolume: number;
  outputVolume: number;
  vadSensitivity: number;
  echoCancellation: boolean;
  noiseSuppression: boolean;
  autoGainControl: boolean;
}

interface PrivacySettings {
  readReceipts: boolean;
  typingIndicators: boolean;
  blockedUsers: string[];
}

interface ServerInfo {
  version: string;
  buildHash: string;
  connectedSince: number | null;
  relayAddress: string;
  isConnected: boolean;
}

interface SettingsProps {
  isOpen: boolean;
  onClose: () => void;
  onShowShortcuts?: () => void;
  knownHashes?: KnownBuild[] | null;
  currentUser?: {
    id: string;
    public_key_hash: string;
    public_key: string;
    created_at: number;
    display_name?: string;
    username?: string;
    displayName?: string;
    bio?: string;
    status?: string;
  };
  onUserUpdate?: (updates: Partial<AccountSettings>) => void;
  serverInfo?: ServerInfo;
  /** Called when the user changes the relay URL from Advanced settings */
  onRelayChange?: (newUrl: string) => void;
  /** Server-side blocked users */
  blockedUsers?: Set<string>;
  /** Called to unblock a user */
  onUnblockUser?: (userId: string) => void;
  /** Map of user IDs to display names for blocked users */
  blockedUserNames?: Map<string, string>;
  /** Called when the user clicks Log Out */
  onLogout?: () => void;
}

type SettingsTab = 'account' | 'appearance' | 'notifications' | 'voice' | 'privacy' | 'advanced' | 'server' | 'about';

// Default settings
const defaultAccountSettings: AccountSettings = {
  displayName: '',
  bio: '',
  status: 'online'
};

const defaultAppearanceSettings: AppearanceSettings = {
  theme: getSavedTheme(),
  fontSize: 15,
  messageDensity: 'comfortable',
};

const defaultVoiceSettings: VoiceSettings = {
  inputDevice: 'default',
  outputDevice: 'default',
  inputVolume: 100,
  outputVolume: 100,
  vadSensitivity: 50,
  echoCancellation: true,
  noiseSuppression: true,
  autoGainControl: true
};

const defaultPrivacySettings: PrivacySettings = {
  readReceipts: true,
  typingIndicators: true,
  blockedUsers: []
};

export const Settings: React.FC<SettingsProps> = ({
  isOpen,
  onClose,
  onShowShortcuts,
  currentUser,
  onUserUpdate,
  serverInfo,
  knownHashes,
  onRelayChange,
  blockedUsers: blockedUsersProp,
  onUnblockUser,
  blockedUserNames,
  onLogout,
}) => {
  const [activeTab, setActiveTab] = useState<SettingsTab>('account');
  
  // Settings state
  const [accountSettings, setAccountSettings] = useState<AccountSettings>(defaultAccountSettings);
  const [appearanceSettings, setAppearanceSettings] = useState<AppearanceSettings>(defaultAppearanceSettings);
  const [notificationPreferences, setNotificationPreferences] = useState<NotificationPreferences>(
    notificationManager.getPreferences()
  );
  const [voiceSettings, setVoiceSettings] = useState<VoiceSettings>(defaultVoiceSettings);
  const [privacySettings, setPrivacySettings] = useState<PrivacySettings>(defaultPrivacySettings);
  
  // Media devices state
  const [inputDevices, setInputDevices] = useState<MediaDeviceInfo[]>([]);
  const [outputDevices, setOutputDevices] = useState<MediaDeviceInfo[]>([]);
  const [devicesError, setDevicesError] = useState<string>('');

  // Profile save state
  const [profileDirty, setProfileDirty] = useState(false);
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileSaveMsg, setProfileSaveMsg] = useState('');

  // Advanced state
  const [manualRelayUrl, setManualRelayUrl] = useState('');
  const [clearConfirm, setClearConfirm] = useState(false);

  // Load settings from localStorage on mount
  useEffect(() => {
    const loadSettings = () => {
      try {
        // Load account settings
        const savedAccount = localStorage.getItem('accord_account_settings');
        if (savedAccount) {
          setAccountSettings({ ...defaultAccountSettings, ...JSON.parse(savedAccount) });
        } else if (currentUser) {
          setAccountSettings({
            displayName: currentUser.displayName || currentUser.display_name || currentUser.username || currentUser.public_key_hash.slice(0, 16),
            bio: currentUser.bio || '',
            status: (currentUser.status as AccountSettings['status']) || 'online'
          });
        }

        // Load appearance settings
        const savedAppearance = localStorage.getItem('accord_appearance_settings');
        if (savedAppearance) {
          const parsed = JSON.parse(savedAppearance);
          // Migrate old fontSize string to number
          if (typeof parsed.fontSize === 'string') {
            const map: Record<string, number> = { small: 13, medium: 15, large: 17 };
            parsed.fontSize = map[parsed.fontSize] || 15;
          }
          if (parsed.compactMode !== undefined && !parsed.messageDensity) {
            parsed.messageDensity = parsed.compactMode ? 'compact' : 'comfortable';
            delete parsed.compactMode;
          }
          setAppearanceSettings({ ...defaultAppearanceSettings, ...parsed });
        }

        // Load voice settings
        const savedVoice = localStorage.getItem('accord_voice_settings');
        if (savedVoice) {
          setVoiceSettings({ ...defaultVoiceSettings, ...JSON.parse(savedVoice) });
        }

        // Load privacy settings
        const savedPrivacy = localStorage.getItem('accord_privacy_settings');
        if (savedPrivacy) {
          setPrivacySettings({ ...defaultPrivacySettings, ...JSON.parse(savedPrivacy) });
        }

        // Load notification preferences (handled by notification manager)
        setNotificationPreferences(notificationManager.getPreferences());
      } catch (error) {
        console.error('Error loading settings:', error);
      }
    };

    if (isOpen) {
      loadSettings();
      loadMediaDevices();
      setProfileDirty(false);
      setProfileSaveMsg('');
      setClearConfirm(false);
    }
  }, [isOpen, currentUser]);

  // Apply appearance settings when they change
  useEffect(() => {
    applyAppearanceSettings(appearanceSettings);
  }, [appearanceSettings]);

  // Load available media devices
  const loadMediaDevices = useCallback(async () => {
    try {
      const devices = await navigator.mediaDevices?.enumerateDevices() ?? [];
      setInputDevices(devices.filter(device => device.kind === 'audioinput'));
      setOutputDevices(devices.filter(device => device.kind === 'audiooutput'));
      setDevicesError('');
    } catch (error) {
      setDevicesError('Failed to load audio devices');
      console.error('Error loading media devices:', error);
    }
  }, []);

  // Save settings to localStorage (does NOT call API — just local)
  const updateAccountLocally = useCallback((settings: AccountSettings) => {
    setAccountSettings(settings);
    setProfileDirty(true);
    setProfileSaveMsg('');
  }, []);

  const saveProfileToServer = useCallback(async () => {
    setProfileSaving(true);
    setProfileSaveMsg('');
    try {
      const token = localStorage.getItem('accord_token') ||
        (currentUser ? localStorage.getItem(`accord_token_${api.getBaseUrl().replace(/https?:\/\//, '')}`) : null);
      if (token) {
        await api.updateProfile({
          display_name: accountSettings.displayName,
          bio: accountSettings.bio,
        }, token);
      }
      localStorage.setItem('accord_account_settings', JSON.stringify(accountSettings));
      onUserUpdate?.(accountSettings);
      setProfileDirty(false);
      setProfileSaveMsg('Profile saved!');
    } catch (err) {
      console.error('Failed to save profile:', err);
      // Still save locally
      localStorage.setItem('accord_account_settings', JSON.stringify(accountSettings));
      onUserUpdate?.(accountSettings);
      setProfileDirty(false);
      setProfileSaveMsg('Saved locally (server sync failed)');
    } finally {
      setProfileSaving(false);
    }
  }, [accountSettings, currentUser, onUserUpdate]);

  const saveAppearanceSettings = useCallback((settings: AppearanceSettings) => {
    localStorage.setItem('accord_appearance_settings', JSON.stringify(settings));
    setAppearanceSettings(settings);
  }, []);

  const saveVoiceSettings = useCallback((settings: VoiceSettings) => {
    localStorage.setItem('accord_voice_settings', JSON.stringify(settings));
    setVoiceSettings(settings);
  }, []);

  const savePrivacySettings = useCallback((settings: PrivacySettings) => {
    localStorage.setItem('accord_privacy_settings', JSON.stringify(settings));
    setPrivacySettings(settings);
  }, []);

  const saveNotificationPreferences = useCallback((preferences: NotificationPreferences) => {
    notificationManager.updatePreferences(preferences);
    setNotificationPreferences(preferences);
  }, []);

  // Apply appearance settings to DOM
  const applyAppearanceSettings = (settings: AppearanceSettings) => {
    const root = document.documentElement;
    
    // Apply theme via theme system
    applyTheme(settings.theme);

    // Apply font size (CSS variable)
    root.style.setProperty('--font-size', `${settings.fontSize}px`);
    localStorage.setItem('accord_font_size', String(settings.fontSize));

    // Apply message density
    const spacingMap = { compact: '2px', comfortable: '8px', cozy: '16px' };
    root.style.setProperty('--message-spacing', spacingMap[settings.messageDensity]);
    localStorage.setItem('accord_message_density', settings.messageDensity);
    
    // Add density class to body
    document.body.className = `theme-${settings.theme} density-${settings.messageDensity}`;
  };

  // Handle keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (isOpen && e.key === 'Escape') {
        onClose();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Test functions for voice settings
  const testMicrophone = async () => {
    try {
      const stream = await navigator.mediaDevices?.getUserMedia({ audio: true });
      setTimeout(() => {
        stream.getTracks().forEach(track => track.stop());
        alert('Microphone test completed!');
      }, 2000);
    } catch (error) {
      alert('Microphone test failed: ' + error);
    }
  };

  const testSpeakers = () => {
    const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)();
    const oscillator = audioContext.createOscillator();
    const gainNode = audioContext.createGain();
    
    oscillator.connect(gainNode);
    gainNode.connect(audioContext.destination);
    
    oscillator.frequency.setValueAtTime(440, audioContext.currentTime);
    gainNode.gain.setValueAtTime(voiceSettings.outputVolume / 100 * 0.1, audioContext.currentTime);
    
    oscillator.start();
    oscillator.stop(audioContext.currentTime + 0.5);
  };

  // Import identity state
  const [importStatus, setImportStatus] = useState<string>('');
  const [importError, setImportError] = useState<string>('');
  const [importPasswordPrompt, setImportPasswordPrompt] = useState<{ hash16: string; encPrivKey: string; pubKeyB64: string } | null>(null);
  const [importPassword, setImportPassword] = useState('');
  const [importLoading, setImportLoading] = useState(false);
  const importFileRef = useRef<HTMLInputElement>(null);

  // QR code state
  const [showQrModal, setShowQrModal] = useState(false);
  const [qrDataUrl, setQrDataUrl] = useState<string>('');
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanError, setScanError] = useState<string>('');
  const scanVideoRef = useRef<HTMLVideoElement>(null);
  const scanCanvasRef = useRef<HTMLCanvasElement>(null);
  const scanStreamRef = useRef<MediaStream | null>(null);
  const scanAnimRef = useRef<number>(0);

  // Advanced: export identity key file
  const handleExportIdentity = () => {
    const pkHash = currentUser?.public_key_hash || '';
    const hash16 = pkHash.substring(0, 16);
    if (!hash16) {
      alert('No identity found to export.');
      return;
    }
    // Read encrypted private key and public key from localStorage (namespaced)
    const encPrivKey = localStorage.getItem(`accord_private_key_${hash16}`);
    const pubKeyB64 = localStorage.getItem(`accord_public_key_${hash16}`);
    // Fallback to legacy keys
    const encPrivKeyFinal = encPrivKey || localStorage.getItem('accord_private_key');
    const pubKeyFinal = pubKeyB64 || localStorage.getItem('accord_public_key');
    if (!encPrivKeyFinal || !pubKeyFinal) {
      alert('Could not find encrypted keys in storage. Cannot export.');
      return;
    }
    const exportData = JSON.stringify({
      version: 1,
      public_key: pubKeyFinal,
      encrypted_private_key: encPrivKeyFinal,
      public_key_hash: hash16,
    }, null, 2);
    const blob = new Blob([exportData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `accord-identity-${hash16}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Advanced: import identity key file
  const handleImportFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError('');
    setImportStatus('');
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target?.result as string);
        if (!data.version || !data.public_key || !data.encrypted_private_key || !data.public_key_hash) {
          setImportError('Invalid identity file: missing required fields (version, public_key, encrypted_private_key, public_key_hash).');
          return;
        }
        if (data.version !== 1) {
          setImportError(`Unsupported identity file version: ${data.version}`);
          return;
        }
        // Prompt for password to verify
        setImportPasswordPrompt({
          hash16: data.public_key_hash,
          encPrivKey: data.encrypted_private_key,
          pubKeyB64: data.public_key,
        });
      } catch {
        setImportError('Failed to parse identity file. Must be valid JSON.');
      }
    };
    reader.readAsText(file);
    // Reset file input so the same file can be selected again
    e.target.value = '';
  };

  const handleImportConfirm = async () => {
    if (!importPasswordPrompt || !importPassword) return;
    setImportLoading(true);
    setImportError('');
    try {
      const { hash16, encPrivKey, pubKeyB64 } = importPasswordPrompt;
      // Store keys in localStorage with proper namespacing
      localStorage.setItem(`accord_private_key_${hash16}`, encPrivKey);
      localStorage.setItem(`accord_public_key_${hash16}`, pubKeyB64);
      // Also store in legacy slots
      localStorage.setItem('accord_private_key', encPrivKey);
      localStorage.setItem('accord_public_key', pubKeyB64);

      // Try to decrypt to verify password works
      const keyPair = await loadKeyWithPassword(importPassword, hash16);
      if (!keyPair) {
        // Clean up on failure
        setImportError('Incorrect password — could not decrypt the private key.');
        setImportLoading(false);
        return;
      }

      // Success — set as active identity and reload
      setActiveIdentity(hash16);
      setImportPasswordPrompt(null);
      setImportPassword('');
      setImportStatus('Identity imported successfully! Reloading...');
      setTimeout(() => window.location.reload(), 1200);
    } catch (err: any) {
      setImportError(`Import failed: ${err.message || 'unknown error'}`);
    } finally {
      setImportLoading(false);
    }
  };

  // QR code: show identity as QR
  const handleShowQrCode = async () => {
    const pkHash = currentUser?.public_key_hash || '';
    const hash16 = pkHash.substring(0, 16);
    if (!hash16) { alert('No identity found.'); return; }
    const encPrivKey = localStorage.getItem(`accord_private_key_${hash16}`) || localStorage.getItem('accord_private_key');
    const pubKey = localStorage.getItem(`accord_public_key_${hash16}`) || localStorage.getItem('accord_public_key');
    if (!encPrivKey || !pubKey) { alert('Could not find keys in storage.'); return; }
    const payload = JSON.stringify({ version: 1, public_key: pubKey, encrypted_private_key: encPrivKey, public_key_hash: hash16 });
    try {
      const url = await QRCode.toDataURL(payload, { errorCorrectionLevel: 'L', width: 300, margin: 2 });
      setQrDataUrl(url);
      setShowQrModal(true);
    } catch (err) {
      alert('Failed to generate QR code — identity data may be too large.');
    }
  };

  // QR code: scan
  const stopScan = useCallback(() => {
    if (scanAnimRef.current) { cancelAnimationFrame(scanAnimRef.current); scanAnimRef.current = 0; }
    if (scanStreamRef.current) { scanStreamRef.current.getTracks().forEach(t => t.stop()); scanStreamRef.current = null; }
  }, []);

  const handleScanQrCode = async () => {
    setScanError('');
    setShowScanModal(true);
    try {
      const stream = await navigator.mediaDevices?.getUserMedia({ video: { facingMode: 'environment' } });
      scanStreamRef.current = stream;
      const video = scanVideoRef.current;
      if (!video) { stopScan(); return; }
      video.srcObject = stream;
      video.setAttribute('playsinline', 'true');
      await video.play();
      const canvas = scanCanvasRef.current;
      if (!canvas) return;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      if (!ctx) return;
      const tick = () => {
        if (!scanStreamRef.current) return;
        if (video.readyState === video.HAVE_ENOUGH_DATA) {
          canvas.width = video.videoWidth;
          canvas.height = video.videoHeight;
          ctx.drawImage(video, 0, 0);
          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height);
          if (code) {
            try {
              const data = JSON.parse(code.data);
              if (!data.version || !data.public_key || !data.encrypted_private_key || !data.public_key_hash) {
                setScanError('Invalid QR code: missing required identity fields.');
              } else if (data.version !== 1) {
                setScanError(`Unsupported identity version: ${data.version}`);
              } else {
                // Valid — trigger import flow
                stopScan();
                setShowScanModal(false);
                setImportPasswordPrompt({ hash16: data.public_key_hash, encPrivKey: data.encrypted_private_key, pubKeyB64: data.public_key });
                return;
              }
            } catch {
              setScanError('QR code does not contain valid identity JSON.');
            }
          }
        }
        scanAnimRef.current = requestAnimationFrame(tick);
      };
      scanAnimRef.current = requestAnimationFrame(tick);
    } catch (err: any) {
      setScanError('Camera access denied. Please use file import instead.');
    }
  };

  // Cleanup scan on modal close
  const closeScanModal = useCallback(() => {
    stopScan();
    setShowScanModal(false);
    setScanError('');
  }, [stopScan]);

  // Advanced: clear local data
  const handleClearLocalData = () => {
    if (!clearConfirm) {
      setClearConfirm(true);
      return;
    }
    // Clear all accord-related localStorage
    const keysToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith('accord_')) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach(k => localStorage.removeItem(k));
    setClearConfirm(false);
    alert('Local data cleared. Please refresh the app.');
    window.location.reload();
  };

  // Advanced: connect to manual relay
  const [relayConnecting, setRelayConnecting] = useState(false);
  const [relayConnectMsg, setRelayConnectMsg] = useState('');

  const handleConnectManualRelay = async () => {
    if (!manualRelayUrl.trim()) return;
    let url = manualRelayUrl.trim();
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'http://' + url;
    }
    // Remove trailing slash
    url = url.replace(/\/+$/, '');

    setRelayConnecting(true);
    setRelayConnectMsg('');
    try {
      // Probe the server to verify it's reachable
      const resp = await fetch(`${url}/api/version`, { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) throw new Error(`Server returned ${resp.status}`);

      // Save to localStorage and update API base
      localStorage.setItem('accord_server_url', url);
      api.setBaseUrl(url);

      setRelayConnectMsg(`✅ Connected to ${url}`);
      setManualRelayUrl('');

      // Notify parent to trigger WS reconnection
      if (onRelayChange) onRelayChange(url);
    } catch (e: any) {
      // Try HTTPS fallback
      const httpsUrl = url.replace(/^http:/, 'https:');
      if (httpsUrl !== url) {
        try {
          const resp2 = await fetch(`${httpsUrl}/api/version`, { signal: AbortSignal.timeout(8000) });
          if (resp2.ok) {
            localStorage.setItem('accord_server_url', httpsUrl);
            api.setBaseUrl(httpsUrl);
            setRelayConnectMsg(`✅ Connected to ${httpsUrl}`);
            setManualRelayUrl('');
            if (onRelayChange) onRelayChange(httpsUrl);
            setRelayConnecting(false);
            return;
          }
        } catch {}
      }
      setRelayConnectMsg(`❌ Failed to connect: ${e.message || 'Server unreachable'}`);
    } finally {
      setRelayConnecting(false);
    }
  };

  // Format fingerprint
  const formatFingerprint = (hash: string) => {
    return hash.slice(0, 32).replace(/(.{4})/g, '$1 ').trim().toUpperCase();
  };

  if (!isOpen) return null;

  return (
    <div className={s.overlay}>
      <div className={s.modal}>
        <div className={s.sidebar}>
          <div className={s.sidebarHeader}>
            <h2>Settings</h2>
          </div>
          <nav className={s.nav}>
            <button
              className={activeTab === 'account' ? s.navItemActive : s.navItem}
              onClick={() => setActiveTab('account')}
            >
              👤 Profile
            </button>
            <button
              className={activeTab === 'appearance' ? s.navItemActive : s.navItem}
              onClick={() => setActiveTab('appearance')}
            >
              🎨 Appearance
            </button>
            <button
              className={activeTab === 'notifications' ? s.navItemActive : s.navItem}
              onClick={() => setActiveTab('notifications')}
            >
              🔔 Notifications
            </button>
            <button
              className={activeTab === 'voice' ? s.navItemActive : s.navItem}
              onClick={() => setActiveTab('voice')}
            >
              🎤 Voice & Audio
            </button>
            <button
              className={activeTab === 'privacy' ? s.navItemActive : s.navItem}
              onClick={() => setActiveTab('privacy')}
            >
              🔒 Privacy
            </button>
            <button
              className={activeTab === 'advanced' ? s.navItemActive : s.navItem}
              onClick={() => setActiveTab('advanced')}
            >
              ⚙️ Advanced
            </button>
            <button
              className={activeTab === 'server' ? s.navItemActive : s.navItem}
              onClick={() => setActiveTab('server')}
            >
              🖥️ Server Info
            </button>
            {onShowShortcuts && (
              <button
                className={s.navItemPlain}
                onClick={() => { onClose(); onShowShortcuts(); }}
              >
                ⌨️ Keyboard Shortcuts
              </button>
            )}
            <button
              className={activeTab === 'about' ? s.navItemActive : s.navItem}
              onClick={() => setActiveTab('about')}
            >
              ℹ️ About
            </button>
          </nav>
        </div>

        <div className={s.content}>
          <div className={s.contentHeader}>
            <button className={s.closeButton} onClick={onClose}>×</button>
          </div>

          <div className={s.panel}>
            {/* =================== PROFILE =================== */}
            {activeTab === 'account' && (
              <div className={s.section}>
                <h3>Profile</h3>

                {/* Avatar Upload */}
                <div className={s.avatarUpload}>
                  <div 
                    className={s.avatarCircle}
                    onClick={() => {
                      const input = document.createElement('input');
                      input.type = 'file';
                      input.accept = 'image/png,image/jpeg,image/gif,image/webp';
                      input.onchange = async (e) => {
                        const file = (e.target as HTMLInputElement).files?.[0];
                        if (!file) return;
                        if (file.size > 256 * 1024) {
                          setProfileSaveMsg('Avatar must be under 256KB');
                          return;
                        }
                        try {
                          const token = localStorage.getItem('accord_auth_token') || '';
                          await api.uploadUserAvatar(file, token);
                          setProfileSaveMsg('Avatar updated!');
                          setProfileDirty(false);
                        } catch (err) {
                          setProfileSaveMsg(err instanceof Error ? err.message : 'Failed to upload avatar');
                        }
                      };
                      input.click();
                    }}
                    title="Click to upload avatar"
                  >
                    {currentUser?.id ? (
                      <img 
                        src={`${api.getUserAvatarUrl(currentUser.id)}`}
                        alt={(currentUser?.display_name || "U")[0]}
                        onError={(e) => { const img = e.target as HTMLImageElement; img.style.display = 'none'; img.removeAttribute('src'); if (img.parentElement) img.parentElement.textContent = (currentUser?.display_name || "U")[0]; }}
                      />
                    ) : (currentUser?.display_name || "U")[0]}
                    <div className={s.avatarEdit}>EDIT</div>
                  </div>
                  <span className={s.avatarHint}>
                    Click to upload avatar (PNG, JPEG, GIF, WebP — max 256KB)
                  </span>
                </div>

                {/* Fingerprint */}
                {currentUser?.public_key_hash && (
                  <div className={s.group}>
                    <label className={s.label}>Public Key Fingerprint</label>
                    <div className={s.info} style={{ fontFamily: 'var(--font-mono)', fontSize: 13, letterSpacing: 0.5 }}>
                      {formatFingerprint(currentUser.public_key_hash)}
                    </div>
                  </div>
                )}

                <div className={s.group}>
                  <label className={s.label}>Display Name</label>
                  <input
                    type="text"
                    className={s.input}
                    value={accountSettings.displayName}
                    onChange={(e) => updateAccountLocally({
                      ...accountSettings,
                      displayName: e.target.value
                    })}
                    placeholder="Enter display name..."
                  />
                </div>

                <div className={s.group}>
                  <label className={s.label}>Bio</label>
                  <textarea
                    className={s.textarea}
                    value={accountSettings.bio}
                    onChange={(e) => updateAccountLocally({
                      ...accountSettings,
                      bio: e.target.value
                    })}
                    placeholder="Tell others about yourself..."
                    rows={3}
                  />
                </div>

                <div className={s.group}>
                  <label className={s.label}>Status</label>
                  <div className="status-buttons">
                    {(['online', 'away', 'busy', 'invisible'] as const).map(status => (
                      <button
                        key={status}
                        className={`status-button ${accountSettings.status === status ? 'active' : ''}`}
                        onClick={() => updateAccountLocally({
                          ...accountSettings,
                          status
                        })}
                      >
                        <div className={`status-indicator ${status}`}></div>
                        {status.charAt(0).toUpperCase() + status.slice(1)}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Save button */}
                <div className={clsx(s.group, s.actionRow)}>
                  <button
                    className={clsx(btnStyles.button, btnStyles.primary)}
                    style={{ width: 'auto', padding: '10px 24px' }}
                    disabled={!profileDirty || profileSaving}
                    onClick={saveProfileToServer}
                  >
                    {profileSaving ? 'Saving...' : 'Save Profile'}
                  </button>
                  {profileSaveMsg && (
                    <span className={s.help} style={{ color: profileSaveMsg.includes('failed') ? 'var(--yellow)' : 'var(--green)', margin: 0 }}>
                      {profileSaveMsg}
                    </span>
                  )}
                </div>

                <div className={s.group}>
                  <div className={s.info}>
                    <strong>User ID:</strong> {currentUser?.id || 'Unknown'}
                  </div>
                </div>

                <div className={s.logoutSection}>
                  <button
                    className={s.logoutBtn}
                    onClick={() => { onClose(); if (onLogout) setTimeout(onLogout, 100); }}
                  >
                    🚪 Log Out
                  </button>
                  <p className={s.logoutHint}>
                    Your identity keys are saved locally. You can log back in with your password.
                  </p>
                </div>
              </div>
            )}

            {/* =================== APPEARANCE =================== */}
            {activeTab === 'appearance' && (
              <div className={s.section}>
                <h3>Appearance</h3>
                
                <div className={s.group}>
                  <label className={s.label}>Theme</label>
                  <div className="theme-buttons" style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                    {Object.values(themes).map((theme) => (
                      <button
                        key={theme.name}
                        className={`theme-swatch-btn ${appearanceSettings.theme === theme.name ? 'active' : ''}`}
                        onClick={() => {
                          applyTheme(theme.name);
                          saveAppearanceSettings({ ...appearanceSettings, theme: theme.name });
                        }}
                        style={{
                          display: 'flex',
                          flexDirection: 'column',
                          alignItems: 'center',
                          gap: '8px',
                          padding: '12px',
                          borderRadius: 'var(--radius-md)',
                          border: appearanceSettings.theme === theme.name
                            ? '2px solid var(--accent)'
                            : '2px solid var(--border-subtle)',
                          background: 'var(--bg-input)',
                          cursor: 'pointer',
                          transition: 'border-color 0.15s ease',
                          minWidth: '100px',
                        }}
                      >
                        {/* Preview swatch */}
                        <div style={{
                          width: '80px',
                          height: '52px',
                          borderRadius: '6px',
                          overflow: 'hidden',
                          display: 'flex',
                          boxShadow: '0 2px 6px rgba(0,0,0,0.3)',
                        }}>
                          <div style={{ width: '24px', background: theme.preview.sidebar }} />
                          <div style={{ flex: 1, background: theme.preview.bg, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', gap: '3px', padding: '4px' }}>
                            <div style={{ width: '100%', height: '4px', borderRadius: '2px', background: theme.preview.text, opacity: 0.6 }} />
                            <div style={{ width: '70%', height: '4px', borderRadius: '2px', background: theme.preview.text, opacity: 0.3 }} />
                            <div style={{ width: '50%', height: '6px', borderRadius: '3px', background: theme.preview.accent, marginTop: '2px' }} />
                          </div>
                        </div>
                        <span style={{ fontSize: '13px', color: 'var(--text-secondary)', fontWeight: appearanceSettings.theme === theme.name ? 600 : 400 }}>
                          {theme.icon} {theme.label}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>

                <div className={s.group}>
                  <label className={s.label}>
                    Font Size: {appearanceSettings.fontSize}px
                  </label>
                  <input
                    type="range"
                    className={s.slider}
                    min="12"
                    max="20"
                    step="1"
                    value={appearanceSettings.fontSize}
                    onChange={(e) => saveAppearanceSettings({
                      ...appearanceSettings,
                      fontSize: parseInt(e.target.value)
                    })}
                  />
                  <div className={s.help} style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>12px</span><span>20px</span>
                  </div>
                </div>

                <div className={s.group}>
                  <label className={s.label}>Message Density</label>
                  <div className="font-size-buttons">
                    {(['compact', 'comfortable', 'cozy'] as const).map(d => (
                      <button
                        key={d}
                        className={`font-size-button ${appearanceSettings.messageDensity === d ? 'active' : ''}`}
                        onClick={() => saveAppearanceSettings({
                          ...appearanceSettings,
                          messageDensity: d
                        })}
                      >
                        {d.charAt(0).toUpperCase() + d.slice(1)}
                      </button>
                    ))}
                  </div>
                  <div className={s.help}>
                    Controls spacing between messages. Compact shows more messages on screen.
                  </div>
                </div>
              </div>
            )}

            {/* =================== NOTIFICATIONS =================== */}
            {activeTab === 'notifications' && (
              <div className={s.section}>
                <h3>Notification Settings</h3>
                
                <div className={s.group}>
                  <label className={s.checkbox}>
                    <input
                      type="checkbox"
                      checked={notificationPreferences.enabled}
                      onChange={(e) => saveNotificationPreferences({
                        ...notificationPreferences,
                        enabled: e.target.checked
                      })}
                    />
                    <span className="checkmark"></span>
                    Enable Desktop Notifications
                  </label>
                </div>

                <div className={s.group}>
                  <label className={s.label}>Notification Mode</label>
                  <div className="notification-mode-buttons">
                    {(['all', 'mentions', 'dms', 'none'] as const).map(mode => (
                      <button
                        key={mode}
                        className={`notification-button ${notificationPreferences.mode === mode ? 'active' : ''}`}
                        onClick={() => saveNotificationPreferences({
                          ...notificationPreferences,
                          mode
                        })}
                      >
                        {mode === 'all' ? 'All Messages' : 
                         mode === 'mentions' ? 'Mentions Only' :
                         mode === 'dms' ? 'DMs & Mentions' :
                         'None'}
                      </button>
                    ))}
                  </div>
                </div>

                <div className={s.group}>
                  <label className={s.checkbox}>
                    <input
                      type="checkbox"
                      checked={notificationPreferences.sounds}
                      onChange={(e) => saveNotificationPreferences({
                        ...notificationPreferences,
                        sounds: e.target.checked
                      })}
                    />
                    <span className="checkmark"></span>
                    Sound Notifications
                  </label>
                </div>

                <div className={s.group}>
                  <div className="test-buttons">
                    <button
                      className="test-button"
                      onClick={() => {
                        if ('Notification' in window && Notification.permission === 'granted') {
                          new Notification('Test Notification', {
                            body: 'This is a test notification from Accord!',
                            icon: '/favicon.ico'
                          });
                        } else {
                          Notification.requestPermission().then(permission => {
                            if (permission === 'granted') {
                              new Notification('Test Notification', {
                                body: 'This is a test notification from Accord!',
                                icon: '/favicon.ico'
                              });
                            }
                          });
                        }
                      }}
                    >
                      Test Notification
                    </button>
                    <button
                      className="test-button"
                      onClick={() => (notificationManager as any).playNotificationSound?.()}
                    >
                      Test Sound
                    </button>
                    <button
                      className="clear-button"
                      onClick={() => {
                        notificationManager.clearAllUnreads();
                        alert('All unread counts cleared');
                      }}
                    >
                      Clear All Unreads
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* =================== VOICE =================== */}
            {activeTab === 'voice' && (
              <div className={s.section}>
                <h3>Voice & Audio</h3>
                <p className={s.sectionDesc}>Configure your microphone, speakers, and voice processing settings.</p>
                
                {devicesError && (
                  <div className={s.error}>{devicesError}</div>
                )}

                {/* Input Device */}
                <div className={s.subsection}>
                  <h4 className={s.subsectionTitle}>🎤 Input Device</h4>
                  <div className={s.group}>
                    <label className={s.label}>Microphone</label>
                    <select
                      className={s.select}
                      value={voiceSettings.inputDevice}
                      onChange={(e) => saveVoiceSettings({
                        ...voiceSettings,
                        inputDevice: e.target.value
                      })}
                    >
                      <option value="default">Default</option>
                      {inputDevices.map(device => (
                        <option key={device.deviceId} value={device.deviceId}>
                          {device.label || `Microphone ${device.deviceId.slice(0, 8)}...`}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className={s.group}>
                    <label className={s.label}>
                      Input Volume
                      <span className={s.labelValue}>{voiceSettings.inputVolume}%</span>
                    </label>
                    <input
                      type="range"
                      className={s.slider}
                      min="0"
                      max="100"
                      value={voiceSettings.inputVolume}
                      onChange={(e) => saveVoiceSettings({
                        ...voiceSettings,
                        inputVolume: parseInt(e.target.value)
                      })}
                    />
                  </div>
                  <button className={s.btnSecondary} onClick={testMicrophone}>
                    Test Microphone
                  </button>
                </div>

                {/* Output Device */}
                <div className={s.subsection}>
                  <h4 className={s.subsectionTitle}>🔊 Output Device</h4>
                  <div className={s.group}>
                    <label className={s.label}>Speakers</label>
                    <select
                      className={s.select}
                      value={voiceSettings.outputDevice}
                      onChange={(e) => saveVoiceSettings({
                        ...voiceSettings,
                        outputDevice: e.target.value
                      })}
                    >
                      <option value="default">Default</option>
                      {outputDevices.map(device => (
                        <option key={device.deviceId} value={device.deviceId}>
                          {device.label || `Speaker ${device.deviceId.slice(0, 8)}...`}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className={s.group}>
                    <label className={s.label}>
                      Output Volume
                      <span className={s.labelValue}>{voiceSettings.outputVolume}%</span>
                    </label>
                    <input
                      type="range"
                      className={s.slider}
                      min="0"
                      max="100"
                      value={voiceSettings.outputVolume}
                      onChange={(e) => saveVoiceSettings({
                        ...voiceSettings,
                        outputVolume: parseInt(e.target.value)
                      })}
                    />
                  </div>
                  <button className={s.btnSecondary} onClick={testSpeakers}>
                    Test Speakers
                  </button>
                </div>

                {/* Voice Activity Detection */}
                <div className={s.subsection}>
                  <h4 className={s.subsectionTitle}>🗣️ Input Sensitivity</h4>
                  <p className={s.subsectionDesc}>Controls how loud you need to be before your mic activates. Higher values require louder audio.</p>
                  <div className={s.group}>
                    <label className={s.label}>
                      Voice Activity Sensitivity
                      <span className={s.labelValue}>{voiceSettings.vadSensitivity}%</span>
                    </label>
                    <input
                      type="range"
                      className={s.slider}
                      min="0"
                      max="100"
                      value={voiceSettings.vadSensitivity}
                      onChange={(e) => saveVoiceSettings({
                        ...voiceSettings,
                        vadSensitivity: parseInt(e.target.value)
                      })}
                    />
                    <div className={s.sliderLabels}>
                      <span>Sensitive</span><span>Aggressive</span>
                    </div>
                  </div>
                </div>

                {/* Voice Processing */}
                <div className={s.subsection}>
                  <h4 className={s.subsectionTitle}>⚡ Voice Processing</h4>
                  <p className={s.subsectionDesc}>Audio processing filters applied to your microphone input.</p>
                  <div className={s.toggleGroup}>
                    <label className={s.toggleRow}>
                      <div className={s.toggleInfo}>
                        <span className={s.toggleLabel}>Echo Cancellation</span>
                        <span className={s.toggleDesc}>Removes echo from your speakers being picked up by your mic</span>
                      </div>
                      <div className={`settings-toggle ${voiceSettings.echoCancellation ? 'active' : ''}`}
                        onClick={() => saveVoiceSettings({ ...voiceSettings, echoCancellation: !voiceSettings.echoCancellation })}>
                        <div className={s.toggleKnob} />
                      </div>
                    </label>
                    <label className={s.toggleRow}>
                      <div className={s.toggleInfo}>
                        <span className={s.toggleLabel}>Noise Suppression</span>
                        <span className={s.toggleDesc}>Filters out background noise like fans, keyboards, and ambient sounds</span>
                      </div>
                      <div className={`settings-toggle ${voiceSettings.noiseSuppression ? 'active' : ''}`}
                        onClick={() => saveVoiceSettings({ ...voiceSettings, noiseSuppression: !voiceSettings.noiseSuppression })}>
                        <div className={s.toggleKnob} />
                      </div>
                    </label>
                    <label className={s.toggleRow}>
                      <div className={s.toggleInfo}>
                        <span className={s.toggleLabel}>Automatic Gain Control</span>
                        <span className={s.toggleDesc}>Automatically adjusts your mic volume to maintain consistent levels</span>
                      </div>
                      <div className={`settings-toggle ${voiceSettings.autoGainControl ? 'active' : ''}`}
                        onClick={() => saveVoiceSettings({ ...voiceSettings, autoGainControl: !voiceSettings.autoGainControl })}>
                        <div className={s.toggleKnob} />
                      </div>
                    </label>
                  </div>
                </div>

                {/* Refresh Devices */}
                <div className={s.group} style={{ paddingTop: '8px' }}>
                  <button className={s.btnSecondary} onClick={loadMediaDevices}>
                    🔄 Refresh Devices
                  </button>
                </div>
              </div>
            )}

            {/* =================== PRIVACY =================== */}
            {activeTab === 'privacy' && (
              <div className={s.section}>
                <h3>Privacy Settings</h3>
                
                <div className={s.group}>
                  <label className={s.checkbox}>
                    <input
                      type="checkbox"
                      checked={privacySettings.readReceipts}
                      onChange={(e) => savePrivacySettings({
                        ...privacySettings,
                        readReceipts: e.target.checked
                      })}
                    />
                    <span className="checkmark"></span>
                    Send Read Receipts
                  </label>
                  <div className={s.help}>
                    Let others know when you've read their messages.
                  </div>
                </div>

                <div className={s.group}>
                  <label className={s.checkbox}>
                    <input
                      type="checkbox"
                      checked={privacySettings.typingIndicators}
                      onChange={(e) => savePrivacySettings({
                        ...privacySettings,
                        typingIndicators: e.target.checked
                      })}
                    />
                    <span className="checkmark"></span>
                    Show Typing Indicators
                  </label>
                  <div className={s.help}>
                    Show when you're typing to other users.
                  </div>
                </div>

                <div className={s.group}>
                  <label className={s.label}>Block List</label>
                  <div className="blocked-users">
                    {(!blockedUsersProp || blockedUsersProp.size === 0) ? (
                      <div className={s.help}>No blocked users</div>
                    ) : (
                      Array.from(blockedUsersProp).map(userId => (
                        <div key={userId} className="blocked-user">
                          <span>{blockedUserNames?.get(userId) || userId.substring(0, 16) + '...'}</span>
                          <button
                            className="unblock-button"
                            onClick={() => onUnblockUser?.(userId)}
                          >
                            Unblock
                          </button>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* =================== ADVANCED =================== */}
            {activeTab === 'advanced' && (
              <div className={s.section}>
                <h3>Advanced</h3>

                <div className={s.group}>
                  <label className={s.label}>Current Relay URL</label>
                  <div className={s.info} style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>
                    {api.getBaseUrl()}
                  </div>
                </div>

                <div className={s.group}>
                  <label className={s.label}>Connect to Relay Manually</label>
                  <div className={s.relayRow}>
                    <input
                      type="text"
                      className={s.input}
                      value={manualRelayUrl}
                      onChange={(e) => setManualRelayUrl(e.target.value)}
                      placeholder="e.g. 192.168.1.100:8080"
                      onKeyDown={(e) => { if (e.key === 'Enter') handleConnectManualRelay(); }}
                    />
                    <button
                      className={clsx(btnStyles.button, btnStyles.primary)}
                      style={{ width: 'auto', padding: '10px 16px', whiteSpace: 'nowrap' }}
                      onClick={handleConnectManualRelay}
                      disabled={!manualRelayUrl.trim() || relayConnecting}
                    >
                      {relayConnecting ? 'Connecting...' : 'Connect'}
                    </button>
                  </div>
                  {relayConnectMsg && (
                    <div className={`settings-relay-msg ${relayConnectMsg.startsWith('✅') ? 'ok' : 'fail'}`}>
                      {relayConnectMsg}
                    </div>
                  )}
                  <div className={s.help}>
                    Enter a relay server address to connect to a different server. This will save the URL and reconnect.
                  </div>
                </div>

                <div className={s.group}>
                  <label className={s.label}>Identity Key Management</label>
                  <div className="test-buttons" style={{ flexWrap: 'wrap' }}>
                    <button className="test-button" onClick={handleExportIdentity}>
                      📤 Export Identity
                    </button>
                    <button className="test-button" onClick={handleShowQrCode}>
                      📱 Show QR Code
                    </button>
                    <button className="test-button" onClick={() => importFileRef.current?.click()}>
                      📥 Import Identity
                    </button>
                    <button className="test-button" onClick={handleScanQrCode}>
                      📷 Scan QR Code
                    </button>
                    <input
                      ref={importFileRef}
                      type="file"
                      accept=".json"
                      style={{ display: 'none' }}
                      onChange={handleImportFile}
                    />
                  </div>
                  <div className={s.help}>
                    Export your encrypted identity to a JSON file for backup or transfer to another browser. Import a previously exported identity file to restore access.
                  </div>
                  {importStatus && <div className="auth-success" style={{ marginTop: 8 }}>{importStatus}</div>}
                  {importError && <div className={s.help} style={{ color: 'var(--red)', marginTop: 8 }}>{importError}</div>}
                  {importPasswordPrompt && (
                    <div className={s.importPrompt}>
                      <div style={{ marginBottom: 8, fontSize: 14 }}>
                        Enter password to decrypt identity <code className={s.hashCode}>{importPasswordPrompt.hash16}</code>:
                      </div>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        <input
                          type="password"
                          placeholder="Password"
                          value={importPassword}
                          onChange={(e) => setImportPassword(e.target.value)}
                          onKeyDown={(e) => { if (e.key === 'Enter') handleImportConfirm(); }}
                          className={s.input}
                          style={{ flex: 1 }}
                          autoFocus
                        />
                        <button className="test-button" onClick={handleImportConfirm} disabled={importLoading || !importPassword}>
                          {importLoading ? 'Verifying...' : 'Confirm'}
                        </button>
                        <button className="test-button" onClick={() => { setImportPasswordPrompt(null); setImportPassword(''); }}>
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                <div className={s.group}>
                  <label className={s.label}>Clear Local Data</label>
                  {!clearConfirm ? (
                    <button className="clear-button" onClick={handleClearLocalData}>
                      🗑️ Clear Local Data
                    </button>
                  ) : (
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <button className="clear-button" onClick={handleClearLocalData}>
                        Confirm — Delete Everything
                      </button>
                      <button className="test-button" onClick={() => setClearConfirm(false)}>
                        Cancel
                      </button>
                    </div>
                  )}
                  <div className={s.help}>
                    Removes all locally stored settings, keys, and tokens. This cannot be undone.
                  </div>
                </div>
              </div>
            )}

            {/* =================== SERVER INFO =================== */}
            {activeTab === 'server' && (
              <div className={s.section}>
                <h3>Server Info</h3>

                <div className={s.group}>
                  <label className={s.label}>Connection Status</label>
                  <div className={s.info}>
                    {serverInfo?.isConnected ? '🟢 Connected' : '🔴 Disconnected'}
                  </div>
                </div>

                {serverInfo?.version && (
                  <div className={s.group}>
                    <label className={s.label}>Server Version</label>
                    <div className={s.info}>{serverInfo.version}</div>
                  </div>
                )}

                {serverInfo?.buildHash && (
                  <div className={s.group}>
                    <label className={s.label}>Server Build Hash</label>
                    <div
                      className={s.info}
                      style={{ fontFamily: 'var(--font-mono)', fontSize: 13, cursor: 'pointer' }}
                      title="Click to copy"
                      onClick={() => { navigator.clipboard?.writeText(serverInfo.buildHash); }}
                    >
                      {serverInfo.buildHash} 📋
                    </div>
                  </div>
                )}

                {serverInfo?.connectedSince && (
                  <div className={s.group}>
                    <label className={s.label}>Connected Since</label>
                    <div className={s.info}>
                      {new Date(serverInfo.connectedSince).toLocaleString()}
                    </div>
                  </div>
                )}

                <div className={s.group}>
                  <label className={s.label}>Relay Address</label>
                  <div className={s.info} style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>
                    {serverInfo?.relayAddress || api.getBaseUrl()}
                  </div>
                </div>
              </div>
            )}

            {/* =================== ABOUT =================== */}
            {activeTab === 'about' && (() => {
              const clientTrust = verifyBuildHash(CLIENT_BUILD_HASH, knownHashes);
              const serverTrust = serverInfo?.buildHash ? verifyBuildHash(serverInfo.buildHash, knownHashes) : null;
              const combinedTrust = serverInfo?.buildHash
                ? getCombinedTrust(CLIENT_BUILD_HASH, serverInfo.buildHash, knownHashes)
                : clientTrust;
              const indicator = getTrustIndicator(combinedTrust);

              return (
              <div className={s.section}>
                <h3>About Accord</h3>
                
                <div className="about-content">
                  <div className="about-logo">
                    <div className="app-icon">A</div>
                    <h2>Accord</h2>
                  </div>
                  
                  <div className="about-info">
                    <div className="info-row">
                      <strong>Version:</strong> {ACCORD_VERSION}
                    </div>
                    <div className="info-row">
                      <strong>Protocol:</strong> Accord Protocol v1
                    </div>
                    <div className="info-row">
                      <strong>Platform:</strong> Desktop (Tauri + React)
                    </div>
                  </div>

                  {/* Build Hash Verification */}
                  <div className={s.buildCard}>
                    <h4>Build Verification</h4>
                    
                    <div className={s.trustBadge} style={{ background: `${indicator.color}15`, border: `1px solid ${indicator.color}40` }}>
                      <span style={{ fontSize: 18 }}>{indicator.emoji}</span>
                      <span style={{ fontWeight: 600, color: indicator.color }}>{indicator.label}</span>
                    </div>

                    <div className="info-row" style={{ marginBottom: 6 }}>
                      <strong>Client Build:</strong>{' '}
                      <code className={s.hashCode} title={`Full hash: ${CLIENT_BUILD_HASH}\nClick to copy`} onClick={() => navigator.clipboard?.writeText(CLIENT_BUILD_HASH)}>
                        {shortHash(CLIENT_BUILD_HASH)}
                      </code>
                      <span style={{ marginLeft: 6, fontSize: 11, color: getTrustIndicator(clientTrust).color }}>
                        {getTrustIndicator(clientTrust).emoji} {getTrustIndicator(clientTrust).label}
                      </span>
                    </div>

                    <div className="info-row" style={{ marginBottom: 6 }}>
                      <strong>Server Build:</strong>{' '}
                      {serverInfo?.buildHash ? (
                        <>
                          <code className={s.hashCode} title={`Full hash: ${serverInfo.buildHash}\nClick to copy`} onClick={() => navigator.clipboard?.writeText(serverInfo.buildHash)}>
                            {shortHash(serverInfo.buildHash)}
                          </code>
                          {serverTrust && (
                            <span style={{ marginLeft: 6, fontSize: 11, color: getTrustIndicator(serverTrust).color }}>
                              {getTrustIndicator(serverTrust).emoji} {getTrustIndicator(serverTrust).label}
                            </span>
                          )}
                        </>
                      ) : (
                        <span className={s.help} style={{ margin: 0 }}>
                          {serverInfo?.isConnected ? 'Not reported' : 'Not connected'}
                        </span>
                      )}
                    </div>

                    <div className={s.help} style={{ marginTop: 8 }}>
                      Build hashes verify that client and server code hasn't been tampered with.
                      Official releases are signed and verified against a known hash registry.
                    </div>
                  </div>

                  {/* Update Checker */}
                  <UpdateSection />

                  <div className="about-description">
                    <p>
                      Accord is an open-source, privacy-first chat application with 
                      end-to-end encryption. Your keys, your data, your control.
                    </p>
                  </div>

                  <div className="about-links">
                    <a href="https://github.com/nicholasgasior/accord" target="_blank" rel="noopener noreferrer">
                      📖 Source Code on GitHub
                    </a>
                    <a href="https://github.com/nicholasgasior/accord/issues" target="_blank" rel="noopener noreferrer">
                      🐛 Report a Bug
                    </a>
                    <a href="https://github.com/nicholasgasior/accord/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">
                      📄 License (MIT)
                    </a>
                  </div>

                  <div className="about-credits">
                    <h4>Built with ❤️ by the Accord team</h4>
                    <p>Special thanks to all contributors and the open-source community.</p>
                  </div>
                </div>
              </div>
              );
            })()}
          </div>
        </div>
      </div>
      {/* QR Code Show Modal */}
      {showQrModal && (
        <div className={s.overlay} style={{ zIndex: 10001 }} onClick={() => setShowQrModal(false)}>
          <div className={s.qrModal} onClick={e => e.stopPropagation()}>
            <h3>Identity QR Code</h3>
            <img src={qrDataUrl} alt="Identity QR Code" className={s.qrImg} />
            <p className={s.help} style={{ margin: '12px 0 4px' }}>
              Scan this QR code on your other device to sync your identity.
            </p>
            <p className={s.qrWarning}>
              ⚠️ This QR code contains your encrypted identity. Only share with your own devices.
            </p>
            <button className={clsx(btnStyles.button, btnStyles.primary)} style={{ width: 'auto', padding: '8px 24px' }} onClick={() => setShowQrModal(false)}>Close</button>
          </div>
        </div>
      )}

      {/* QR Code Scan Modal */}
      {showScanModal && (
        <div className={s.overlay} style={{ zIndex: 10001 }} onClick={closeScanModal}>
          <div className={s.qrModal} style={{ maxWidth: 400 }} onClick={e => e.stopPropagation()}>
            <h3>Scan Identity QR Code</h3>
            {scanError ? (
              <div>
                <p style={{ color: 'var(--red)', fontSize: 14, margin: '16px 0' }}>{scanError}</p>
                <p className={s.help}>You can use file import as an alternative.</p>
              </div>
            ) : (
              <div>
                <video ref={scanVideoRef} style={{ width: '100%', maxWidth: 340, borderRadius: 8, background: '#000' }} muted playsInline />
                <canvas ref={scanCanvasRef} style={{ display: 'none' }} />
                <p className={s.help} style={{ marginTop: 8 }}>Point your camera at an Accord identity QR code.</p>
              </div>
            )}
            <button className={clsx(btnStyles.button, btnStyles.primary)} style={{ width: 'auto', padding: '8px 24px', marginTop: 12 }} onClick={closeScanModal}>Cancel</button>
          </div>
        </div>
      )}
    </div>
  );
};
