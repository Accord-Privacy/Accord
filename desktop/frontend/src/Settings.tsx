import React, { useState, useEffect, useCallback } from 'react';
import { notificationManager, NotificationPreferences } from './notifications';

// Types for settings
interface AccountSettings {
  displayName: string;
  bio: string;
  status: 'online' | 'away' | 'busy' | 'invisible';
}

interface AppearanceSettings {
  theme: 'dark' | 'light';
  fontSize: 'small' | 'medium' | 'large';
  compactMode: boolean;
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

interface SettingsProps {
  isOpen: boolean;
  onClose: () => void;
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
}

type SettingsTab = 'account' | 'appearance' | 'notifications' | 'voice' | 'privacy' | 'about';

// Default settings
const defaultAccountSettings: AccountSettings = {
  displayName: '',
  bio: '',
  status: 'online'
};

const defaultAppearanceSettings: AppearanceSettings = {
  theme: 'dark',
  fontSize: 'medium',
  compactMode: false
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
  currentUser,
  onUserUpdate
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
            status: (currentUser.status as any) || 'online'
          });
        }

        // Load appearance settings
        const savedAppearance = localStorage.getItem('accord_appearance_settings');
        if (savedAppearance) {
          setAppearanceSettings({ ...defaultAppearanceSettings, ...JSON.parse(savedAppearance) });
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
    }
  }, [isOpen, currentUser]);

  // Apply appearance settings when they change
  useEffect(() => {
    applyAppearanceSettings(appearanceSettings);
  }, [appearanceSettings]);

  // Load available media devices
  const loadMediaDevices = useCallback(async () => {
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      setInputDevices(devices.filter(device => device.kind === 'audioinput'));
      setOutputDevices(devices.filter(device => device.kind === 'audiooutput'));
      setDevicesError('');
    } catch (error) {
      setDevicesError('Failed to load audio devices');
      console.error('Error loading media devices:', error);
    }
  }, []);

  // Save settings to localStorage
  const saveAccountSettings = useCallback((settings: AccountSettings) => {
    localStorage.setItem('accord_account_settings', JSON.stringify(settings));
    setAccountSettings(settings);
    onUserUpdate?.(settings);
  }, [onUserUpdate]);

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
    
    // Apply theme
    if (settings.theme === 'light') {
      root.style.setProperty('--bg-primary', '#ffffff');
      root.style.setProperty('--bg-secondary', '#f6f6f6');
      root.style.setProperty('--bg-tertiary', '#e3e5e8');
      root.style.setProperty('--text-primary', '#2e3338');
      root.style.setProperty('--text-secondary', '#747f8d');
    } else {
      root.style.setProperty('--bg-primary', '#36393f');
      root.style.setProperty('--bg-secondary', '#2f3136');
      root.style.setProperty('--bg-tertiary', '#202225');
      root.style.setProperty('--text-primary', '#dcddde');
      root.style.setProperty('--text-secondary', '#8e9297');
    }

    // Apply font size
    const fontSizes = {
      small: '13px',
      medium: '14px',
      large: '16px'
    };
    root.style.setProperty('--font-size', fontSizes[settings.fontSize]);

    // Apply compact mode
    const spacing = settings.compactMode ? '4px' : '8px';
    root.style.setProperty('--message-spacing', spacing);
    
    // Add theme class to body
    document.body.className = `theme-${settings.theme}${settings.compactMode ? ' compact-mode' : ''}`;
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
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      // Simple test - could be enhanced with audio level visualization
      setTimeout(() => {
        stream.getTracks().forEach(track => track.stop());
        alert('Microphone test completed!');
      }, 2000);
    } catch (error) {
      alert('Microphone test failed: ' + error);
    }
  };

  const testSpeakers = () => {
    // Play a simple test tone
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

  if (!isOpen) return null;

  return (
    <div className="settings-overlay">
      <div className="settings-modal">
        <div className="settings-sidebar">
          <div className="settings-header">
            <h2>Settings</h2>
          </div>
          <nav className="settings-nav">
            <button
              className={`settings-nav-item ${activeTab === 'account' ? 'active' : ''}`}
              onClick={() => setActiveTab('account')}
            >
              👤 Account
            </button>
            <button
              className={`settings-nav-item ${activeTab === 'appearance' ? 'active' : ''}`}
              onClick={() => setActiveTab('appearance')}
            >
              🎨 Appearance
            </button>
            <button
              className={`settings-nav-item ${activeTab === 'notifications' ? 'active' : ''}`}
              onClick={() => setActiveTab('notifications')}
            >
              🔔 Notifications
            </button>
            <button
              className={`settings-nav-item ${activeTab === 'voice' ? 'active' : ''}`}
              onClick={() => setActiveTab('voice')}
            >
              🎤 Voice & Audio
            </button>
            <button
              className={`settings-nav-item ${activeTab === 'privacy' ? 'active' : ''}`}
              onClick={() => setActiveTab('privacy')}
            >
              🔒 Privacy
            </button>
            <button
              className={`settings-nav-item ${activeTab === 'about' ? 'active' : ''}`}
              onClick={() => setActiveTab('about')}
            >
              ℹ️ About
            </button>
          </nav>
        </div>

        <div className="settings-content">
          <div className="settings-content-header">
            <button className="settings-close" onClick={onClose}>×</button>
          </div>

          <div className="settings-panel">
            {activeTab === 'account' && (
              <div className="settings-section">
                <h3>Account Settings</h3>
                <div className="settings-group">
                  <label className="settings-label">
                    Display Name
                    <input
                      type="text"
                      className="settings-input"
                      value={accountSettings.displayName}
                      onChange={(e) => saveAccountSettings({
                        ...accountSettings,
                        displayName: e.target.value
                      })}
                      placeholder="Enter display name..."
                    />
                  </label>
                </div>

                <div className="settings-group">
                  <label className="settings-label">
                    Bio
                    <textarea
                      className="settings-textarea"
                      value={accountSettings.bio}
                      onChange={(e) => saveAccountSettings({
                        ...accountSettings,
                        bio: e.target.value
                      })}
                      placeholder="Tell others about yourself..."
                      rows={3}
                    />
                  </label>
                </div>

                <div className="settings-group">
                  <label className="settings-label">Status</label>
                  <div className="status-buttons">
                    {(['online', 'away', 'busy', 'invisible'] as const).map(status => (
                      <button
                        key={status}
                        className={`status-button ${accountSettings.status === status ? 'active' : ''}`}
                        onClick={() => saveAccountSettings({
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

                <div className="settings-group">
                  <div className="settings-info">
                    <strong>Username:</strong> {currentUser?.username || 'Unknown'}
                    <br />
                    <strong>User ID:</strong> {currentUser?.id || 'Unknown'}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'appearance' && (
              <div className="settings-section">
                <h3>Appearance</h3>
                
                <div className="settings-group">
                  <label className="settings-label">Theme</label>
                  <div className="theme-buttons">
                    <button
                      className={`theme-button dark ${appearanceSettings.theme === 'dark' ? 'active' : ''}`}
                      onClick={() => saveAppearanceSettings({
                        ...appearanceSettings,
                        theme: 'dark'
                      })}
                    >
                      🌙 Dark
                    </button>
                    <button
                      className={`theme-button light ${appearanceSettings.theme === 'light' ? 'active' : ''}`}
                      onClick={() => saveAppearanceSettings({
                        ...appearanceSettings,
                        theme: 'light'
                      })}
                    >
                      ☀️ Light
                    </button>
                  </div>
                  <div className="settings-help">
                    Light theme is experimental and may not look perfect everywhere.
                  </div>
                </div>

                <div className="settings-group">
                  <label className="settings-label">Font Size</label>
                  <div className="font-size-buttons">
                    {(['small', 'medium', 'large'] as const).map(size => (
                      <button
                        key={size}
                        className={`font-size-button ${appearanceSettings.fontSize === size ? 'active' : ''}`}
                        onClick={() => saveAppearanceSettings({
                          ...appearanceSettings,
                          fontSize: size
                        })}
                      >
                        {size.charAt(0).toUpperCase() + size.slice(1)}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="settings-group">
                  <label className="settings-checkbox">
                    <input
                      type="checkbox"
                      checked={appearanceSettings.compactMode}
                      onChange={(e) => saveAppearanceSettings({
                        ...appearanceSettings,
                        compactMode: e.target.checked
                      })}
                    />
                    <span className="checkmark"></span>
                    Compact Mode
                  </label>
                  <div className="settings-help">
                    Reduces spacing between messages for a more compact view.
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'notifications' && (
              <div className="settings-section">
                <h3>Notification Settings</h3>
                
                <div className="settings-group">
                  <label className="settings-checkbox">
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

                <div className="settings-group">
                  <label className="settings-label">Notification Mode</label>
                  <div className="notification-mode-buttons">
                    {(['all', 'mentions', 'none'] as const).map(mode => (
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
                         'None'}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="settings-group">
                  <label className="settings-checkbox">
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

                <div className="settings-group">
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

            {activeTab === 'voice' && (
              <div className="settings-section">
                <h3>Voice & Audio Settings</h3>
                
                {devicesError && (
                  <div className="settings-error">{devicesError}</div>
                )}
                
                <div className="settings-group">
                  <label className="settings-label">
                    Input Device
                    <select
                      className="settings-select"
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
                  </label>
                </div>

                <div className="settings-group">
                  <label className="settings-label">
                    Output Device
                    <select
                      className="settings-select"
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
                  </label>
                </div>

                <div className="settings-group">
                  <label className="settings-label">
                    Input Volume: {voiceSettings.inputVolume}%
                    <input
                      type="range"
                      className="settings-slider"
                      min="0"
                      max="100"
                      value={voiceSettings.inputVolume}
                      onChange={(e) => saveVoiceSettings({
                        ...voiceSettings,
                        inputVolume: parseInt(e.target.value)
                      })}
                    />
                  </label>
                </div>

                <div className="settings-group">
                  <label className="settings-label">
                    Output Volume: {voiceSettings.outputVolume}%
                    <input
                      type="range"
                      className="settings-slider"
                      min="0"
                      max="100"
                      value={voiceSettings.outputVolume}
                      onChange={(e) => saveVoiceSettings({
                        ...voiceSettings,
                        outputVolume: parseInt(e.target.value)
                      })}
                    />
                  </label>
                </div>

                <div className="settings-group">
                  <label className="settings-label">
                    Voice Activity Sensitivity: {voiceSettings.vadSensitivity}%
                    <input
                      type="range"
                      className="settings-slider"
                      min="0"
                      max="100"
                      value={voiceSettings.vadSensitivity}
                      onChange={(e) => saveVoiceSettings({
                        ...voiceSettings,
                        vadSensitivity: parseInt(e.target.value)
                      })}
                    />
                  </label>
                  <div className="settings-help">
                    Higher values require louder audio to trigger voice activation.
                  </div>
                </div>

                <div className="settings-group">
                  <label className="settings-checkbox">
                    <input
                      type="checkbox"
                      checked={voiceSettings.echoCancellation}
                      onChange={(e) => saveVoiceSettings({
                        ...voiceSettings,
                        echoCancellation: e.target.checked
                      })}
                    />
                    <span className="checkmark"></span>
                    Echo Cancellation
                  </label>
                </div>

                <div className="settings-group">
                  <label className="settings-checkbox">
                    <input
                      type="checkbox"
                      checked={voiceSettings.noiseSuppression}
                      onChange={(e) => saveVoiceSettings({
                        ...voiceSettings,
                        noiseSuppression: e.target.checked
                      })}
                    />
                    <span className="checkmark"></span>
                    Noise Suppression
                  </label>
                </div>

                <div className="settings-group">
                  <label className="settings-checkbox">
                    <input
                      type="checkbox"
                      checked={voiceSettings.autoGainControl}
                      onChange={(e) => saveVoiceSettings({
                        ...voiceSettings,
                        autoGainControl: e.target.checked
                      })}
                    />
                    <span className="checkmark"></span>
                    Automatic Gain Control
                  </label>
                </div>

                <div className="settings-group">
                  <div className="test-buttons">
                    <button
                      className="test-button"
                      onClick={testMicrophone}
                    >
                      Test Microphone
                    </button>
                    <button
                      className="test-button"
                      onClick={testSpeakers}
                    >
                      Test Speakers
                    </button>
                    <button
                      className="refresh-button"
                      onClick={loadMediaDevices}
                    >
                      Refresh Devices
                    </button>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'privacy' && (
              <div className="settings-section">
                <h3>Privacy Settings</h3>
                
                <div className="settings-group">
                  <label className="settings-checkbox">
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
                  <div className="settings-help">
                    Let others know when you've read their messages.
                  </div>
                </div>

                <div className="settings-group">
                  <label className="settings-checkbox">
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
                  <div className="settings-help">
                    Show when you're typing to other users.
                  </div>
                </div>

                <div className="settings-group">
                  <label className="settings-label">Block List</label>
                  <div className="blocked-users">
                    {privacySettings.blockedUsers.length === 0 ? (
                      <div className="settings-help">No blocked users</div>
                    ) : (
                      privacySettings.blockedUsers.map(user => (
                        <div key={user} className="blocked-user">
                          <span>{user}</span>
                          <button
                            className="unblock-button"
                            onClick={() => savePrivacySettings({
                              ...privacySettings,
                              blockedUsers: privacySettings.blockedUsers.filter(u => u !== user)
                            })}
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

            {activeTab === 'about' && (
              <div className="settings-section">
                <h3>About Accord</h3>
                
                <div className="about-content">
                  <div className="about-logo">
                    <div className="app-icon">A</div>
                    <h2>Accord</h2>
                  </div>
                  
                  <div className="about-info">
                    <div className="info-row">
                      <strong>Version:</strong> 1.0.0-alpha
                    </div>
                    <div className="info-row">
                      <strong>Build:</strong> Development
                    </div>
                    <div className="info-row">
                      <strong>Platform:</strong> Desktop (Electron)
                    </div>
                  </div>

                  <div className="about-description">
                    <p>
                      Accord is an open-source chat application focused on privacy, 
                      security, and user control. Built with modern web technologies 
                      and featuring end-to-end encryption.
                    </p>
                  </div>

                  <div className="about-links">
                    <a href="https://github.com/accord-chat/accord" target="_blank" rel="noopener noreferrer">
                      📖 Source Code
                    </a>
                    <a href="https://github.com/accord-chat/accord/issues" target="_blank" rel="noopener noreferrer">
                      🐛 Report Bug
                    </a>
                    <a href="https://github.com/accord-chat/accord/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">
                      📄 License (MIT)
                    </a>
                    <a href="https://discord.gg/accord" target="_blank" rel="noopener noreferrer">
                      💬 Community
                    </a>
                  </div>

                  <div className="about-credits">
                    <h4>Built with ❤️ by the Accord team</h4>
                    <p>Special thanks to all contributors and the open-source community.</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};