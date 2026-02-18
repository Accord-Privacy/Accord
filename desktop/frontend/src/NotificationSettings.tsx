import React from 'react';
import { notificationManager, NotificationPreferences } from './notifications';

interface NotificationSettingsProps {
  isOpen: boolean;
  onClose: () => void;
  preferences: NotificationPreferences;
  onPreferencesChange: (preferences: NotificationPreferences) => void;
}

export const NotificationSettings: React.FC<NotificationSettingsProps> = ({
  isOpen,
  onClose,
  preferences,
  onPreferencesChange
}) => {
  if (!isOpen) return null;

  const handleModeChange = (mode: 'all' | 'mentions' | 'dms' | 'none') => {
    const newPreferences = { ...preferences, mode };
    onPreferencesChange(newPreferences);
  };

  const handleEnabledChange = () => {
    const newPreferences = { ...preferences, enabled: !preferences.enabled };
    onPreferencesChange(newPreferences);
  };

  const handleSoundsChange = () => {
    const newPreferences = { ...preferences, sounds: !preferences.sounds };
    onPreferencesChange(newPreferences);
  };

  const testNotification = () => {
    if ('Notification' in window) {
      if (Notification.permission === 'granted') {
        new Notification('Test Notification', {
          body: 'This is a test notification from Accord!',
          icon: '/favicon.ico'
        });
      } else if (Notification.permission !== 'denied') {
        Notification.requestPermission().then(permission => {
          if (permission === 'granted') {
            new Notification('Test Notification', {
              body: 'This is a test notification from Accord!',
              icon: '/favicon.ico'
            });
          }
        });
      }
    }
  };

  const testSound = () => {
    if (preferences.sounds) {
      // Use the notification manager's sound system
      (notificationManager as any).playNotificationSound();
    }
  };

  const clearAllUnreads = () => {
    notificationManager.clearAllUnreads();
    // Force a re-render by updating preferences (this will trigger parent update)
    onPreferencesChange({ ...preferences });
  };

  return (
    <div className="notification-modal">
      <div className="notification-modal-content">
        <h3 style={{ margin: '0 0 16px 0', color: '#ffffff' }}>
          Notification Settings
        </h3>

        <div className="notification-setting">
          <label>Enable Notifications</label>
          <div
            className={`notification-checkbox ${preferences.enabled ? 'checked' : ''}`}
            onClick={handleEnabledChange}
          >
            {preferences.enabled && '✓'}
          </div>
        </div>

        <div className="notification-setting">
          <label>Notification Mode</label>
          <div style={{ display: 'flex', gap: '4px' }}>
            <button
              className={`notification-toggle ${preferences.mode === 'all' ? 'active' : ''}`}
              onClick={() => handleModeChange('all')}
            >
              All
            </button>
            <button
              className={`notification-toggle ${preferences.mode === 'mentions' ? 'active' : ''}`}
              onClick={() => handleModeChange('mentions')}
            >
              Mentions
            </button>
            <button
              className={`notification-toggle ${preferences.mode === 'dms' ? 'active' : ''}`}
              onClick={() => handleModeChange('dms')}
            >
              DMs
            </button>
            <button
              className={`notification-toggle ${preferences.mode === 'none' ? 'active' : ''}`}
              onClick={() => handleModeChange('none')}
            >
              None
            </button>
          </div>
        </div>

        <div className="notification-setting">
          <label>Sound Notifications</label>
          <div
            className={`notification-checkbox ${preferences.sounds ? 'checked' : ''}`}
            onClick={handleSoundsChange}
          >
            {preferences.sounds && '✓'}
          </div>
        </div>

        <div style={{ marginTop: '24px', paddingTop: '16px', borderTop: '1px solid #40444b' }}>
          <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
            <button
              onClick={testNotification}
              style={{
                flex: 1,
                background: '#7289da',
                border: 'none',
                color: '#ffffff',
                padding: '8px 12px',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '12px'
              }}
            >
              Test Notification
            </button>
            <button
              onClick={testSound}
              style={{
                flex: 1,
                background: '#43b581',
                border: 'none',
                color: '#ffffff',
                padding: '8px 12px',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '12px'
              }}
            >
              Test Sound
            </button>
          </div>
          
          <button
            onClick={clearAllUnreads}
            style={{
              width: '100%',
              background: '#f04747',
              border: 'none',
              color: '#ffffff',
              padding: '8px 12px',
              borderRadius: '4px',
              cursor: 'pointer',
              fontSize: '12px',
              marginBottom: '12px'
            }}
          >
            Clear All Unread Counts
          </button>
        </div>

        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end', marginTop: '16px' }}>
          <button
            onClick={onClose}
            style={{
              background: '#747f8d',
              border: 'none',
              color: '#ffffff',
              padding: '8px 16px',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            Close
          </button>
        </div>

        <div style={{ 
          fontSize: '11px', 
          color: '#72767d', 
          marginTop: '12px',
          lineHeight: '1.4'
        }}>
          <strong>Tips:</strong><br/>
          • Desktop notifications only show when window is not focused<br/>
          • @username and @everyone will be highlighted in messages<br/>
          • Orange badges show mentions, red badges show regular unreads
        </div>
      </div>
    </div>
  );
};