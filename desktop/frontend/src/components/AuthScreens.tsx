import React from "react";
import { useAppContext } from "./AppContext";
import { SetupWizard, SetupResult } from "../SetupWizard";

// Mnemonic backup modal (shown after registration)
export const MnemonicModal: React.FC = () => {
  const ctx = useAppContext();

  return (
    <div className="app">
      <div className="auth-page">
        <div className="auth-card key-backup-card">
          <h2 className="auth-title">🔑 Save Your Recovery Phrase</h2>
          <p className="auth-subtitle">
            This 24-word phrase is the <strong>only way</strong> to recover your identity if you lose access to this browser.
            <strong className="warning" style={{ color: 'var(--yellow)' }}> Write it down and store it safely. It will NOT be shown again.</strong>
          </p>
          <div className="form-group">
            <label className="form-label">Recovery Phrase (24 words)</label>
            <div style={{
              background: 'var(--bg-tertiary)',
              border: '2px solid var(--yellow)',
              borderRadius: '8px',
              padding: '16px',
              fontFamily: 'monospace',
              fontSize: '15px',
              lineHeight: '2',
              wordSpacing: '8px',
              userSelect: 'all',
              cursor: 'text',
            }}>
              {ctx.mnemonicPhrase}
            </div>
          </div>
          <div className="key-backup-actions" style={{ marginTop: '16px' }}>
            <button
              onClick={() => {
                ctx.copyToClipboard(ctx.mnemonicPhrase);
                ctx.setCopyButtonText('Copied!');
                setTimeout(() => ctx.setCopyButtonText('Copy to Clipboard'), 2000);
              }}
              className="btn btn-green"
            >
              {ctx.copyButtonText}
            </button>
            <button
              onClick={() => {
                if (ctx.mnemonicConfirmStep < 2) {
                  ctx.setMnemonicConfirmStep(ctx.mnemonicConfirmStep + 1);
                  return;
                }
                ctx.setShowMnemonicModal(false);
                ctx.setMnemonicPhrase("");
                ctx.setMnemonicConfirmStep(0);
                if (!ctx.isAuthenticated) {
                  ctx.setIsLoginMode(true);
                  ctx.setPassword("");
                  ctx.setAuthError("");
                }
              }}
              className="btn btn-primary"
              style={ctx.mnemonicConfirmStep === 1 ? { background: '#e67e22' } : ctx.mnemonicConfirmStep === 2 ? { background: '#e74c3c' } : {}}
            >
              {ctx.mnemonicConfirmStep === 0
                ? (ctx.isAuthenticated ? 'I\'ve saved my phrase' : 'I\'ve saved my phrase — Continue to Login')
                : ctx.mnemonicConfirmStep === 1
                ? 'Are you absolutely sure?'
                : 'This is your ONLY way to recover your account!'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Recovery modal
export const RecoverModal: React.FC = () => {
  const ctx = useAppContext();

  return (
    <div className="app">
      <div className="auth-page">
        <div className="auth-card">
          <button onClick={() => { ctx.setShowRecoverModal(false); ctx.setRecoverError(""); ctx.setRecoverMnemonic(""); ctx.setRecoverPassword(""); }} className="auth-back-btn">← Back</button>
          <h2 className="auth-title">🔄 Recover Identity</h2>
          <p className="auth-subtitle">Enter your 24-word recovery phrase and password to restore your identity</p>
          
          <div className="form-group">
            <label className="form-label">Recovery Phrase (24 words)</label>
            <textarea
              placeholder="word1 word2 word3 ... word24"
              value={ctx.recoverMnemonic}
              onChange={(e) => ctx.setRecoverMnemonic(e.target.value)}
              rows={3}
              className="form-textarea"
              style={{ fontFamily: 'monospace' }}
            />
          </div>

          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              type="password"
              placeholder="Your account password"
              value={ctx.recoverPassword}
              onChange={(e) => ctx.setRecoverPassword(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleRecover(); }}
              className="form-input"
            />
          </div>

          {ctx.recoverError && <div className="auth-error">{ctx.recoverError}</div>}

          <button
            onClick={ctx.handleRecover}
            disabled={ctx.recoverLoading || !ctx.recoverMnemonic.trim() || !ctx.recoverPassword}
            className="btn btn-primary"
          >
            {ctx.recoverLoading ? 'Recovering...' : 'Recover Identity'}
          </button>
        </div>
      </div>
    </div>
  );
};

// Key backup screen
export const KeyBackupScreen: React.FC = () => {
  const ctx = useAppContext();

  return (
    <div className="app">
      <div className="auth-page">
        <div className="auth-card key-backup-card">
          <h2 className="auth-title">🔑 Backup Your Key</h2>
          <p className="auth-subtitle">
            Your identity is your keypair. If you lose it, you lose access to your account forever.
            <strong className="warning" style={{ color: 'var(--yellow)' }}> There is no recovery.</strong>
          </p>
          <div className="form-group">
            <label className="form-label">Your Public Key Fingerprint</label>
            <div className="key-value">{ctx.publicKeyHash || 'computing...'}</div>
          </div>
          <div className="form-group">
            <label className="form-label">Public Key (share this)</label>
            <textarea
              readOnly
              value={ctx.publicKey}
              rows={3}
              className="form-textarea"
            />
          </div>
          <div className="auth-success" style={{ marginBottom: '16px' }}>
            ✅ Your keypair is saved in this browser's storage. To use Accord on another device, you'll need to export and import your key.
          </div>
          <div className="key-backup-actions">
            <button
              onClick={() => {
                ctx.copyToClipboard(ctx.publicKey);
                alert('Public key copied to clipboard!');
              }}
              className="btn btn-green"
            >
              Copy Public Key
            </button>
            <button
              onClick={() => {
                ctx.setShowKeyBackup(false);
                ctx.setIsLoginMode(true);
                ctx.setPassword("");
                ctx.setAuthError("");
              }}
              className="btn btn-primary"
            >
              Continue to Login
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Welcome / Invite screen
export const WelcomeScreen: React.FC = () => {
  const ctx = useAppContext();

  return (
    <div className="app">
      <div className="auth-page">
        <div className="auth-card auth-card-narrow">
          
          {ctx.welcomeMode === 'choose' && (
            <>
              <div className="auth-brand">
                <h1><img src="/logo.png" alt="Accord" style={{width: '48px', height: '48px', verticalAlign: 'middle', marginRight: '12px', borderRadius: '8px'}} /><span className="brand-accent">Accord</span></h1>
              </div>
              <p className="auth-tagline">Privacy-first community communications</p>
              <div className="auth-buttons-stack">
                {ctx.serverAvailable ? (
                  <>
                    <button onClick={() => { ctx.setShowWelcomeScreen(false); ctx.setIsLoginMode(true); }} className="btn btn-primary">
                      Log in
                    </button>
                    <button onClick={() => { ctx.setShowWelcomeScreen(false); ctx.setIsLoginMode(false); }} className="btn btn-outline">
                      Create new identity
                    </button>
                    <button onClick={() => ctx.setWelcomeMode('invite')} className="btn btn-outline">
                      I have an invite link
                    </button>
                    <button onClick={() => { ctx.setShowWelcomeScreen(false); ctx.setShowRecoverModal(true); ctx.setRecoverError(""); }} className="btn-ghost" style={{ fontSize: '13px', marginTop: '8px', opacity: 0.8 }}>
                      🔄 Recover identity with recovery phrase
                    </button>
                  </>
                ) : (
                  <>
                    <button onClick={() => ctx.setWelcomeMode('invite')} className="btn btn-primary">
                      I have an invite link
                    </button>
                    <button onClick={() => ctx.setWelcomeMode('admin')} className="btn btn-outline">
                      Set up a new relay (admin)
                    </button>
                    <button onClick={() => ctx.setWelcomeMode('recover')} className="btn-ghost" style={{ fontSize: '13px', marginTop: '8px', opacity: 0.8 }}>
                      🔄 Recover identity (connect to relay first)
                    </button>
                  </>
                )}
              </div>
            </>
          )}

          {ctx.welcomeMode === 'invite' && !ctx.inviteNeedsRegister && (
            <>
              <button onClick={() => { ctx.setWelcomeMode('choose'); ctx.setInviteError(''); ctx.setInviteLinkInput(''); ctx.setAuthError(''); }} className="auth-back-btn">← Back</button>
              <h2 className="auth-title">Join via Invite</h2>
              <p className="auth-subtitle">Paste the invite link you received</p>
              
              <div className="form-group">
                <input
                  type="text"
                  placeholder="accord://host:port/invite/CODE or https://..."
                  value={ctx.inviteLinkInput}
                  onChange={(e) => ctx.setInviteLinkInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleInviteLinkSubmit(); }}
                  className="form-input"
                />
              </div>

              {ctx.inviteError && <div className="auth-error">{ctx.inviteError}</div>}
              {ctx.inviteRelayVersion && <div className="auth-success">✅ Connected to relay v{ctx.inviteRelayVersion}</div>}

              <button
                onClick={ctx.handleInviteLinkSubmit}
                disabled={ctx.inviteConnecting || !ctx.inviteLinkInput.trim()}
                className="btn btn-primary"
              >
                {ctx.inviteConnecting ? 'Connecting to relay...' : 'Join'}
              </button>
            </>
          )}

          {ctx.welcomeMode === 'invite' && ctx.inviteNeedsRegister && (
            <>
              <h2 className="auth-title">Create Your Identity</h2>
              <p className="auth-subtitle">Connected to relay — now set a password to create your identity</p>
              <div className="auth-info-box">
                <span className="accent">🔐 A keypair will be auto-generated. No username needed.</span>
              </div>

              <div className="form-group">
                <label className="form-label">Display Name <span style={{ color: "var(--accent)" }}>*</span></label>
                <input
                  type="text"
                  placeholder="How others will see you (required)"
                  required
                  value={ctx.inviteDisplayName ?? ''}
                  onChange={(e) => ctx.setInviteDisplayName(e.target.value)}
                  className="form-input"
                />
              </div>

              <div className="form-group">
                <label className="form-label">Password (min 8 characters)</label>
                <input
                  type="password"
                  placeholder="Choose a password"
                  value={ctx.invitePassword}
                  onChange={(e) => ctx.setInvitePassword(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleInviteRegister(); }}
                  className="form-input"
                />
              </div>

              {ctx.inviteError && <div className="auth-error">{ctx.inviteError}</div>}

              <button
                onClick={ctx.handleInviteRegister}
                disabled={ctx.inviteJoining || ctx.invitePassword.length < 8}
                className="btn btn-green"
              >
                {ctx.inviteJoining ? 'Creating identity & joining...' : 'Create Identity & Join'}
              </button>
            </>
          )}

          {(ctx.welcomeMode === 'admin' || ctx.welcomeMode === 'recover') && (
            <>
              <button onClick={() => { ctx.setWelcomeMode('choose'); ctx.setAuthError(''); }} className="auth-back-btn">← Back</button>
              <h2 className="auth-title">{ctx.welcomeMode === 'recover' ? 'Connect to Relay' : 'Connect to Relay'}</h2>
              <p className="auth-subtitle">{ctx.welcomeMode === 'recover' ? 'Enter your relay URL to recover your identity' : 'Enter the relay server URL (admin/power-user)'}</p>
              
              <div className="form-group">
                <label className="form-label">Server URL</label>
                <input
                  type="text"
                  placeholder="http://localhost:8080"
                  value={ctx.serverUrl}
                  onChange={(e) => ctx.setServerUrl(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleServerConnect(); }}
                  className="form-input"
                />
              </div>

              {ctx.authError && <div className="auth-error">{ctx.authError}</div>}
              {ctx.serverVersion && <div className="auth-success">✅ Connected — server v{ctx.serverVersion}</div>}

              {!ctx.serverVersion ? (
                <button
                  onClick={ctx.handleServerConnect}
                  disabled={ctx.serverConnecting}
                  className="btn btn-primary"
                >
                  {ctx.serverConnecting ? 'Connecting...' : 'Connect'}
                </button>
              ) : ctx.welcomeMode === 'recover' ? (
                <button
                  onClick={() => { ctx.setShowWelcomeScreen(false); ctx.setShowRecoverModal(true); ctx.setRecoverError(''); }}
                  className="btn btn-green"
                >
                  Continue to Recovery
                </button>
              ) : (
                <button
                  onClick={ctx.handleServerConnect}
                  disabled={ctx.serverConnecting}
                  className="btn btn-primary"
                >
                  {ctx.serverConnecting ? 'Connecting...' : 'Connect'}
                </button>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};

// Server connection screen (legacy)
export const ServerConnectScreen: React.FC = () => {
  const ctx = useAppContext();

  return (
    <div className="app">
      <div className="auth-page">
        <div className="auth-card auth-card-narrow">
          <h2 className="auth-title">Connect to Relay</h2>
          <p className="auth-subtitle">Manual relay connection</p>
          
          <div className="form-group">
            <label className="form-label">Server URL</label>
            <input
              type="text"
              placeholder="http://localhost:8080"
              value={ctx.serverUrl}
              onChange={(e) => ctx.setServerUrl(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleServerConnect(); }}
              className="form-input"
            />
          </div>

          {ctx.authError && <div className="auth-error">{ctx.authError}</div>}
          {ctx.serverVersion && <div className="auth-success">✅ Connected — server v{ctx.serverVersion}</div>}

          <button
            onClick={ctx.handleServerConnect}
            disabled={ctx.serverConnecting}
            className="btn btn-primary"
          >
            {ctx.serverConnecting ? 'Connecting...' : 'Connect'}
          </button>
        </div>
      </div>
    </div>
  );
};

// Login / Register screen
export const LoginScreen: React.FC = () => {
  const ctx = useAppContext();

  return (
    <div className="app">
      <div className="auth-page">
        <div className="auth-card">
          <h2 className="auth-title">
            {ctx.isLoginMode ? (ctx.hasExistingKey ? 'Welcome Back' : 'Login to Accord') : 'Create Identity'}
          </h2>
          <p className="auth-subtitle">
            {ctx.isLoginMode 
              ? (ctx.hasExistingKey ? 'Enter your password to sign back in' : 'Authenticate with your keypair and password')
              : 'A new keypair will be generated automatically'}
          </p>
          
          {ctx.serverAvailable && (
            <div className="auth-server-bar">
              <span>● Connected</span>
            </div>
          )}

          {ctx.isLoginMode && (
            <div className="form-group">
              <label className="form-label">Key Status</label>
              <div className="auth-info-box">
                {ctx.keyPair || ctx.publicKey || ctx.hasExistingKey ? (
                  <span className="accent">🔑 Keypair found — enter your password to sign back in</span>
                ) : localStorage.getItem('accord_public_key_plain') ? (
                  <span className="accent">🔑 Identity remembered — enter your password to log in</span>
                ) : (
                  <span style={{ color: 'var(--yellow)' }}>⚠️ No identity found on this device — create a new one or recover with your phrase</span>
                )}
              </div>
            </div>
          )}

          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              type="password"
              placeholder={ctx.isLoginMode ? "Enter your password" : "Choose a password (min 8 chars)"}
              value={ctx.password}
              onChange={(e) => ctx.setPassword(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleAuth(); }}
              className="form-input"
            />
            {!ctx.isLoginMode && ctx.password && ctx.password.length < 8 && (
              <div className="form-hint" style={{ color: 'var(--red)' }}>
                Password must be at least 8 characters
              </div>
            )}
          </div>

          {!ctx.isLoginMode && ctx.encryptionEnabled && (
            <div className="auth-info-box" style={{ marginBottom: '20px' }}>
              <div className="accent">🔐 A new ECDH P-256 keypair will be generated for your identity</div>
              <div style={{ fontSize: '12px', marginTop: '4px' }}>No username needed — you are identified by your public key hash</div>
            </div>
          )}

          {ctx.authError && <div className="auth-error">{ctx.authError}</div>}

          <button onClick={ctx.handleAuth} className="btn btn-primary" style={{ marginBottom: '16px' }}>
            {ctx.isLoginMode ? 'Login' : 'Create Identity & Register'}
          </button>

          <div className="auth-toggle" style={{ display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'center' }}>
            <button
              onClick={() => { ctx.setIsLoginMode(!ctx.isLoginMode); ctx.setAuthError(""); ctx.setPassword(""); }}
              className="btn-ghost"
            >
              {ctx.isLoginMode ? 'Need to create an identity?' : 'Already have a keypair? Login'}
            </button>
            
            <div style={{ borderTop: '1px solid var(--border)', width: '100%', paddingTop: '12px', marginTop: '4px', display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'center' }}>
              <span style={{ fontSize: '12px', opacity: 0.6 }}>Lost access to your keypair?</span>
              <button
                onClick={() => { ctx.setShowRecoverModal(true); ctx.setRecoverError(""); }}
                className="btn btn-outline"
                style={{ width: '100%' }}
              >
                🔄 Recover with recovery phrase
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Re-export SetupWizard wrapper
export { SetupWizard };
export type { SetupResult };
