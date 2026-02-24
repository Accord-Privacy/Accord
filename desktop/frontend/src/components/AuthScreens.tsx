import React from "react";
import clsx from "clsx";
import { useAppContext } from "./AppContext";
import { SetupWizard, SetupResult } from "../SetupWizard";
import authStyles from "../components/layout/AuthLayout.module.css";
import btnStyles from "../components/uikit/button/Button.module.css";

// Mnemonic backup modal (shown after registration)
export const MnemonicModal: React.FC = () => {
  const ctx = useAppContext();

  return (
    <div className={authStyles.scrollerWrapper}>
      <div className={authStyles.container}>
        <div className={authStyles.cardContainer}>
          <div className={clsx(authStyles.card, authStyles.cardSingle)}>
            <div className={authStyles.formSideSingle} style={{ padding: '3rem' }}>
              <h2 style={{ color: 'var(--text-primary)', fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>🔑 Save Your Recovery Phrase</h2>
              <p style={{ color: 'var(--text-tertiary-muted)', fontSize: '14px', lineHeight: 1.5, marginBottom: '24px' }}>
                This 24-word phrase is the <strong>only way</strong> to recover your identity if you lose access to this browser.
                <strong style={{ color: 'var(--yellow, #f59e0b)' }}> Write it down and store it safely. It will NOT be shown again.</strong>
              </p>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.02em', color: 'var(--text-tertiary-muted)', display: 'block', marginBottom: '6px' }}>Recovery Phrase (24 words)</label>
                <div style={{
                  background: 'var(--background-tertiary)',
                  border: '2px solid var(--yellow, #f59e0b)',
                  borderRadius: '8px',
                  padding: '16px',
                  fontFamily: 'monospace',
                  fontSize: '15px',
                  lineHeight: '2',
                  wordSpacing: '8px',
                  userSelect: 'all',
                  cursor: 'text',
                  color: 'var(--text-primary)',
                }}>
                  {ctx.mnemonicPhrase}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '8px', marginTop: '16px' }}>
                <button
                  onClick={() => {
                    ctx.copyToClipboard(ctx.mnemonicPhrase);
                    ctx.setCopyButtonText('Copied!');
                    setTimeout(() => ctx.setCopyButtonText('Copy to Clipboard'), 2000);
                  }}
                  className={clsx(btnStyles.button, btnStyles.secondary)}
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
                  className={clsx(btnStyles.button, ctx.mnemonicConfirmStep >= 1 ? btnStyles.dangerPrimary : btnStyles.primary)}
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
      </div>
    </div>
  );
};

// Recovery modal
export const RecoverModal: React.FC = () => {
  const ctx = useAppContext();

  return (
    <div className={authStyles.scrollerWrapper}>
      <div className={authStyles.container}>
        <div className={authStyles.cardContainer}>
          <div className={clsx(authStyles.card, authStyles.cardSingle)}>
            <div className={authStyles.formSideSingle} style={{ padding: '3rem' }}>
              <button onClick={() => { ctx.setShowRecoverModal(false); ctx.setRecoverError(""); ctx.setRecoverMnemonic(""); ctx.setRecoverPassword(""); }} className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.compact, btnStyles.fitContent)} style={{ marginBottom: '16px' }}>← Back</button>
              <h2 style={{ color: 'var(--text-primary)', fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>🔄 Recover Identity</h2>
              <p style={{ color: 'var(--text-tertiary-muted)', fontSize: '14px', lineHeight: 1.5, marginBottom: '24px' }}>Enter your 24-word recovery phrase and password to restore your identity</p>
              
              <div style={{ marginBottom: '16px' }}>
                <label style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.02em', color: 'var(--text-tertiary-muted)', display: 'block', marginBottom: '6px' }}>Recovery Phrase (24 words)</label>
                <textarea
                  placeholder="word1 word2 word3 ... word24"
                  value={ctx.recoverMnemonic}
                  onChange={(e) => ctx.setRecoverMnemonic(e.target.value)}
                  rows={3}
                  style={{ width: '100%', padding: '10px 12px', fontSize: '14px', backgroundColor: 'var(--background-tertiary)', border: '1px solid transparent', borderRadius: '6px', color: 'var(--text-primary)', outline: 'none', resize: 'vertical', fontFamily: 'monospace', boxSizing: 'border-box' }}
                />
              </div>

              <div style={{ marginBottom: '16px' }}>
                <label style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.02em', color: 'var(--text-tertiary-muted)', display: 'block', marginBottom: '6px' }}>Password</label>
                <input
                  type="password"
                  placeholder="Your account password"
                  value={ctx.recoverPassword}
                  onChange={(e) => ctx.setRecoverPassword(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleRecover(); }}
                  style={{ width: '100%', padding: '10px 12px', fontSize: '14px', backgroundColor: 'var(--background-tertiary)', border: '1px solid transparent', borderRadius: '6px', color: 'var(--text-primary)', outline: 'none', boxSizing: 'border-box' }}
                />
              </div>

              {ctx.recoverError && <div style={{ color: 'var(--red)', fontSize: '13px', marginBottom: '12px', padding: '8px 12px', background: 'rgba(237,66,69,0.1)', borderRadius: '6px' }}>{ctx.recoverError}</div>}

              <button
                onClick={ctx.handleRecover}
                disabled={ctx.recoverLoading || !ctx.recoverMnemonic.trim() || !ctx.recoverPassword}
                className={clsx(btnStyles.button, btnStyles.primary, btnStyles.fitContainer)}
              >
                {ctx.recoverLoading ? 'Recovering...' : 'Recover Identity'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Key backup screen
export const KeyBackupScreen: React.FC = () => {
  const ctx = useAppContext();

  return (
    <div className={authStyles.scrollerWrapper}>
      <div className={authStyles.container}>
        <div className={authStyles.cardContainer}>
          <div className={clsx(authStyles.card, authStyles.cardSingle)}>
            <div className={authStyles.formSideSingle} style={{ padding: '3rem' }}>
              <h2 style={{ color: 'var(--text-primary)', fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>🔑 Backup Your Key</h2>
              <p style={{ color: 'var(--text-tertiary-muted)', fontSize: '14px', lineHeight: 1.5, marginBottom: '24px' }}>
                Your identity is your keypair. If you lose it, you lose access to your account forever.
                <strong style={{ color: 'var(--yellow, #f59e0b)' }}> There is no recovery.</strong>
              </p>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.02em', color: 'var(--text-tertiary-muted)', display: 'block', marginBottom: '6px' }}>Your Public Key Fingerprint</label>
                <div style={{ padding: '10px 12px', background: 'var(--background-tertiary)', borderRadius: '6px', fontFamily: 'monospace', fontSize: '13px', color: 'var(--text-primary)' }}>{ctx.publicKeyHash || 'computing...'}</div>
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.02em', color: 'var(--text-tertiary-muted)', display: 'block', marginBottom: '6px' }}>Public Key (share this)</label>
                <textarea
                  readOnly
                  value={ctx.publicKey}
                  rows={3}
                  style={{ width: '100%', padding: '10px 12px', fontSize: '14px', backgroundColor: 'var(--background-tertiary)', border: '1px solid transparent', borderRadius: '6px', color: 'var(--text-primary)', outline: 'none', resize: 'none', fontFamily: 'monospace', boxSizing: 'border-box' }}
                />
              </div>
              <div style={{ color: 'var(--accent-success, #16a34a)', marginBottom: '16px', fontSize: '14px', padding: '10px 12px', background: 'rgba(22,163,74,0.1)', borderRadius: '6px' }}>
                ✅ Your keypair is saved in this browser's storage. To use Accord on another device, you'll need to export and import your key.
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  onClick={() => { ctx.copyToClipboard(ctx.publicKey); alert('Public key copied to clipboard!'); }}
                  className={clsx(btnStyles.button, btnStyles.secondary)}
                >
                  Copy Public Key
                </button>
                <button
                  onClick={() => { ctx.setShowKeyBackup(false); ctx.setIsLoginMode(true); ctx.setPassword(""); ctx.setAuthError(""); }}
                  className={clsx(btnStyles.button, btnStyles.primary)}
                >
                  Continue to Login
                </button>
              </div>
            </div>
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
    <div className={authStyles.scrollerWrapper}>
      <div className={authStyles.container}>
        <div className={authStyles.cardContainer}>
          <div className={clsx(authStyles.card, authStyles.cardSingle)}>
            <div className={authStyles.formSideSingle} style={{ padding: '3rem' }}>
              
              {ctx.welcomeMode === 'choose' && (
                <>
                  <div style={{ textAlign: 'center', marginBottom: '24px' }}>
                    <h1 style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px', color: 'var(--text-primary)', fontSize: '28px', fontWeight: 700, margin: 0 }}>
                      <img src="/logo.png" alt="Accord" style={{ width: '48px', height: '48px', borderRadius: '8px' }} />
                      <span style={{ color: 'var(--accent)' }}>Accord</span>
                    </h1>
                  </div>
                  <p style={{ textAlign: 'center', color: 'var(--text-tertiary-muted)', fontSize: '14px', marginBottom: '24px' }}>Privacy-first community communications</p>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {ctx.serverAvailable ? (
                      <>
                        <button onClick={() => { ctx.setShowWelcomeScreen(false); ctx.setIsLoginMode(true); }} className={clsx(btnStyles.button, btnStyles.primary, btnStyles.fitContainer)}>Log in</button>
                        <button onClick={() => { ctx.setShowWelcomeScreen(false); ctx.setIsLoginMode(false); }} className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.fitContainer)}>Create new identity</button>
                        <button onClick={() => ctx.setWelcomeMode('invite')} className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.fitContainer)}>I have an invite link</button>
                        <button onClick={() => { ctx.setShowWelcomeScreen(false); ctx.setShowRecoverModal(true); ctx.setRecoverError(""); }} className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.compact, btnStyles.fitContainer)} style={{ marginTop: '8px', opacity: 0.8 }}>🔄 Recover identity with recovery phrase</button>
                      </>
                    ) : (
                      <>
                        <button onClick={() => ctx.setWelcomeMode('invite')} className={clsx(btnStyles.button, btnStyles.primary, btnStyles.fitContainer)}>I have an invite link</button>
                        <button onClick={() => ctx.setWelcomeMode('admin')} className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.fitContainer)}>Set up a new relay (admin)</button>
                        <button onClick={() => ctx.setWelcomeMode('recover')} className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.compact, btnStyles.fitContainer)} style={{ marginTop: '8px', opacity: 0.8 }}>🔄 Recover identity (connect to relay first)</button>
                      </>
                    )}
                  </div>
                </>
              )}

              {ctx.welcomeMode === 'invite' && !ctx.inviteNeedsRegister && (
                <>
                  <button onClick={() => { ctx.setWelcomeMode('choose'); ctx.setInviteError(''); ctx.setInviteLinkInput(''); ctx.setAuthError(''); }} className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.compact, btnStyles.fitContent)} style={{ marginBottom: '16px' }}>← Back</button>
                  <h2 style={{ color: 'var(--text-primary)', fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>Join via Invite</h2>
                  <p style={{ color: 'var(--text-tertiary-muted)', fontSize: '14px', marginBottom: '20px' }}>Paste the invite link you received</p>
                  
                  <div style={{ marginBottom: '16px' }}>
                    <input
                      type="text"
                      placeholder="accord://host:port/invite/CODE or https://..."
                      value={ctx.inviteLinkInput}
                      onChange={(e) => ctx.setInviteLinkInput(e.target.value)}
                      onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleInviteLinkSubmit(); }}
                      style={{ width: '100%', padding: '10px 12px', fontSize: '14px', backgroundColor: 'var(--background-tertiary)', border: '1px solid transparent', borderRadius: '6px', color: 'var(--text-primary)', outline: 'none', boxSizing: 'border-box' }}
                    />
                  </div>

                  {ctx.inviteError && <div style={{ color: 'var(--red)', fontSize: '13px', marginBottom: '12px', padding: '8px 12px', background: 'rgba(237,66,69,0.1)', borderRadius: '6px' }}>{ctx.inviteError}</div>}
                  {ctx.inviteRelayVersion && <div style={{ color: 'var(--accent-success, #16a34a)', fontSize: '13px', marginBottom: '12px', padding: '8px 12px', background: 'rgba(22,163,74,0.1)', borderRadius: '6px' }}>✅ Connected to relay v{ctx.inviteRelayVersion}</div>}

                  <button
                    onClick={ctx.handleInviteLinkSubmit}
                    disabled={ctx.inviteConnecting || !ctx.inviteLinkInput.trim()}
                    className={clsx(btnStyles.button, btnStyles.primary, btnStyles.fitContainer)}
                  >
                    {ctx.inviteConnecting ? 'Connecting to relay...' : 'Join'}
                  </button>
                </>
              )}

              {ctx.welcomeMode === 'invite' && ctx.inviteNeedsRegister && (
                <>
                  <h2 style={{ color: 'var(--text-primary)', fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>Create Your Identity</h2>
                  <p style={{ color: 'var(--text-tertiary-muted)', fontSize: '14px', marginBottom: '12px' }}>Connected to relay — now set a password to create your identity</p>
                  <div style={{ padding: '10px 12px', background: 'rgba(var(--accent-rgb, 88,101,242), 0.1)', borderRadius: '6px', marginBottom: '20px', fontSize: '14px', color: 'var(--accent)' }}>🔐 A keypair will be auto-generated. No username needed.</div>

                  <div style={{ marginBottom: '16px' }}>
                    <label style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.02em', color: 'var(--text-tertiary-muted)', display: 'block', marginBottom: '6px' }}>Display Name <span style={{ color: 'var(--accent)' }}>*</span></label>
                    <input type="text" placeholder="How others will see you (required)" required value={ctx.inviteDisplayName ?? ''} onChange={(e) => ctx.setInviteDisplayName(e.target.value)} style={{ width: '100%', padding: '10px 12px', fontSize: '14px', backgroundColor: 'var(--background-tertiary)', border: '1px solid transparent', borderRadius: '6px', color: 'var(--text-primary)', outline: 'none', boxSizing: 'border-box' }} />
                  </div>

                  <div style={{ marginBottom: '16px' }}>
                    <label style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.02em', color: 'var(--text-tertiary-muted)', display: 'block', marginBottom: '6px' }}>Password (min 8 characters)</label>
                    <input type="password" placeholder="Choose a password" value={ctx.invitePassword} onChange={(e) => ctx.setInvitePassword(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleInviteRegister(); }} style={{ width: '100%', padding: '10px 12px', fontSize: '14px', backgroundColor: 'var(--background-tertiary)', border: '1px solid transparent', borderRadius: '6px', color: 'var(--text-primary)', outline: 'none', boxSizing: 'border-box' }} />
                  </div>

                  {ctx.inviteError && <div style={{ color: 'var(--red)', fontSize: '13px', marginBottom: '12px', padding: '8px 12px', background: 'rgba(237,66,69,0.1)', borderRadius: '6px' }}>{ctx.inviteError}</div>}

                  <button
                    onClick={ctx.handleInviteRegister}
                    disabled={ctx.inviteJoining || ctx.invitePassword.length < 8}
                    className={clsx(btnStyles.button, btnStyles.primary, btnStyles.fitContainer)}
                  >
                    {ctx.inviteJoining ? 'Creating identity & joining...' : 'Create Identity & Join'}
                  </button>
                </>
              )}

              {(ctx.welcomeMode === 'admin' || ctx.welcomeMode === 'recover') && (
                <>
                  <button onClick={() => { ctx.setWelcomeMode('choose'); ctx.setAuthError(''); }} className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.compact, btnStyles.fitContent)} style={{ marginBottom: '16px' }}>← Back</button>
                  <h2 style={{ color: 'var(--text-primary)', fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>{ctx.welcomeMode === 'recover' ? 'Connect to Relay' : 'Connect to Relay'}</h2>
                  <p style={{ color: 'var(--text-tertiary-muted)', fontSize: '14px', marginBottom: '20px' }}>{ctx.welcomeMode === 'recover' ? 'Enter your relay URL to recover your identity' : 'Enter the relay server URL (admin/power-user)'}</p>
                  
                  <div style={{ marginBottom: '16px' }}>
                    <label style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.02em', color: 'var(--text-tertiary-muted)', display: 'block', marginBottom: '6px' }}>Server URL</label>
                    <input type="text" placeholder="http://localhost:8080" value={ctx.serverUrl} onChange={(e) => ctx.setServerUrl(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleServerConnect(); }} style={{ width: '100%', padding: '10px 12px', fontSize: '14px', backgroundColor: 'var(--background-tertiary)', border: '1px solid transparent', borderRadius: '6px', color: 'var(--text-primary)', outline: 'none', boxSizing: 'border-box' }} />
                  </div>

                  {ctx.authError && <div style={{ color: 'var(--red)', fontSize: '13px', marginBottom: '12px', padding: '8px 12px', background: 'rgba(237,66,69,0.1)', borderRadius: '6px' }}>{ctx.authError}</div>}
                  {ctx.serverVersion && <div style={{ color: 'var(--accent-success, #16a34a)', fontSize: '13px', marginBottom: '12px', padding: '8px 12px', background: 'rgba(22,163,74,0.1)', borderRadius: '6px' }}>✅ Connected — server v{ctx.serverVersion}</div>}

                  {!ctx.serverVersion ? (
                    <button onClick={ctx.handleServerConnect} disabled={ctx.serverConnecting} className={clsx(btnStyles.button, btnStyles.primary, btnStyles.fitContainer)}>
                      {ctx.serverConnecting ? 'Connecting...' : 'Connect'}
                    </button>
                  ) : ctx.welcomeMode === 'recover' ? (
                    <button onClick={() => { ctx.setShowWelcomeScreen(false); ctx.setShowRecoverModal(true); ctx.setRecoverError(''); }} className={clsx(btnStyles.button, btnStyles.primary, btnStyles.fitContainer)}>
                      Continue to Recovery
                    </button>
                  ) : (
                    <button onClick={ctx.handleServerConnect} disabled={ctx.serverConnecting} className={clsx(btnStyles.button, btnStyles.primary, btnStyles.fitContainer)}>
                      {ctx.serverConnecting ? 'Connecting...' : 'Connect'}
                    </button>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Server connection screen (legacy)
export const ServerConnectScreen: React.FC = () => {
  const ctx = useAppContext();

  return (
    <div className={authStyles.scrollerWrapper}>
      <div className={authStyles.container}>
        <div className={authStyles.cardContainer}>
          <div className={clsx(authStyles.card, authStyles.cardSingle)}>
            <div className={authStyles.formSideSingle} style={{ padding: '3rem' }}>
              <h2 style={{ color: 'var(--text-primary)', fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>Connect to Relay</h2>
              <p style={{ color: 'var(--text-tertiary-muted)', fontSize: '14px', marginBottom: '20px' }}>Manual relay connection</p>
              
              <div style={{ marginBottom: '16px' }}>
                <label style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.02em', color: 'var(--text-tertiary-muted)', display: 'block', marginBottom: '6px' }}>Server URL</label>
                <input type="text" placeholder="http://localhost:8080" value={ctx.serverUrl} onChange={(e) => ctx.setServerUrl(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleServerConnect(); }} style={{ width: '100%', padding: '10px 12px', fontSize: '14px', backgroundColor: 'var(--background-tertiary)', border: '1px solid transparent', borderRadius: '6px', color: 'var(--text-primary)', outline: 'none', boxSizing: 'border-box' }} />
              </div>

              {ctx.authError && <div style={{ color: 'var(--red)', fontSize: '13px', marginBottom: '12px', padding: '8px 12px', background: 'rgba(237,66,69,0.1)', borderRadius: '6px' }}>{ctx.authError}</div>}
              {ctx.serverVersion && <div style={{ color: 'var(--accent-success, #16a34a)', fontSize: '13px', marginBottom: '12px', padding: '8px 12px', background: 'rgba(22,163,74,0.1)', borderRadius: '6px' }}>✅ Connected — server v{ctx.serverVersion}</div>}

              <button onClick={ctx.handleServerConnect} disabled={ctx.serverConnecting} className={clsx(btnStyles.button, btnStyles.primary, btnStyles.fitContainer)}>
                {ctx.serverConnecting ? 'Connecting...' : 'Connect'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Login / Register screen
export const LoginScreen: React.FC = () => {
  const ctx = useAppContext();

  return (
    <div className={authStyles.scrollerWrapper}>
      <div className={authStyles.container}>
        <div className={authStyles.cardContainer}>
          <div className={clsx(authStyles.card, authStyles.cardSingle)}>
            <div className={authStyles.formSideSingle} style={{ padding: '3rem' }}>
              <h2 style={{ color: 'var(--text-primary)', fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>
                {ctx.isLoginMode ? (ctx.hasExistingKey ? 'Welcome Back' : 'Login to Accord') : 'Create Identity'}
              </h2>
              <p style={{ color: 'var(--text-tertiary-muted)', fontSize: '14px', lineHeight: 1.5, marginBottom: '24px' }}>
                {ctx.isLoginMode 
                  ? (ctx.hasExistingKey ? 'Enter your password to sign back in' : 'Authenticate with your keypair and password')
                  : 'A new keypair will be generated automatically'}
              </p>
              
              {ctx.serverAvailable && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--accent-success, #16a34a)', marginBottom: '16px' }}>
                  <span>● Connected</span>
                </div>
              )}

              {ctx.isLoginMode && (
                <div style={{ marginBottom: '20px' }}>
                  <label style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.02em', color: 'var(--text-tertiary-muted)', display: 'block', marginBottom: '6px' }}>Key Status</label>
                  <div style={{ padding: '10px 12px', background: 'var(--background-tertiary)', borderRadius: '6px', fontSize: '14px' }}>
                    {ctx.keyPair || ctx.publicKey || ctx.hasExistingKey ? (
                      <span style={{ color: 'var(--accent)' }}>🔑 Keypair found — enter your password to sign back in</span>
                    ) : localStorage.getItem('accord_public_key_plain') ? (
                      <span style={{ color: 'var(--accent)' }}>🔑 Identity remembered — enter your password to log in</span>
                    ) : (
                      <span style={{ color: 'var(--yellow, #f59e0b)' }}>⚠️ No identity found on this device — create a new one or recover with your phrase</span>
                    )}
                  </div>
                </div>
              )}

              <div style={{ marginBottom: '16px' }}>
                <label style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.02em', color: 'var(--text-tertiary-muted)', display: 'block', marginBottom: '6px' }}>Password</label>
                <input
                  type="password"
                  placeholder={ctx.isLoginMode ? "Enter your password" : "Choose a password (min 8 chars)"}
                  value={ctx.password}
                  onChange={(e) => ctx.setPassword(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') ctx.handleAuth(); }}
                  style={{ width: '100%', padding: '10px 12px', fontSize: '14px', backgroundColor: 'var(--background-tertiary)', border: '1px solid transparent', borderRadius: '6px', color: 'var(--text-primary)', outline: 'none', boxSizing: 'border-box' }}
                />
                {!ctx.isLoginMode && ctx.password && ctx.password.length < 8 && (
                  <div style={{ color: 'var(--red)', fontSize: '12px', marginTop: '4px' }}>Password must be at least 8 characters</div>
                )}
              </div>

              {!ctx.isLoginMode && ctx.encryptionEnabled && (
                <div style={{ padding: '10px 12px', background: 'var(--background-tertiary)', borderRadius: '6px', marginBottom: '20px', fontSize: '14px' }}>
                  <div style={{ color: 'var(--accent)' }}>🔐 A new ECDH P-256 keypair will be generated for your identity</div>
                  <div style={{ fontSize: '12px', marginTop: '4px', color: 'var(--text-tertiary-muted)' }}>No username needed — you are identified by your public key hash</div>
                </div>
              )}

              {ctx.authError && <div style={{ color: 'var(--red)', fontSize: '13px', marginBottom: '12px', padding: '8px 12px', background: 'rgba(237,66,69,0.1)', borderRadius: '6px' }}>{ctx.authError}</div>}

              <button onClick={ctx.handleAuth} className={clsx(btnStyles.button, btnStyles.primary, btnStyles.fitContainer)} style={{ marginBottom: '16px' }}>
                {ctx.isLoginMode ? 'Login' : 'Create Identity & Register'}
              </button>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'center' }}>
                <button
                  onClick={() => { ctx.setIsLoginMode(!ctx.isLoginMode); ctx.setAuthError(""); ctx.setPassword(""); }}
                  className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.compact, btnStyles.fitContent)}
                >
                  {ctx.isLoginMode ? 'Need to create an identity?' : 'Already have a keypair? Login'}
                </button>
                
                <div style={{ borderTop: '1px solid var(--background-modifier-accent)', width: '100%', paddingTop: '12px', marginTop: '4px', display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'center' }}>
                  <span style={{ fontSize: '12px', opacity: 0.6, color: 'var(--text-tertiary-muted)' }}>Lost access to your keypair?</span>
                  <button
                    onClick={() => { ctx.setShowRecoverModal(true); ctx.setRecoverError(""); }}
                    className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.fitContainer)}
                  >
                    🔄 Recover with recovery phrase
                  </button>
                </div>
              </div>
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
