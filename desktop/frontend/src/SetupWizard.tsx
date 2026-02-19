import React, { useState, useCallback } from "react";
import {
  generateKeyPair,
  exportPublicKey,
  sha256Hex,
  keyPairToMnemonic,
  mnemonicToKeyPair,
  saveKeyWithPassword,
  setActiveIdentity,
} from "./crypto";
import { parseInviteLink, normalizeServerUrl, probeServerUrl } from "./api";

export interface SetupResult {
  keyPair: CryptoKeyPair;
  publicKey: string;
  publicKeyHash: string;
  password: string;
  mnemonic: string;
  relayUrl: string;
  inviteCode?: string;
  meshEnabled: boolean;
  displayName?: string;
}

interface SetupWizardProps {
  onComplete: (result: SetupResult) => void;
}

type Step = 1 | 2 | 3;
type IdentityMode = "create" | "recover";

export const SetupWizard: React.FC<SetupWizardProps> = ({ onComplete }) => {
  const [step, setStep] = useState<Step>(1);

  // Step 2 state
  const [identityMode, setIdentityMode] = useState<IdentityMode | null>(null);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [mnemonic, setMnemonic] = useState("");
  const [generatedMnemonic, setGeneratedMnemonic] = useState("");
  const [mnemonicCopied, setMnemonicCopied] = useState(false);
  const [keyPair, setKeyPair] = useState<CryptoKeyPair | null>(null);
  const [publicKey, setPublicKey] = useState("");
  const [publicKeyHash, setPublicKeyHash] = useState("");
  const [identityReady, setIdentityReady] = useState(false);
  const [identityError, setIdentityError] = useState("");
  const [generating, setGenerating] = useState(false);

  // Display name state
  const [displayName, setDisplayName] = useState("");

  // Step 3 state
  const [relayAddress, setRelayAddress] = useState("");
  const [inviteLinkInput, setInviteLinkInput] = useState("");
  const [useInviteLink, setUseInviteLink] = useState(false);
  const [meshEnabled, setMeshEnabled] = useState(false);
  const [showMeshTooltip, setShowMeshTooltip] = useState(false);
  const [connectError, setConnectError] = useState("");
  const [connecting, setConnecting] = useState(false);

  // Step 2: Create new identity
  const handleCreateIdentity = useCallback(async () => {
    if (password.length < 8) {
      setIdentityError("Password must be at least 8 characters");
      return;
    }
    if (password !== confirmPassword) {
      setIdentityError("Passwords do not match");
      return;
    }
    setGenerating(true);
    setIdentityError("");
    try {
      const kp = await generateKeyPair();
      const pk = await exportPublicKey(kp.publicKey);
      const pkHash = await sha256Hex(pk);
      const phrase = await keyPairToMnemonic(kp);

      setActiveIdentity(pkHash);
      await saveKeyWithPassword(kp, password, pkHash);

      setKeyPair(kp);
      setPublicKey(pk);
      setPublicKeyHash(pkHash);
      setGeneratedMnemonic(phrase);
      setIdentityReady(true);
    } catch (e: any) {
      setIdentityError(e.message || "Failed to generate identity");
    } finally {
      setGenerating(false);
    }
  }, [password, confirmPassword]);

  // Step 2: Recover identity from mnemonic
  const handleRecoverIdentity = useCallback(async () => {
    if (password.length < 8) {
      setIdentityError("Password must be at least 8 characters");
      return;
    }
    if (!mnemonic.trim()) {
      setIdentityError("Please enter your recovery phrase");
      return;
    }
    setGenerating(true);
    setIdentityError("");
    try {
      const kp = mnemonicToKeyPair(mnemonic.trim());
      const pk = await exportPublicKey(kp.publicKey);
      const pkHash = await sha256Hex(pk);

      setActiveIdentity(pkHash);
      await saveKeyWithPassword(kp, password, pkHash);

      setKeyPair(kp);
      setPublicKey(pk);
      setPublicKeyHash(pkHash);
      setIdentityReady(true);
    } catch (e: any) {
      setIdentityError(e.message || "Invalid recovery phrase");
    } finally {
      setGenerating(false);
    }
  }, [password, mnemonic]);

  // Step 3: Connect
  const handleConnect = useCallback(async () => {
    if (!keyPair || !publicKey || !publicKeyHash) return;

    let relayUrl = "";
    let inviteCode: string | undefined;

    if (useInviteLink && inviteLinkInput.trim()) {
      const parsed = parseInviteLink(inviteLinkInput.trim());
      if (!parsed) {
        setConnectError("Invalid invite link format. Expected: accord://host/CODE, https://host/invite/CODE, or similar.");
        return;
      }
      relayUrl = parsed.relayUrl;
      inviteCode = parsed.inviteCode;
    } else if (relayAddress.trim()) {
      relayUrl = normalizeServerUrl(relayAddress.trim());
    } else {
      setConnectError("Please enter a relay address or invite link");
      return;
    }

    setConnecting(true);
    setConnectError("");

    try {
      // Probe the server — tries both HTTP and HTTPS, returns the working URL
      const verifiedUrl = await probeServerUrl(relayUrl);

      onComplete({
        keyPair,
        publicKey,
        publicKeyHash,
        password,
        mnemonic: generatedMnemonic || mnemonic,
        relayUrl: verifiedUrl,
        inviteCode,
        meshEnabled,
        displayName: displayName.trim() || undefined,
      });
    } catch (e: any) {
      setConnectError(e.message || "Failed to connect to relay server");
      setConnecting(false);
    }
  }, [keyPair, publicKey, publicKeyHash, password, generatedMnemonic, mnemonic, relayAddress, inviteLinkInput, useInviteLink, meshEnabled, onComplete]);

  const handleCopyMnemonic = () => {
    navigator.clipboard.writeText(generatedMnemonic);
    setMnemonicCopied(true);
    setTimeout(() => setMnemonicCopied(false), 2000);
  };

  return (
    <div className="app">
      <div className="auth-page">
        <div className="auth-card" style={{ maxWidth: 480 }}>
          {/* Progress indicator */}
          <div className="setup-progress">
            {[1, 2, 3].map((s) => (
              <div key={s} className={`setup-progress-step ${step >= s ? "active" : ""} ${step === s ? "current" : ""}`}>
                <div className="setup-progress-dot">{step > s ? "✓" : s}</div>
                <span className="setup-progress-label">
                  {s === 1 ? "Welcome" : s === 2 ? "Identity" : "Connect"}
                </span>
              </div>
            ))}
            <div className="setup-progress-line">
              <div className="setup-progress-line-fill" style={{ width: `${((step - 1) / 2) * 100}%` }} />
            </div>
          </div>

          {/* Step 1: Welcome */}
          {step === 1 && (
            <>
              <div className="auth-brand" style={{ marginTop: 16 }}>
                <h1>⚡ <span className="brand-accent">Accord</span></h1>
              </div>
              <p className="auth-tagline">Privacy-first communications</p>
              <div style={{ margin: "24px 0", color: "var(--text-secondary)", fontSize: 14, lineHeight: 1.6, textAlign: "center" }}>
                Accord gives you encrypted messaging, voice, and communities — 
                without trusting a central server with your data. Your keys, your messages.
              </div>
              <div className="auth-info-box">
                <span className="accent">🔐 End-to-end encrypted by default</span>
              </div>
              <div className="auth-info-box" style={{ marginTop: 8 }}>
                <span className="accent">🌐 Self-hosted relay servers — you choose who to trust</span>
              </div>
              <div className="auth-info-box" style={{ marginTop: 8 }}>
                <span className="accent">🆔 Keypair-based identity — no email or phone required</span>
              </div>
              <button className="btn btn-primary" style={{ marginTop: 24 }} onClick={() => setStep(2)}>
                Get Started
              </button>
            </>
          )}

          {/* Step 2: Identity */}
          {step === 2 && !identityReady && (
            <>
              <button onClick={() => { setStep(1); setIdentityMode(null); setIdentityError(""); }} className="auth-back-btn">← Back</button>
              <h2 className="auth-title">Your Identity</h2>
              <p className="auth-subtitle">
                {!identityMode
                  ? "Choose how to set up your identity"
                  : identityMode === "create"
                  ? "Generate a new keypair"
                  : "Restore from recovery phrase"}
              </p>

              {!identityMode && (
                <div className="auth-buttons-stack" style={{ marginTop: 16 }}>
                  <button className="btn btn-primary" onClick={() => setIdentityMode("create")}>
                    🔑 Create New Identity
                  </button>
                  <button className="btn btn-outline" onClick={() => setIdentityMode("recover")}>
                    🔄 Recover Identity
                  </button>
                </div>
              )}

              {identityMode === "create" && (
                <>
                  <button onClick={() => { setIdentityMode(null); setIdentityError(""); setPassword(""); setConfirmPassword(""); }} className="auth-back-btn" style={{ marginTop: 8 }}>← Change method</button>
                  <div className="form-group" style={{ marginTop: 12 }}>
                    <label className="form-label">Password (min 8 characters)</label>
                    <input
                      type="password"
                      placeholder="Choose a password to protect your key"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="form-input"
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Confirm Password</label>
                    <input
                      type="password"
                      placeholder="Confirm your password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      onKeyDown={(e) => { if (e.key === "Enter") handleCreateIdentity(); }}
                      className="form-input"
                    />
                  </div>
                  {identityError && <div className="auth-error">{identityError}</div>}
                  <button
                    className="btn btn-green"
                    disabled={generating || password.length < 8}
                    onClick={handleCreateIdentity}
                  >
                    {generating ? "Generating keypair..." : "Generate Identity"}
                  </button>
                </>
              )}

              {identityMode === "recover" && (
                <>
                  <button onClick={() => { setIdentityMode(null); setIdentityError(""); setPassword(""); setMnemonic(""); }} className="auth-back-btn" style={{ marginTop: 8 }}>← Change method</button>
                  <div className="form-group" style={{ marginTop: 12 }}>
                    <label className="form-label">Recovery Phrase (24 words)</label>
                    <textarea
                      placeholder="Enter your 24-word recovery phrase..."
                      value={mnemonic}
                      onChange={(e) => setMnemonic(e.target.value)}
                      className="form-input"
                      rows={3}
                      style={{ resize: "vertical", minHeight: 72 }}
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">New Password (min 8 characters)</label>
                    <input
                      type="password"
                      placeholder="Choose a password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      onKeyDown={(e) => { if (e.key === "Enter") handleRecoverIdentity(); }}
                      className="form-input"
                    />
                  </div>
                  {identityError && <div className="auth-error">{identityError}</div>}
                  <button
                    className="btn btn-green"
                    disabled={generating || password.length < 8 || !mnemonic.trim()}
                    onClick={handleRecoverIdentity}
                  >
                    {generating ? "Recovering..." : "Recover Identity"}
                  </button>
                </>
              )}
            </>
          )}

          {/* Step 2b: Mnemonic backup (after create) */}
          {step === 2 && identityReady && generatedMnemonic && (
            <>
              <h2 className="auth-title">🔑 Backup Your Recovery Phrase</h2>
              <p className="auth-subtitle">
                Write this down and store it safely. It's the only way to recover your identity if you lose access.
              </p>
              <div className="auth-info-box" style={{ marginTop: 16, fontFamily: "var(--font-mono)", fontSize: 13, wordBreak: "break-word", lineHeight: 1.8, userSelect: "all" }}>
                {generatedMnemonic}
              </div>
              <button
                className="btn btn-outline"
                style={{ marginTop: 12 }}
                onClick={handleCopyMnemonic}
              >
                {mnemonicCopied ? "✓ Copied!" : "📋 Copy to clipboard"}
              </button>
              <div className="auth-info-box" style={{ marginTop: 12 }}>
                <span className="warning">⚠️ Never share this phrase. Anyone with it can access your identity.</span>
              </div>
              <button
                className="btn btn-primary"
                style={{ marginTop: 16 }}
                onClick={() => setStep(3)}
              >
                I've saved my recovery phrase →
              </button>
            </>
          )}

          {/* Step 2: Recovered identity (no mnemonic to show) */}
          {step === 2 && identityReady && !generatedMnemonic && (
            <>
              <h2 className="auth-title">✅ Identity Recovered</h2>
              <p className="auth-subtitle">Your keypair has been restored successfully.</p>
              <div className="auth-info-box" style={{ marginTop: 16 }}>
                <span className="accent">Fingerprint: {publicKeyHash.substring(0, 8)}...{publicKeyHash.substring(publicKeyHash.length - 8)}</span>
              </div>
              <button className="btn btn-primary" style={{ marginTop: 16 }} onClick={() => setStep(3)}>
                Continue →
              </button>
            </>
          )}

          {/* Step 3: Connect */}
          {step === 3 && (
            <>
              <button onClick={() => setStep(2)} className="auth-back-btn">← Back</button>
              <h2 className="auth-title">Connect to a Relay</h2>
              <p className="auth-subtitle">Choose a display name and enter a relay address</p>

              <div className="form-group" style={{ marginTop: 16 }}>
                <label className="form-label">Display Name</label>
                <input
                  type="text"
                  placeholder="How others will see you"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  className="form-input"
                  maxLength={32}
                />
              </div>

              {!useInviteLink ? (
                <>
                  <div className="form-group" style={{ marginTop: 16 }}>
                    <label className="form-label">Relay Address</label>
                    <input
                      type="text"
                      placeholder="relay.example.com:8443"
                      value={relayAddress}
                      onChange={(e) => setRelayAddress(e.target.value)}
                      onKeyDown={(e) => { if (e.key === "Enter") handleConnect(); }}
                      className="form-input"
                    />
                  </div>
                  <button
                    className="btn-ghost"
                    style={{ fontSize: 13, marginBottom: 12 }}
                    onClick={() => setUseInviteLink(true)}
                  >
                    Or paste an invite link instead
                  </button>
                </>
              ) : (
                <>
                  <div className="form-group" style={{ marginTop: 16 }}>
                    <label className="form-label">Invite Link</label>
                    <input
                      type="text"
                      placeholder="accord://host:port/invite/CODE or https://..."
                      value={inviteLinkInput}
                      onChange={(e) => setInviteLinkInput(e.target.value)}
                      onKeyDown={(e) => { if (e.key === "Enter") handleConnect(); }}
                      className="form-input"
                    />
                  </div>
                  <button
                    className="btn-ghost"
                    style={{ fontSize: 13, marginBottom: 12 }}
                    onClick={() => setUseInviteLink(false)}
                  >
                    Or enter relay address manually
                  </button>
                </>
              )}

              {/* Mesh opt-in */}
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16, position: "relative" }}>
                <input
                  type="checkbox"
                  id="mesh-optin"
                  checked={meshEnabled}
                  onChange={(e) => setMeshEnabled(e.target.checked)}
                  style={{ accentColor: "var(--accent)" }}
                />
                <label htmlFor="mesh-optin" style={{ fontSize: 13, color: "var(--text-secondary)", cursor: "pointer" }}>
                  Enable relay mesh for cross-relay DMs
                </label>
                <span
                  style={{ cursor: "help", fontSize: 14, opacity: 0.6 }}
                  onMouseEnter={() => setShowMeshTooltip(true)}
                  onMouseLeave={() => setShowMeshTooltip(false)}
                >
                  ℹ️
                </span>
                {showMeshTooltip && (
                  <div className="setup-tooltip">
                    Relay mesh allows you to send direct messages to users on other relays. 
                    Your relay will connect to other participating relays to route messages. 
                    This is optional and can be changed later.
                  </div>
                )}
              </div>

              {connectError && (
                <div className="auth-error" style={{ textAlign: "left", lineHeight: 1.5 }}>
                  <div style={{ marginBottom: 8 }}>⚠️ {connectError}</div>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    <button
                      className="btn btn-outline"
                      style={{ fontSize: 12, padding: "4px 12px" }}
                      onClick={() => { setConnectError(""); handleConnect(); }}
                    >
                      🔄 Retry
                    </button>
                    <button
                      className="btn btn-outline"
                      style={{ fontSize: 12, padding: "4px 12px" }}
                      onClick={() => { setConnectError(""); }}
                    >
                      ✏️ Edit Address
                    </button>
                  </div>
                </div>
              )}

              <button
                className="btn btn-primary"
                disabled={connecting || (!relayAddress.trim() && !inviteLinkInput.trim())}
                onClick={handleConnect}
              >
                {connecting ? "Checking server..." : "Connect"}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
