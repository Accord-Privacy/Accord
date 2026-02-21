import React, { useState, useCallback } from "react";
import {
  generateKeyPair,
  exportPublicKey,
  sha256Hex,
  keyPairToMnemonic,
  mnemonicToKeyPair,
  saveKeyWithPassword,
  setActiveIdentity,
  loadKeyWithPassword,
  hasStoredKeyPair,
  getStoredPublicKey,
} from "./crypto";
import { parseInviteLink, probeServerUrl } from "./api";

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

type WizardMode = "choose" | "login" | "create" | "recover" | "join";
type CreateStep = "invite" | "identity" | "mnemonic";

export const SetupWizard: React.FC<SetupWizardProps> = ({ onComplete }) => {
  const [mode, setMode] = useState<WizardMode>("choose");

  // Shared state
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [inviteLinkInput, setInviteLinkInput] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [meshEnabled, setMeshEnabled] = useState(false);
  const [showMeshTooltip, setShowMeshTooltip] = useState(false);

  // Create account state
  const [createStep, setCreateStep] = useState<CreateStep>("invite");
  const [generatedMnemonic, setGeneratedMnemonic] = useState("");
  const [mnemonicCopied, setMnemonicCopied] = useState(false);
  const [keyPair, setKeyPair] = useState<CryptoKeyPair | null>(null);
  const [publicKey, setPublicKey] = useState("");
  const [publicKeyHash, setPublicKeyHash] = useState("");
  const [parsedRelayUrl, setParsedRelayUrl] = useState("");
  const [parsedInviteCode, setParsedInviteCode] = useState<string | undefined>();

  // Recover state
  const [mnemonic, setMnemonic] = useState("");

  // Login state
  const [loginNeedsInvite, setLoginNeedsInvite] = useState(false);

  const storedServerUrl = localStorage.getItem("accord_server_url");

  const resetState = () => {
    setPassword("");
    setConfirmPassword("");
    setInviteLinkInput("");
    setDisplayName("");
    setError("");
    setLoading(false);
    setCreateStep("invite");
    setGeneratedMnemonic("");
    setMnemonicCopied(false);
    setKeyPair(null);
    setPublicKey("");
    setPublicKeyHash("");
    setParsedRelayUrl("");
    setParsedInviteCode(undefined);
    setMnemonic("");
    setLoginNeedsInvite(false);
  };

  const goBack = () => {
    resetState();
    setMode("choose");
  };

  // Parse invite link and extract relay URL
  const validateInviteLink = (): { relayUrl: string; inviteCode?: string } | null => {
    const parsed = parseInviteLink(inviteLinkInput.trim());
    if (!parsed) {
      setError("Invalid invite link. Expected: accord://host/CODE, https://host/invite/CODE, or similar.");
      return null;
    }
    return { relayUrl: parsed.relayUrl, inviteCode: parsed.inviteCode };
  };

  // === CREATE ACCOUNT: Step 1 - Validate invite link ===
  const handleCreateInviteSubmit = useCallback(() => {
    setError("");
    const result = validateInviteLink();
    if (!result) return;
    setParsedRelayUrl(result.relayUrl);
    setParsedInviteCode(result.inviteCode);
    setCreateStep("identity");
  }, [inviteLinkInput]);

  // === CREATE ACCOUNT: Step 2 - Generate identity ===
  const handleCreateIdentity = useCallback(async () => {
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    setLoading(true);
    setError("");
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
      setCreateStep("mnemonic");
    } catch (e: any) {
      setError(e.message || "Failed to generate identity");
    } finally {
      setLoading(false);
    }
  }, [password, confirmPassword]);

  // === CREATE ACCOUNT: Step 3 - Connect after mnemonic backup ===
  const handleCreateConnect = useCallback(async () => {
    if (!keyPair || !publicKey || !publicKeyHash) return;
    setLoading(true);
    setError("");
    try {
      const verifiedUrl = await probeServerUrl(parsedRelayUrl);
      onComplete({
        keyPair,
        publicKey,
        publicKeyHash,
        password,
        mnemonic: generatedMnemonic,
        relayUrl: verifiedUrl,
        inviteCode: parsedInviteCode,
        meshEnabled,
        displayName: displayName.trim() || undefined,
      });
    } catch (e: any) {
      setError(e.message || "Failed to connect to relay server");
      setLoading(false);
    }
  }, [keyPair, publicKey, publicKeyHash, password, generatedMnemonic, parsedRelayUrl, parsedInviteCode, meshEnabled, displayName, onComplete]);

  // === RECOVER ACCOUNT ===
  const handleRecover = useCallback(async () => {
    if (!mnemonic.trim()) {
      setError("Please enter your recovery phrase");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    const inviteResult = validateInviteLink();
    if (!inviteResult) return;

    setLoading(true);
    setError("");
    try {
      const kp = mnemonicToKeyPair(mnemonic.trim());
      const pk = await exportPublicKey(kp.publicKey);
      const pkHash = await sha256Hex(pk);

      setActiveIdentity(pkHash);
      await saveKeyWithPassword(kp, password, pkHash);

      const verifiedUrl = await probeServerUrl(inviteResult.relayUrl);
      onComplete({
        keyPair: kp,
        publicKey: pk,
        publicKeyHash: pkHash,
        password,
        mnemonic: mnemonic.trim(),
        relayUrl: verifiedUrl,
        inviteCode: inviteResult.inviteCode,
        meshEnabled,
        displayName: displayName.trim() || undefined,
      });
    } catch (e: any) {
      setError(e.message || "Recovery failed");
      setLoading(false);
    }
  }, [mnemonic, password, inviteLinkInput, meshEnabled, displayName, onComplete]);

  // === LOGIN ===
  const handleLogin = useCallback(async () => {
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }

    let relayUrl = storedServerUrl || "";
    let inviteCode: string | undefined;

    if (!storedServerUrl || loginNeedsInvite) {
      const inviteResult = validateInviteLink();
      if (!inviteResult) return;
      relayUrl = inviteResult.relayUrl;
      inviteCode = inviteResult.inviteCode;
    }

    setLoading(true);
    setError("");
    try {
      // Try to load existing keypair with password
      const storedPkHash = localStorage.getItem("accord_active_identity");
      if (!storedPkHash) {
        setError("No stored identity found. Try 'Create Account' or 'Recover Account' instead.");
        setLoading(false);
        return;
      }

      const kp = await loadKeyWithPassword(password, storedPkHash);
      const pk = await exportPublicKey(kp.publicKey);
      const pkHash = await sha256Hex(pk);

      const verifiedUrl = await probeServerUrl(relayUrl);
      onComplete({
        keyPair: kp,
        publicKey: pk,
        publicKeyHash: pkHash,
        password,
        mnemonic: "",
        relayUrl: verifiedUrl,
        inviteCode,
        meshEnabled,
        displayName: displayName.trim() || undefined,
      });
    } catch (e: any) {
      setError(e.message || "Login failed — wrong password?");
      setLoading(false);
    }
  }, [password, storedServerUrl, loginNeedsInvite, inviteLinkInput, meshEnabled, displayName, onComplete]);

  // === JOIN NODE ===
  const handleJoinNode = useCallback(async () => {
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    const inviteResult = validateInviteLink();
    if (!inviteResult) return;

    setLoading(true);
    setError("");
    try {
      const storedPkHash = localStorage.getItem("accord_active_identity");
      if (!storedPkHash) {
        setError("No stored identity found. Try 'Create Account' first.");
        setLoading(false);
        return;
      }

      const kp = await loadKeyWithPassword(password, storedPkHash);
      const pk = await exportPublicKey(kp.publicKey);
      const pkHash = await sha256Hex(pk);

      const verifiedUrl = await probeServerUrl(inviteResult.relayUrl);
      onComplete({
        keyPair: kp,
        publicKey: pk,
        publicKeyHash: pkHash,
        password,
        mnemonic: "",
        relayUrl: verifiedUrl,
        inviteCode: inviteResult.inviteCode,
        meshEnabled,
        displayName: displayName.trim() || undefined,
      });
    } catch (e: any) {
      setError(e.message || "Failed to join — wrong password?");
      setLoading(false);
    }
  }, [password, inviteLinkInput, meshEnabled, displayName, onComplete]);

  const handleCopyMnemonic = () => {
    navigator.clipboard.writeText(generatedMnemonic);
    setMnemonicCopied(true);
    setTimeout(() => setMnemonicCopied(false), 2000);
  };

  // Mesh checkbox (shared across modes)
  const renderMeshOption = () => (
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
  );

  const renderDisplayNameField = () => (
    <div className="form-group" style={{ marginTop: 16 }}>
      <label className="form-label">Display Name <span style={{ color: "var(--accent)" }}>*</span></label>
      <input
        type="text"
        placeholder="How others will see you (required)"
        required
        value={displayName}
        onChange={(e) => setDisplayName(e.target.value)}
        className="form-input"
        maxLength={32}
      />
    </div>
  );

  const renderInviteLinkField = (onSubmit?: () => void) => (
    <div className="form-group" style={{ marginTop: 16 }}>
      <label className="form-label">Invite Link</label>
      <input
        type="text"
        placeholder="accord://host:port/invite/CODE or https://..."
        value={inviteLinkInput}
        onChange={(e) => setInviteLinkInput(e.target.value)}
        onKeyDown={(e) => { if (e.key === "Enter" && onSubmit) onSubmit(); }}
        className="form-input"
      />
    </div>
  );

  return (
    <div className="app">
      <div className="auth-page">
        <div className="auth-card" style={{ maxWidth: 480 }}>

          {/* === CHOOSE MODE === */}
          {mode === "choose" && (
            <>
              <div className="auth-brand" style={{ marginTop: 16 }}>
                <h1>⚡ <span className="brand-accent">Accord</span></h1>
              </div>
              <p className="auth-tagline">Privacy-first communications</p>
              <div style={{ margin: "24px 0", color: "var(--text-secondary)", fontSize: 14, lineHeight: 1.6, textAlign: "center" }}>
                Accord gives you encrypted messaging, voice, and communities —
                without trusting a central server with your data. Your keys, your messages.
              </div>
              <div className="auth-buttons-stack" style={{ marginTop: 16 }}>
                {(storedServerUrl || hasStoredKeyPair()) && (
                  <button className="btn btn-primary" onClick={() => setMode("login")}>
                    🔓 Log In
                  </button>
                )}
                <button className="btn btn-outline" onClick={() => setMode("create")}>
                  🔑 Create Account
                </button>
                <button className="btn btn-outline" onClick={() => setMode("recover")}>
                  🔄 Recover Account
                </button>
                {hasStoredKeyPair() && (
                  <button className="btn btn-outline" onClick={() => setMode("join")}>
                    🌐 Join a Node
                  </button>
                )}
              </div>
            </>
          )}

          {/* === LOGIN === */}
          {mode === "login" && (
            <>
              <button onClick={goBack} className="auth-back-btn">← Back</button>
              <h2 className="auth-title">Log In</h2>
              <p className="auth-subtitle">
                {storedServerUrl && !loginNeedsInvite
                  ? "Enter your password to unlock your identity"
                  : "Paste an invite link and enter your password"}
              </p>

              {(!storedServerUrl || loginNeedsInvite) && (
                <>
                  {renderInviteLinkField(handleLogin)}
                </>
              )}

              <div className="form-group" style={{ marginTop: 16 }}>
                <label className="form-label">Password</label>
                <input
                  type="password"
                  placeholder="Your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleLogin(); }}
                  className="form-input"
                />
              </div>

              {storedServerUrl && !loginNeedsInvite && (
                <button
                  className="btn-ghost"
                  style={{ fontSize: 13, marginBottom: 12 }}
                  onClick={() => setLoginNeedsInvite(true)}
                >
                  Connect to a different relay
                </button>
              )}

              {error && <div className="auth-error">{error}</div>}

              <button
                className="btn btn-primary"
                disabled={loading || password.length < 8}
                onClick={handleLogin}
              >
                {loading ? "Logging in..." : "Log In"}
              </button>
            </>
          )}

          {/* === CREATE ACCOUNT: Invite Link === */}
          {mode === "create" && createStep === "invite" && (
            <>
              <button onClick={goBack} className="auth-back-btn">← Back</button>
              <h2 className="auth-title">Create Account</h2>
              <p className="auth-subtitle">Paste the invite link you received to connect to a relay</p>

              {renderInviteLinkField(handleCreateInviteSubmit)}

              {error && <div className="auth-error">{error}</div>}

              <button
                className="btn btn-primary"
                style={{ marginTop: 16 }}
                disabled={!inviteLinkInput.trim()}
                onClick={handleCreateInviteSubmit}
              >
                Continue →
              </button>
            </>
          )}

          {/* === CREATE ACCOUNT: Password & Identity === */}
          {mode === "create" && createStep === "identity" && (
            <>
              <button onClick={() => { setCreateStep("invite"); setError(""); setPassword(""); setConfirmPassword(""); }} className="auth-back-btn">← Back</button>
              <h2 className="auth-title">Create Your Identity</h2>
              <p className="auth-subtitle">Choose a password to protect your keypair</p>

              {renderDisplayNameField()}

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

              {renderMeshOption()}

              {error && <div className="auth-error">{error}</div>}

              <button
                className="btn btn-green"
                disabled={loading || password.length < 8}
                onClick={handleCreateIdentity}
              >
                {loading ? "Generating keypair..." : "Generate Identity"}
              </button>
            </>
          )}

          {/* === CREATE ACCOUNT: Mnemonic Backup === */}
          {mode === "create" && createStep === "mnemonic" && (
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

              {error && <div className="auth-error" style={{ marginTop: 12 }}>{error}</div>}

              <button
                className="btn btn-primary"
                style={{ marginTop: 16 }}
                disabled={loading}
                onClick={handleCreateConnect}
              >
                {loading ? "Connecting to relay..." : "I've saved my recovery phrase — Connect →"}
              </button>
            </>
          )}

          {/* === RECOVER ACCOUNT === */}
          {mode === "recover" && (
            <>
              <button onClick={goBack} className="auth-back-btn">← Back</button>
              <h2 className="auth-title">Recover Account</h2>
              <p className="auth-subtitle">Restore your identity with your recovery phrase and an invite link</p>

              <div className="form-group" style={{ marginTop: 16 }}>
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

              {renderInviteLinkField(handleRecover)}
              {renderDisplayNameField()}

              <div className="form-group" style={{ marginTop: 12 }}>
                <label className="form-label">New Password (min 8 characters)</label>
                <input
                  type="password"
                  placeholder="Choose a password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleRecover(); }}
                  className="form-input"
                />
              </div>

              {renderMeshOption()}

              {error && <div className="auth-error">{error}</div>}

              <button
                className="btn btn-green"
                disabled={loading || password.length < 8 || !mnemonic.trim() || !inviteLinkInput.trim()}
                onClick={handleRecover}
              >
                {loading ? "Recovering..." : "Recover & Connect"}
              </button>
            </>
          )}

          {/* === JOIN NODE === */}
          {mode === "join" && (
            <>
              <button onClick={goBack} className="auth-back-btn">← Back</button>
              <h2 className="auth-title">Join a Node</h2>
              <p className="auth-subtitle">Use an invite link to join a new node with your existing identity</p>

              {renderInviteLinkField(handleJoinNode)}
              {renderDisplayNameField()}

              <div className="form-group" style={{ marginTop: 12 }}>
                <label className="form-label">Password</label>
                <input
                  type="password"
                  placeholder="Your identity password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleJoinNode(); }}
                  className="form-input"
                />
              </div>

              {renderMeshOption()}

              {error && <div className="auth-error">{error}</div>}

              <button
                className="btn btn-primary"
                disabled={loading || password.length < 8 || !inviteLinkInput.trim()}
                onClick={handleJoinNode}
              >
                {loading ? "Joining..." : "Join Node"}
              </button>
            </>
          )}

        </div>
      </div>
    </div>
  );
};
