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
} from "./crypto";

export interface SetupResult {
  keyPair: CryptoKeyPair;
  publicKey: string;
  publicKeyHash: string;
  password: string;
  mnemonic: string;
  relayUrl?: string;
  inviteCode?: string;
  meshEnabled?: boolean;
  displayName?: string;
}

interface SetupWizardProps {
  onComplete: (result: SetupResult) => void;
}

type WizardMode = "choose" | "login" | "create" | "recover";
type CreateStep = "identity" | "mnemonic";

export const SetupWizard: React.FC<SetupWizardProps> = ({ onComplete }) => {
  const [mode, setMode] = useState<WizardMode>("choose");

  // Shared state
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // Create account state
  const [createStep, setCreateStep] = useState<CreateStep>("identity");
  const [generatedMnemonic, setGeneratedMnemonic] = useState("");
  const [mnemonicCopied, setMnemonicCopied] = useState(false);
  const [keyPair, setKeyPair] = useState<CryptoKeyPair | null>(null);
  const [publicKey, setPublicKey] = useState("");
  const [publicKeyHash, setPublicKeyHash] = useState("");

  // Recover state
  const [mnemonic, setMnemonic] = useState("");

  const resetState = () => {
    setPassword("");
    setConfirmPassword("");
    setDisplayName("");
    setError("");
    setLoading(false);
    setCreateStep("identity");
    setGeneratedMnemonic("");
    setMnemonicCopied(false);
    setKeyPair(null);
    setPublicKey("");
    setPublicKeyHash("");
    setMnemonic("");
  };

  const goBack = () => {
    resetState();
    setMode("choose");
  };

  // === CREATE ACCOUNT: Step 1 - Generate identity ===
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

  // === CREATE ACCOUNT: Step 2 - Complete after mnemonic backup ===
  const handleCreateComplete = useCallback(() => {
    if (!keyPair || !publicKey || !publicKeyHash) return;
    onComplete({
      keyPair,
      publicKey,
      publicKeyHash,
      password,
      mnemonic: generatedMnemonic,
      displayName: displayName.trim() || undefined,
    });
  }, [keyPair, publicKey, publicKeyHash, password, generatedMnemonic, displayName, onComplete]);

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

    setLoading(true);
    setError("");
    try {
      const kp = mnemonicToKeyPair(mnemonic.trim());
      const pk = await exportPublicKey(kp.publicKey);
      const pkHash = await sha256Hex(pk);

      setActiveIdentity(pkHash);
      await saveKeyWithPassword(kp, password, pkHash);

      onComplete({
        keyPair: kp,
        publicKey: pk,
        publicKeyHash: pkHash,
        password,
        mnemonic: mnemonic.trim(),
        displayName: displayName.trim() || undefined,
      });
    } catch (e: any) {
      setError(e.message || "Recovery failed");
      setLoading(false);
    }
  }, [mnemonic, password, displayName, onComplete]);

  // === LOGIN ===
  const handleLogin = useCallback(async () => {
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }

    setLoading(true);
    setError("");
    try {
      const storedPkHash = localStorage.getItem("accord_active_identity");
      if (!storedPkHash) {
        setError("No stored identity found. Try 'Create Identity' or 'Recover Identity' instead.");
        setLoading(false);
        return;
      }

      const kp = await loadKeyWithPassword(password, storedPkHash);
      if (!kp) { setError("Failed to unlock identity — wrong password?"); setLoading(false); return; }
      const pk = await exportPublicKey(kp.publicKey);
      const pkHash = await sha256Hex(pk);

      // Check if there's an existing relay URL (backward compat)
      const existingRelayUrl = localStorage.getItem("accord_server_url") || undefined;

      onComplete({
        keyPair: kp,
        publicKey: pk,
        publicKeyHash: pkHash,
        password,
        mnemonic: "",
        relayUrl: existingRelayUrl,
        displayName: displayName.trim() || undefined,
      });
    } catch (e: any) {
      setError(e.message || "Login failed — wrong password?");
      setLoading(false);
    }
  }, [password, displayName, onComplete]);

  const handleCopyMnemonic = () => {
    navigator.clipboard.writeText(generatedMnemonic);
    setMnemonicCopied(true);
    setTimeout(() => setMnemonicCopied(false), 2000);
  };

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
                {hasStoredKeyPair() && (
                  <button className="btn btn-primary" onClick={() => setMode("login")}>
                    🔓 Log In
                  </button>
                )}
                <button className="btn btn-outline" onClick={() => setMode("create")}>
                  🔑 Create Identity
                </button>
                <button className="btn btn-outline" onClick={() => setMode("recover")}>
                  🔄 Recover Identity
                </button>
              </div>
            </>
          )}

          {/* === LOGIN === */}
          {mode === "login" && (
            <>
              <button onClick={goBack} className="auth-back-btn">← Back</button>
              <h2 className="auth-title">Log In</h2>
              <p className="auth-subtitle">Enter your password to unlock your identity</p>

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

          {/* === CREATE IDENTITY: Password & Identity === */}
          {mode === "create" && createStep === "identity" && (
            <>
              <button onClick={goBack} className="auth-back-btn">← Back</button>
              <h2 className="auth-title">Create Your Identity</h2>
              <p className="auth-subtitle">Choose a password to protect your keypair. No server connection needed.</p>

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

          {/* === CREATE IDENTITY: Mnemonic Backup === */}
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
                onClick={handleCreateComplete}
              >
                I've saved my recovery phrase — Continue →
              </button>
            </>
          )}

          {/* === RECOVER IDENTITY === */}
          {mode === "recover" && (
            <>
              <button onClick={goBack} className="auth-back-btn">← Back</button>
              <h2 className="auth-title">Recover Identity</h2>
              <p className="auth-subtitle">Restore your identity with your recovery phrase</p>

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

              {error && <div className="auth-error">{error}</div>}

              <button
                className="btn btn-green"
                disabled={loading || password.length < 8 || !mnemonic.trim()}
                onClick={handleRecover}
              >
                {loading ? "Recovering..." : "Recover Identity"}
              </button>
            </>
          )}

        </div>
      </div>
    </div>
  );
};
