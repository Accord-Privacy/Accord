import React, { useState, useCallback } from "react";
import clsx from "clsx";
import authStyles from "./components/layout/AuthLayout.module.css";
import btnStyles from "./components/uikit/button/Button.module.css";
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
  isRecovery?: boolean;
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
      let phrase: string;
      try {
        phrase = await keyPairToMnemonic(kp);
      } catch (mnErr) {
        console.error("Mnemonic generation failed:", mnErr);
        phrase = "";
      }

      if (!phrase || phrase.trim().split(/\s+/).length < 24) {
        console.error("Invalid mnemonic generated, length:", phrase?.length, "words:", phrase?.trim().split(/\s+/).length);
        // Fallback: extract raw bytes and try again
        try {
          const { getRawPrivateKey, entropyToMnemonic } = await import("./crypto");
          const raw = await getRawPrivateKey(kp);
          phrase = entropyToMnemonic(raw);
        } catch (fallbackErr) {
          console.error("Mnemonic fallback also failed:", fallbackErr);
        }
      }

      setActiveIdentity(pkHash);
      await saveKeyWithPassword(kp, password, pkHash);

      setKeyPair(kp);
      setPublicKey(pk);
      setPublicKeyHash(pkHash);
      setGeneratedMnemonic(phrase || "(Error: could not generate recovery phrase. Your identity is still saved.)");
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
        isRecovery: true,
      });
    } catch (e: any) {
      setError(e.message || "Recovery failed");
      setLoading(false);
    }
  }, [mnemonic, password, onComplete]);

  // === LOGIN ===
  const handleLogin = useCallback(async () => {
    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }

    setLoading(true);
    setError("");
    try {
      let storedPkHash = localStorage.getItem("accord_active_identity");
      // Fallback: check identity index
      if (!storedPkHash) {
        try {
          const idx = JSON.parse(localStorage.getItem("accord_identity_index") || "[]");
          if (idx.length > 0) storedPkHash = idx[idx.length - 1];
        } catch {}
      }
      // Fallback: check legacy public key hash
      if (!storedPkHash) {
        storedPkHash = localStorage.getItem("accord_public_key_hash");
      }
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
        isRecovery: true, // existing account — don't prompt for display name
      });
    } catch (e: any) {
      setError(e.message || "Login failed — wrong password?");
      setLoading(false);
    }
  }, [password, onComplete]);

  const handleCopyMnemonic = async () => {
    try {
      await navigator.clipboard.writeText(generatedMnemonic);
    } catch {
      // Fallback for non-HTTPS contexts
      const ta = document.createElement('textarea');
      ta.value = generatedMnemonic;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setMnemonicCopied(true);
    setTimeout(() => setMnemonicCopied(false), 2000);
  };

  const renderDisplayNameField = () => (
    <div style={{ marginBottom: "16px", marginTop: 16 }}>
      <label style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase" as const, letterSpacing: "0.02em", color: "var(--text-tertiary-muted)", display: "block", marginBottom: "6px" }}>Display Name <span style={{ color: "var(--accent)" }}>*</span></label>
      <input
        type="text"
        placeholder="How others will see you (required)"
        required
        value={displayName}
        onChange={(e) => setDisplayName(e.target.value)}
        style={{ width: "100%", padding: "10px 12px", fontSize: "14px", backgroundColor: "var(--background-tertiary)", border: "1px solid transparent", borderRadius: "6px", color: "var(--text-primary)", outline: "none", boxSizing: "border-box" as const }}
        maxLength={32}
      />
    </div>
  );

  return (
    <div className={authStyles.scrollerWrapper}>
      <div className={authStyles.container}>
        <div className={authStyles.cardContainer}>
        <div className={clsx(authStyles.card, authStyles.cardSingle)} style={{ maxWidth: 480 }}>
        <div className={authStyles.formSideSingle} style={{ padding: '2rem 3rem' }}>

          {/* === CHOOSE MODE === */}
          {mode === "choose" && (
            <>
              <div style={{ textAlign: "center" as const, marginBottom: "16px", marginTop: 16 }}>
                <h1>⚡ <span style={{ color: "var(--accent)" }}>Accord</span></h1>
              </div>
              <p style={{ textAlign: "center" as const, color: "var(--text-tertiary-muted)", fontSize: "14px", marginBottom: "24px" }}>Privacy-first communications</p>
              <div style={{ margin: "24px 0", color: "var(--text-secondary)", fontSize: 14, lineHeight: 1.6, textAlign: "center" }}>
                Accord gives you encrypted messaging, voice, and communities —
                without trusting a central server with your data. Your keys, your messages.
              </div>
              <div style={{ display: "flex", flexDirection: "column" as const, gap: "8px", marginTop: 16 }}>
                {hasStoredKeyPair() && (
                  <button className={clsx(btnStyles.button, btnStyles.primary)} onClick={() => setMode("login")}>
                    🔓 Log In
                  </button>
                )}
                <button className={clsx(btnStyles.button, btnStyles.secondary)} onClick={() => setMode("create")}>
                  🔑 Create Identity
                </button>
                <button className={clsx(btnStyles.button, btnStyles.secondary)} onClick={() => setMode("recover")}>
                  🔄 Recover Identity
                </button>
              </div>
            </>
          )}

          {/* === LOGIN === */}
          {mode === "login" && (
            <>
              <button onClick={goBack} className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.compact, btnStyles.fitContent)} style={{ marginBottom: "16px" }}>← Back</button>
              <h2 style={{ color: "var(--text-primary)", fontSize: "24px", fontWeight: 700, marginBottom: "8px" }}>Log In</h2>
              <p style={{ color: "var(--text-tertiary-muted)", fontSize: "14px", lineHeight: "1.5", marginBottom: "20px" }}>Enter your password to unlock your identity</p>

              <div style={{ padding: "10px 12px", background: "var(--background-tertiary)", borderRadius: "6px", fontSize: "14px", marginTop: 16, marginBottom: 12 }}>
                {hasStoredKeyPair() ? (
                  <span style={{ color: 'var(--green, #43b581)' }}>🔑 Identity keypair found on this device</span>
                ) : (
                  <span style={{ color: 'var(--yellow, #faa61a)' }}>⚠️ No identity found — try Create or Recover instead</span>
                )}
              </div>

              <div style={{ marginBottom: "16px" }}>
                <label style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase" as const, letterSpacing: "0.02em", color: "var(--text-tertiary-muted)", display: "block", marginBottom: "6px" }}>Password</label>
                <input
                  type="password"
                  placeholder="Your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleLogin(); }}
                  style={{ width: "100%", padding: "10px 12px", fontSize: "14px", backgroundColor: "var(--background-tertiary)", border: "1px solid transparent", borderRadius: "6px", color: "var(--text-primary)", outline: "none", boxSizing: "border-box" as const }}
                />
              </div>

              {error && <div style={{ color: "var(--red)", fontSize: "13px", marginBottom: "12px", padding: "8px 12px", background: "rgba(237,66,69,0.1)", borderRadius: "6px" }}>{error}</div>}

              <button
                className={clsx(btnStyles.button, btnStyles.primary)}
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
              <button onClick={goBack} className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.compact, btnStyles.fitContent)} style={{ marginBottom: "16px" }}>← Back</button>
              <h2 style={{ color: "var(--text-primary)", fontSize: "24px", fontWeight: 700, marginBottom: "8px" }}>Create Your Identity</h2>
              <p style={{ color: "var(--text-tertiary-muted)", fontSize: "14px", lineHeight: "1.5", marginBottom: "20px" }}>Choose a password to protect your keypair. No server connection needed.</p>

              {renderDisplayNameField()}

              <div style={{ marginBottom: "16px", marginTop: 12 }}>
                <label style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase" as const, letterSpacing: "0.02em", color: "var(--text-tertiary-muted)", display: "block", marginBottom: "6px" }}>Password (min 8 characters)</label>
                <input
                  type="password"
                  placeholder="Choose a password to protect your key"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  style={{ width: "100%", padding: "10px 12px", fontSize: "14px", backgroundColor: "var(--background-tertiary)", border: "1px solid transparent", borderRadius: "6px", color: "var(--text-primary)", outline: "none", boxSizing: "border-box" as const }}
                />
              </div>
              <div style={{ marginBottom: "16px" }}>
                <label style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase" as const, letterSpacing: "0.02em", color: "var(--text-tertiary-muted)", display: "block", marginBottom: "6px" }}>Confirm Password</label>
                <input
                  type="password"
                  placeholder="Confirm your password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleCreateIdentity(); }}
                  style={{ width: "100%", padding: "10px 12px", fontSize: "14px", backgroundColor: "var(--background-tertiary)", border: "1px solid transparent", borderRadius: "6px", color: "var(--text-primary)", outline: "none", boxSizing: "border-box" as const }}
                />
              </div>

              {error && <div style={{ color: "var(--red)", fontSize: "13px", marginBottom: "12px", padding: "8px 12px", background: "rgba(237,66,69,0.1)", borderRadius: "6px" }}>{error}</div>}

              <button
                className={clsx(btnStyles.button, btnStyles.primary)}
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
              <h2 style={{ color: "var(--text-primary)", fontSize: "24px", fontWeight: 700, marginBottom: "8px" }}>🔑 Backup Your Recovery Phrase</h2>
              <p style={{ color: "var(--text-tertiary-muted)", fontSize: "14px", lineHeight: "1.5", marginBottom: "20px" }}>
                Write this down and store it safely. It's the only way to recover your identity if you lose access.
              </p>
              <div style={{ padding: "10px 12px", background: "var(--background-tertiary)", borderRadius: "6px", marginTop: 16, fontFamily: "var(--font-mono)", fontSize: 13, wordBreak: "break-word", lineHeight: 1.8, userSelect: "all" }}>
                {generatedMnemonic}
              </div>
              <button
                className={clsx(btnStyles.button, btnStyles.secondary)}
                style={{ marginTop: 12 }}
                onClick={handleCopyMnemonic}
              >
                {mnemonicCopied ? "✓ Copied!" : "📋 Copy to clipboard"}
              </button>
              <div style={{ padding: "10px 12px", background: "var(--background-tertiary)", borderRadius: "6px", fontSize: "14px", marginTop: 12 }}>
                <span className="warning">⚠️ Never share this phrase. Anyone with it can access your identity.</span>
              </div>

              {error && <div style={{ color: "var(--red)", fontSize: "13px", marginBottom: "12px", padding: "8px 12px", background: "rgba(237,66,69,0.1)", borderRadius: "6px", marginTop: 12 }}>{error}</div>}

              <button
                className={clsx(btnStyles.button, btnStyles.primary)}
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
              <button onClick={goBack} className={clsx(btnStyles.button, btnStyles.secondary, btnStyles.compact, btnStyles.fitContent)} style={{ marginBottom: "16px" }}>← Back</button>
              <h2 style={{ color: "var(--text-primary)", fontSize: "24px", fontWeight: 700, marginBottom: "8px" }}>Recover Identity</h2>
              <p style={{ color: "var(--text-tertiary-muted)", fontSize: "14px", lineHeight: "1.5", marginBottom: "20px" }}>Restore your identity with your recovery phrase</p>

              <div style={{ marginBottom: "16px", marginTop: 16 }}>
                <label style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase" as const, letterSpacing: "0.02em", color: "var(--text-tertiary-muted)", display: "block", marginBottom: "6px" }}>Recovery Phrase (24 words)</label>
                <textarea
                  placeholder="Enter your 24-word recovery phrase..."
                  value={mnemonic}
                  onChange={(e) => setMnemonic(e.target.value)}
                  style={{ width: "100%", padding: "10px 12px", fontSize: "14px", backgroundColor: "var(--background-tertiary)", border: "1px solid transparent", borderRadius: "6px", color: "var(--text-primary)", outline: "none", boxSizing: "border-box" as const, resize: "vertical" as const, minHeight: 72 }}
                  rows={3}
                />
              </div>

              <div style={{ marginBottom: "16px", marginTop: 12 }}>
                <label style={{ fontSize: "12px", fontWeight: 600, textTransform: "uppercase" as const, letterSpacing: "0.02em", color: "var(--text-tertiary-muted)", display: "block", marginBottom: "6px" }}>New Password (min 8 characters)</label>
                <input
                  type="password"
                  placeholder="Choose a password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleRecover(); }}
                  style={{ width: "100%", padding: "10px 12px", fontSize: "14px", backgroundColor: "var(--background-tertiary)", border: "1px solid transparent", borderRadius: "6px", color: "var(--text-primary)", outline: "none", boxSizing: "border-box" as const }}
                />
              </div>

              {error && <div style={{ color: "var(--red)", fontSize: "13px", marginBottom: "12px", padding: "8px 12px", background: "rgba(237,66,69,0.1)", borderRadius: "6px" }}>{error}</div>}

              <button
                className={clsx(btnStyles.button, btnStyles.primary)}
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
      </div>
    </div>
  );
};
