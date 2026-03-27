import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import {
  MnemonicModal,
  RecoverModal,
  KeyBackupScreen,
  WelcomeScreen,
  ServerConnectScreen,
  LoginScreen,
} from '../components/AuthScreens';
import { AppContext } from '../components/AppContext';
import type { AppContextType } from '../components/AppContext';

const createMockContext = (overrides: Partial<AppContextType> = {}): AppContextType => ({
  serverUrl: '',
  setServerUrl: vi.fn(),
  serverAvailable: false,
  serverConnecting: false,
  serverVersion: '',
  showServerScreen: false,
  setShowServerScreen: vi.fn(),
  showWelcomeScreen: false,
  setShowWelcomeScreen: vi.fn(),
  welcomeMode: 'choose',
  setWelcomeMode: vi.fn(),
  inviteLinkInput: '',
  setInviteLinkInput: vi.fn(),
  inviteError: '',
  setInviteError: vi.fn(),
  inviteConnecting: false,
  inviteRelayVersion: '',
  inviteNeedsRegister: false,
  invitePassword: '',
  setInvitePassword: vi.fn(),
  inviteDisplayName: '',
  setInviteDisplayName: vi.fn(),
  inviteJoining: false,
  isAuthenticated: false,
  isLoginMode: true,
  setIsLoginMode: vi.fn(),
  password: '',
  setPassword: vi.fn(),
  publicKey: '',
  authError: '',
  setAuthError: vi.fn(),
  publicKeyHash: '',
  hasExistingKey: false,
  showMnemonicModal: false,
  setShowMnemonicModal: vi.fn(),
  mnemonicPhrase: 'word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12 word13 word14 word15 word16 word17 word18 word19 word20 word21 word22 word23 word24',
  setMnemonicPhrase: vi.fn(),
  copyButtonText: 'Copy to Clipboard',
  setCopyButtonText: vi.fn(),
  mnemonicConfirmStep: 0,
  setMnemonicConfirmStep: vi.fn(),
  showRecoverModal: false,
  setShowRecoverModal: vi.fn(),
  recoverMnemonic: '',
  setRecoverMnemonic: vi.fn(),
  recoverPassword: '',
  setRecoverPassword: vi.fn(),
  recoverError: '',
  setRecoverError: vi.fn(),
  recoverLoading: false,
  showKeyBackup: false,
  setShowKeyBackup: vi.fn(),
  keyPair: null,
  encryptionEnabled: true,
  appState: {} as any,
  setAppState: vi.fn(),
  message: '',
  setMessage: vi.fn(),
  slowModeCooldown: 0,
  slowModeSeconds: 0,
  messageError: '',
  activeChannel: '',
  activeServer: 0,
  ws: null,
  connectionInfo: {} as any,
  lastConnectionError: '',
  setLastConnectionError: vi.fn(),
  replyingTo: null,
  setReplyingTo: vi.fn(),
  nodes: [],
  channels: [],
  members: [],
  selectedNodeId: null,
  selectedChannelId: null,
  isLoadingOlderMessages: false,
  copyToClipboard: vi.fn(),
  handleAuth: vi.fn(),
  handleServerConnect: vi.fn(),
  handleRecover: vi.fn(),
  handleInviteLinkSubmit: vi.fn(),
  handleInviteRegister: vi.fn(),
  handleNodeSelect: vi.fn(),
  ...overrides,
} as AppContextType);

describe('MnemonicModal', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders mnemonic phrase', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <MnemonicModal />
      </AppContext.Provider>
    );

    expect(screen.getByText('Save Your Recovery Phrase')).toBeInTheDocument();
    expect(screen.getByText(/word1 word2 word3/)).toBeInTheDocument();
  });

  it('displays warning about recovery phrase', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <MnemonicModal />
      </AppContext.Provider>
    );

    expect(screen.getByText(/It will NOT be shown again/)).toBeInTheDocument();
  });

  it('calls copyToClipboard when copy button is clicked', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <MnemonicModal />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText('Copy to Clipboard'));

    expect(ctx.copyToClipboard).toHaveBeenCalledWith(ctx.mnemonicPhrase);
    expect(ctx.setCopyButtonText).toHaveBeenCalledWith('Copied!');
  });

  it('shows confirmation button progression', () => {
    const ctx = createMockContext();
    const { rerender } = render(
      <AppContext.Provider value={ctx}>
        <MnemonicModal />
      </AppContext.Provider>
    );

    expect(screen.getByText(/I've saved my phrase/)).toBeInTheDocument();

    const newCtx = createMockContext({ mnemonicConfirmStep: 1 });
    rerender(
      <AppContext.Provider value={newCtx}>
        <MnemonicModal />
      </AppContext.Provider>
    );

    expect(screen.getByText('Are you absolutely sure?')).toBeInTheDocument();

    const finalCtx = createMockContext({ mnemonicConfirmStep: 2 });
    rerender(
      <AppContext.Provider value={finalCtx}>
        <MnemonicModal />
      </AppContext.Provider>
    );

    expect(screen.getByText('This is your ONLY way to recover your account!')).toBeInTheDocument();
  });

  it('progresses through confirmation steps', () => {
    const setMnemonicConfirmStep = vi.fn();
    const ctx = createMockContext({ setMnemonicConfirmStep });
    render(
      <AppContext.Provider value={ctx}>
        <MnemonicModal />
      </AppContext.Provider>
    );

    const confirmButton = screen.getByText(/I've saved my phrase/);
    fireEvent.click(confirmButton);

    expect(setMnemonicConfirmStep).toHaveBeenCalledWith(1);
  });

  it('closes modal and redirects to login after final confirmation', () => {
    const setShowMnemonicModal = vi.fn();
    const setIsLoginMode = vi.fn();
    const ctx = createMockContext({
      mnemonicConfirmStep: 2,
      isAuthenticated: false,
      setShowMnemonicModal,
      setIsLoginMode,
    });
    render(
      <AppContext.Provider value={ctx}>
        <MnemonicModal />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText('This is your ONLY way to recover your account!'));

    expect(setShowMnemonicModal).toHaveBeenCalledWith(false);
    expect(setIsLoginMode).toHaveBeenCalledWith(true);
  });

  it('does not redirect if already authenticated', () => {
    const setIsLoginMode = vi.fn();
    const ctx = createMockContext({
      mnemonicConfirmStep: 2,
      isAuthenticated: true,
      setIsLoginMode,
    });
    render(
      <AppContext.Provider value={ctx}>
        <MnemonicModal />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText('This is your ONLY way to recover your account!'));

    expect(setIsLoginMode).not.toHaveBeenCalled();
  });
});

describe('RecoverModal', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders recovery form', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <RecoverModal />
      </AppContext.Provider>
    );

    expect(screen.getByRole('heading', { name: 'Recover Identity' })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/word1 word2 word3/)).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Your account password')).toBeInTheDocument();
  });

  it('updates mnemonic input', () => {
    const setRecoverMnemonic = vi.fn();
    const ctx = createMockContext({ setRecoverMnemonic });
    render(
      <AppContext.Provider value={ctx}>
        <RecoverModal />
      </AppContext.Provider>
    );

    const mnemonicInput = screen.getByPlaceholderText(/word1 word2 word3/);
    fireEvent.change(mnemonicInput, { target: { value: 'test mnemonic phrase' } });

    expect(setRecoverMnemonic).toHaveBeenCalledWith('test mnemonic phrase');
  });

  it('updates password input', () => {
    const setRecoverPassword = vi.fn();
    const ctx = createMockContext({ setRecoverPassword });
    render(
      <AppContext.Provider value={ctx}>
        <RecoverModal />
      </AppContext.Provider>
    );

    const passwordInput = screen.getByPlaceholderText('Your account password');
    fireEvent.change(passwordInput, { target: { value: 'password123' } });

    expect(setRecoverPassword).toHaveBeenCalledWith('password123');
  });

  it('calls handleRecover on button click', () => {
    const handleRecover = vi.fn();
    const ctx = createMockContext({
      recoverMnemonic: 'test phrase',
      recoverPassword: 'password',
      handleRecover,
    });
    render(
      <AppContext.Provider value={ctx}>
        <RecoverModal />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByRole('button', { name: 'Recover Identity' }));

    expect(handleRecover).toHaveBeenCalled();
  });

  it('calls handleRecover on Enter key', () => {
    const handleRecover = vi.fn();
    const ctx = createMockContext({
      recoverMnemonic: 'test phrase',
      recoverPassword: 'password',
      handleRecover,
    });
    render(
      <AppContext.Provider value={ctx}>
        <RecoverModal />
      </AppContext.Provider>
    );

    const passwordInput = screen.getByPlaceholderText('Your account password');
    fireEvent.keyDown(passwordInput, { key: 'Enter' });

    expect(handleRecover).toHaveBeenCalled();
  });

  it('disables button when fields are empty', () => {
    const ctx = createMockContext({ recoverMnemonic: '', recoverPassword: '' });
    render(
      <AppContext.Provider value={ctx}>
        <RecoverModal />
      </AppContext.Provider>
    );

    const button = screen.getByRole('button', { name: 'Recover Identity' });
    expect(button).toBeDisabled();
  });

  it('disables button when loading', () => {
    const ctx = createMockContext({
      recoverMnemonic: 'phrase',
      recoverPassword: 'pass',
      recoverLoading: true,
    });
    render(
      <AppContext.Provider value={ctx}>
        <RecoverModal />
      </AppContext.Provider>
    );

    const button = screen.getByRole('button', { name: 'Recovering...' });
    expect(button).toBeInTheDocument();
    expect(button).toBeDisabled();
  });

  it('displays error message', () => {
    const ctx = createMockContext({ recoverError: 'Invalid recovery phrase' });
    render(
      <AppContext.Provider value={ctx}>
        <RecoverModal />
      </AppContext.Provider>
    );

    expect(screen.getByText('Invalid recovery phrase')).toBeInTheDocument();
  });

  it('closes modal on back button click', () => {
    const setShowRecoverModal = vi.fn();
    const ctx = createMockContext({ setShowRecoverModal });
    render(
      <AppContext.Provider value={ctx}>
        <RecoverModal />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText('← Back'));

    expect(setShowRecoverModal).toHaveBeenCalledWith(false);
  });
});

describe('KeyBackupScreen', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders key backup information', () => {
    const ctx = createMockContext({
      publicKeyHash: 'abc123def456',
      publicKey: 'PUBLIC_KEY_DATA',
    });
    render(
      <AppContext.Provider value={ctx}>
        <KeyBackupScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText('Backup Your Key')).toBeInTheDocument();
    expect(screen.getByText('abc123def456')).toBeInTheDocument();
    expect(screen.getByDisplayValue('PUBLIC_KEY_DATA')).toBeInTheDocument();
  });

  it('shows computing placeholder when hash not ready', () => {
    const ctx = createMockContext({ publicKeyHash: '' });
    render(
      <AppContext.Provider value={ctx}>
        <KeyBackupScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText('computing...')).toBeInTheDocument();
  });

  it('copies public key to clipboard', () => {
    global.alert = vi.fn();
    const ctx = createMockContext({ publicKey: 'PUBLIC_KEY_DATA' });
    render(
      <AppContext.Provider value={ctx}>
        <KeyBackupScreen />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText('Copy Public Key'));

    expect(ctx.copyToClipboard).toHaveBeenCalledWith('PUBLIC_KEY_DATA');
    expect(global.alert).toHaveBeenCalledWith('Public key copied to clipboard!');
  });

  it('navigates to login on continue button click', () => {
    const setShowKeyBackup = vi.fn();
    const setIsLoginMode = vi.fn();
    const ctx = createMockContext({ setShowKeyBackup, setIsLoginMode });
    render(
      <AppContext.Provider value={ctx}>
        <KeyBackupScreen />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText('Continue to Login'));

    expect(setShowKeyBackup).toHaveBeenCalledWith(false);
    expect(setIsLoginMode).toHaveBeenCalledWith(true);
  });
});

describe('WelcomeScreen', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders welcome screen in choose mode', () => {
    const ctx = createMockContext({ serverAvailable: true });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText(/Privacy-first community communications/)).toBeInTheDocument();
    expect(screen.getByText('Log in')).toBeInTheDocument();
    expect(screen.getByText('Create new identity')).toBeInTheDocument();
  });

  it('shows invite option when server available', () => {
    const ctx = createMockContext({ serverAvailable: true });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText('I have an invite link')).toBeInTheDocument();
  });

  it('shows different options when server not available', () => {
    const ctx = createMockContext({ serverAvailable: false });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText('Set up a new relay (admin)')).toBeInTheDocument();
    expect(screen.queryByText('Log in')).not.toBeInTheDocument();
  });

  it('switches to login mode when login clicked', () => {
    const setShowWelcomeScreen = vi.fn();
    const setIsLoginMode = vi.fn();
    const ctx = createMockContext({ serverAvailable: true, setShowWelcomeScreen, setIsLoginMode });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText('Log in'));

    expect(setShowWelcomeScreen).toHaveBeenCalledWith(false);
    expect(setIsLoginMode).toHaveBeenCalledWith(true);
  });

  it('switches to register mode when create identity clicked', () => {
    const setShowWelcomeScreen = vi.fn();
    const setIsLoginMode = vi.fn();
    const ctx = createMockContext({ serverAvailable: true, setShowWelcomeScreen, setIsLoginMode });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText('Create new identity'));

    expect(setShowWelcomeScreen).toHaveBeenCalledWith(false);
    expect(setIsLoginMode).toHaveBeenCalledWith(false);
  });

  it('switches to invite mode', () => {
    const setWelcomeMode = vi.fn();
    const ctx = createMockContext({ serverAvailable: true, setWelcomeMode });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText('I have an invite link'));

    expect(setWelcomeMode).toHaveBeenCalledWith('invite');
  });

  it('renders invite mode without registration', () => {
    const ctx = createMockContext({ welcomeMode: 'invite', inviteNeedsRegister: false });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText('Join via Invite')).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/accord:\/\//)).toBeInTheDocument();
  });

  it('updates invite link input', () => {
    const setInviteLinkInput = vi.fn();
    const ctx = createMockContext({
      welcomeMode: 'invite',
      inviteNeedsRegister: false,
      setInviteLinkInput,
    });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    const input = screen.getByPlaceholderText(/accord:\/\//);
    fireEvent.change(input, { target: { value: 'accord://host/invite/CODE' } });

    expect(setInviteLinkInput).toHaveBeenCalledWith('accord://host/invite/CODE');
  });

  it('submits invite link on button click', () => {
    const handleInviteLinkSubmit = vi.fn();
    const ctx = createMockContext({
      welcomeMode: 'invite',
      inviteNeedsRegister: false,
      inviteLinkInput: 'accord://host/invite/CODE',
      handleInviteLinkSubmit,
    });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText('Join'));

    expect(handleInviteLinkSubmit).toHaveBeenCalled();
  });

  it('submits invite link on Enter key', () => {
    const handleInviteLinkSubmit = vi.fn();
    const ctx = createMockContext({
      welcomeMode: 'invite',
      inviteNeedsRegister: false,
      inviteLinkInput: 'accord://host/invite/CODE',
      handleInviteLinkSubmit,
    });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    const input = screen.getByPlaceholderText(/accord:\/\//);
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(handleInviteLinkSubmit).toHaveBeenCalled();
  });

  it('displays invite error', () => {
    const ctx = createMockContext({
      welcomeMode: 'invite',
      inviteNeedsRegister: false,
      inviteError: 'Invalid invite link',
    });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText('Invalid invite link')).toBeInTheDocument();
  });

  it('displays relay version on successful connection', () => {
    const ctx = createMockContext({
      welcomeMode: 'invite',
      inviteNeedsRegister: false,
      inviteRelayVersion: '1.2.3',
    });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText(/Connected to relay v1.2.3/)).toBeInTheDocument();
  });

  it('renders invite registration screen', () => {
    const ctx = createMockContext({
      welcomeMode: 'invite',
      inviteNeedsRegister: true,
    });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    expect(screen.getByRole('heading', { name: 'Create Your Identity' })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/How others will see you/)).toBeInTheDocument();
  });

  it('updates invite display name', () => {
    const setInviteDisplayName = vi.fn();
    const ctx = createMockContext({
      welcomeMode: 'invite',
      inviteNeedsRegister: true,
      setInviteDisplayName,
    });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    const input = screen.getByPlaceholderText(/How others will see you/);
    fireEvent.change(input, { target: { value: 'Alice' } });

    expect(setInviteDisplayName).toHaveBeenCalledWith('Alice');
  });

  it('updates invite password', () => {
    const setInvitePassword = vi.fn();
    const ctx = createMockContext({
      welcomeMode: 'invite',
      inviteNeedsRegister: true,
      setInvitePassword,
    });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    const input = screen.getByPlaceholderText('Choose a password');
    fireEvent.change(input, { target: { value: 'password123' } });

    expect(setInvitePassword).toHaveBeenCalledWith('password123');
  });

  it('disables register button when password too short', () => {
    const ctx = createMockContext({
      welcomeMode: 'invite',
      inviteNeedsRegister: true,
      invitePassword: 'short',
    });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText('Create Identity & Join')).toBeDisabled();
  });

  it('submits invite registration', () => {
    const handleInviteRegister = vi.fn();
    const ctx = createMockContext({
      welcomeMode: 'invite',
      inviteNeedsRegister: true,
      invitePassword: 'password123',
      handleInviteRegister,
    });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText('Create Identity & Join'));

    expect(handleInviteRegister).toHaveBeenCalled();
  });

  it('renders admin mode', () => {
    const ctx = createMockContext({ welcomeMode: 'admin' });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    expect(screen.getByRole('heading', { name: 'Connect to Relay' })).toBeInTheDocument();
    expect(screen.getByPlaceholderText('http://localhost:8080')).toBeInTheDocument();
  });

  it('connects to server in admin mode', () => {
    const handleServerConnect = vi.fn();
    const ctx = createMockContext({
      welcomeMode: 'admin',
      serverUrl: 'http://localhost:8080',
      handleServerConnect,
    });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText('Connect'));

    expect(handleServerConnect).toHaveBeenCalled();
  });

  it('shows server version after connection', () => {
    const ctx = createMockContext({
      welcomeMode: 'admin',
      serverVersion: '1.0.0',
    });
    render(
      <AppContext.Provider value={ctx}>
        <WelcomeScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText(/Connected — server v1.0.0/)).toBeInTheDocument();
  });
});

describe('ServerConnectScreen', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders server connection form', () => {
    const ctx = createMockContext();
    render(
      <AppContext.Provider value={ctx}>
        <ServerConnectScreen />
      </AppContext.Provider>
    );

    expect(screen.getByRole('heading', { name: 'Connect to Relay' })).toBeInTheDocument();
    expect(screen.getByPlaceholderText('http://localhost:8080')).toBeInTheDocument();
  });

  it('updates server URL input', () => {
    const setServerUrl = vi.fn();
    const ctx = createMockContext({ setServerUrl });
    render(
      <AppContext.Provider value={ctx}>
        <ServerConnectScreen />
      </AppContext.Provider>
    );

    const input = screen.getByPlaceholderText('http://localhost:8080');
    fireEvent.change(input, { target: { value: 'http://example.com:8080' } });

    expect(setServerUrl).toHaveBeenCalledWith('http://example.com:8080');
  });

  it('connects to server on button click', () => {
    const handleServerConnect = vi.fn();
    const ctx = createMockContext({ handleServerConnect });
    render(
      <AppContext.Provider value={ctx}>
        <ServerConnectScreen />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText('Connect'));

    expect(handleServerConnect).toHaveBeenCalled();
  });

  it('connects to server on Enter key', () => {
    const handleServerConnect = vi.fn();
    const ctx = createMockContext({ handleServerConnect });
    render(
      <AppContext.Provider value={ctx}>
        <ServerConnectScreen />
      </AppContext.Provider>
    );

    const input = screen.getByPlaceholderText('http://localhost:8080');
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(handleServerConnect).toHaveBeenCalled();
  });

  it('displays error message', () => {
    const ctx = createMockContext({ authError: 'Connection failed' });
    render(
      <AppContext.Provider value={ctx}>
        <ServerConnectScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText('Connection failed')).toBeInTheDocument();
  });

  it('displays server version on success', () => {
    const ctx = createMockContext({ serverVersion: '2.0.0' });
    render(
      <AppContext.Provider value={ctx}>
        <ServerConnectScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText(/Connected — server v2.0.0/)).toBeInTheDocument();
  });

  it('disables button when connecting', () => {
    const ctx = createMockContext({ serverConnecting: true });
    render(
      <AppContext.Provider value={ctx}>
        <ServerConnectScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText('Connecting...')).toBeInTheDocument();
    expect(screen.getByText('Connecting...')).toBeDisabled();
  });
});

describe('LoginScreen', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders login mode', () => {
    const ctx = createMockContext({ isLoginMode: true });
    render(
      <AppContext.Provider value={ctx}>
        <LoginScreen />
      </AppContext.Provider>
    );

    expect(screen.getByRole('heading', { name: 'Login to Accord' })).toBeInTheDocument();
    expect(screen.getByPlaceholderText('Enter your password')).toBeInTheDocument();
  });

  it('renders register mode', () => {
    const ctx = createMockContext({ isLoginMode: false });
    render(
      <AppContext.Provider value={ctx}>
        <LoginScreen />
      </AppContext.Provider>
    );

    expect(screen.getByRole('heading', { name: 'Create Identity' })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Choose a password/)).toBeInTheDocument();
  });

  it('updates password input', () => {
    const setPassword = vi.fn();
    const ctx = createMockContext({ setPassword });
    render(
      <AppContext.Provider value={ctx}>
        <LoginScreen />
      </AppContext.Provider>
    );

    const input = screen.getByPlaceholderText('Enter your password');
    fireEvent.change(input, { target: { value: 'mypassword' } });

    expect(setPassword).toHaveBeenCalledWith('mypassword');
  });

  it('calls handleAuth on button click', () => {
    const handleAuth = vi.fn();
    const ctx = createMockContext({ handleAuth });
    render(
      <AppContext.Provider value={ctx}>
        <LoginScreen />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByRole('button', { name: 'Login' }));

    expect(handleAuth).toHaveBeenCalled();
  });

  it('calls handleAuth on Enter key', () => {
    const handleAuth = vi.fn();
    const ctx = createMockContext({ handleAuth });
    render(
      <AppContext.Provider value={ctx}>
        <LoginScreen />
      </AppContext.Provider>
    );

    const input = screen.getByPlaceholderText('Enter your password');
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(handleAuth).toHaveBeenCalled();
  });

  it('displays auth error', () => {
    const ctx = createMockContext({ authError: 'Invalid credentials' });
    render(
      <AppContext.Provider value={ctx}>
        <LoginScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText('Invalid credentials')).toBeInTheDocument();
  });

  it('shows password length hint in register mode', () => {
    const ctx = createMockContext({ isLoginMode: false, password: 'short' });
    render(
      <AppContext.Provider value={ctx}>
        <LoginScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText('Password must be at least 8 characters')).toBeInTheDocument();
  });

  it('toggles between login and register modes', () => {
    const setIsLoginMode = vi.fn();
    const ctx = createMockContext({ isLoginMode: true, setIsLoginMode });
    render(
      <AppContext.Provider value={ctx}>
        <LoginScreen />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText(/Need to create an identity/));

    expect(setIsLoginMode).toHaveBeenCalledWith(false);
  });

  it('shows connected status when server available', () => {
    const ctx = createMockContext({ serverAvailable: true });
    render(
      <AppContext.Provider value={ctx}>
        <LoginScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText('● Connected')).toBeInTheDocument();
  });

  it('shows keypair found status', () => {
    const ctx = createMockContext({ hasExistingKey: true, isLoginMode: true });
    render(
      <AppContext.Provider value={ctx}>
        <LoginScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText(/Keypair found/)).toBeInTheDocument();
  });

  it('opens recovery modal', () => {
    const setShowRecoverModal = vi.fn();
    const ctx = createMockContext({ setShowRecoverModal });
    render(
      <AppContext.Provider value={ctx}>
        <LoginScreen />
      </AppContext.Provider>
    );

    fireEvent.click(screen.getByText('Recover with recovery phrase'));

    expect(setShowRecoverModal).toHaveBeenCalledWith(true);
  });

  it('shows encryption info in register mode', () => {
    const ctx = createMockContext({ isLoginMode: false, encryptionEnabled: true });
    render(
      <AppContext.Provider value={ctx}>
        <LoginScreen />
      </AppContext.Provider>
    );

    expect(screen.getByText(/ECDH P-256 keypair/)).toBeInTheDocument();
  });
});
