import { useState, useEffect, useCallback } from "react";
import { api } from "./api";
import { AccordWebSocket } from "./ws";
import { AppState, Message, WsIncomingMessage, Node, Channel, NodeMember, User } from "./types";
import { 
  generateKeyPair, 
  exportPublicKey, 
  saveKeyToStorage, 
  loadKeyFromStorage, 
  getChannelKey, 
  encryptMessage, 
  decryptMessage, 
  clearChannelKeyCache,
  isCryptoSupported 
} from "./crypto";
import { FileUploadButton, FileList } from "./FileManager";

// Mock data as fallback
const MOCK_SERVERS = ["Accord Dev", "Gaming", "Music"];
const MOCK_CHANNELS = ["# general", "# random", "# dev", "# off-topic"];
const MOCK_USERS = ["Alice", "Bob", "Charlie", "Diana", "Eve"];
const MOCK_MESSAGES = [
  { id: "1", author: "Alice", content: "Hey everyone! Welcome to Accord 👋", time: "12:01 PM", timestamp: Date.now() },
  { id: "2", author: "Bob", content: "This is looking great so far!", time: "12:02 PM", timestamp: Date.now() },
  { id: "3", author: "Charlie", content: "Can't wait for E2EE to land", time: "12:03 PM", timestamp: Date.now() },
  { id: "4", author: "Diana", content: "The UI is giving me good vibes", time: "12:05 PM", timestamp: Date.now() },
  { id: "5", author: "Alice", content: "We're building something special here", time: "12:06 PM", timestamp: Date.now() },
];

function App() {
  // Authentication state
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoginMode, setIsLoginMode] = useState(true);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [authError, setAuthError] = useState("");

  // Encryption state
  const [keyPair, setKeyPair] = useState<CryptoKeyPair | null>(null);
  const [encryptionEnabled] = useState(isCryptoSupported());

  // App state
  const [appState, setAppState] = useState<AppState>({
    isAuthenticated: false,
    nodes: [],
    messages: MOCK_MESSAGES,
    isConnected: false,
  });

  const [message, setMessage] = useState("");
  const [activeChannel, setActiveChannel] = useState("# general");
  const [activeServer, setActiveServer] = useState(0);
  const [serverAvailable, setServerAvailable] = useState(false);
  const [ws, setWs] = useState<AccordWebSocket | null>(null);

  // Real data state
  const [nodes, setNodes] = useState<Node[]>([]);
  const [channels, setChannels] = useState<Channel[]>([]);
  const [members, setMembers] = useState<Array<NodeMember & { user: User }>>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedChannelId, setSelectedChannelId] = useState<string | null>(null);

  // Role-based permission state
  const [userRoles, setUserRoles] = useState<Record<string, 'admin' | 'moderator' | 'member'>>({});
  const [showCreateChannelForm, setShowCreateChannelForm] = useState(false);
  const [newChannelName, setNewChannelName] = useState("");
  const [newChannelType, setNewChannelType] = useState("text");
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [generatedInvite, setGeneratedInvite] = useState<string>("");
  const [error, setError] = useState<string>("");

  // Permission checking utilities
  const getCurrentUserRole = useCallback((nodeId: string) => {
    return userRoles[nodeId] || 'member';
  }, [userRoles]);

  const hasPermission = useCallback((nodeId: string, permission: 'CreateChannel' | 'DeleteChannel' | 'ManageMembers' | 'KickMembers' | 'ManageInvites' | 'ManageNode') => {
    const role = getCurrentUserRole(nodeId);
    
    switch (role) {
      case 'admin':
        return true; // Admin has all permissions
      case 'moderator':
        return ['KickMembers', 'ManageInvites'].includes(permission);
      case 'member':
        return false; // Members have no admin permissions
      default:
        return false;
    }
  }, [getCurrentUserRole]);

  const getRoleBadge = (role: 'admin' | 'moderator' | 'member') => {
    switch (role) {
      case 'admin': return '👑';
      case 'moderator': return '🛡️';
      default: return '';
    }
  };

  const handleApiError = (error: any) => {
    if (error.message && error.message.includes('403')) {
      setError("You don't have permission to perform this action");
    } else {
      setError(error.message || "An error occurred");
    }
    setTimeout(() => setError(""), 5000); // Clear error after 5 seconds
  };

  // Check server availability on mount
  useEffect(() => {
    const checkServer = async () => {
      const available = await api.testConnection();
      setServerAvailable(available);
      if (!available) {
        console.log("Server unavailable, using mock data");
      }
    };
    checkServer();
  }, []);

  // WebSocket event handlers
  const setupWebSocketHandlers = useCallback((socket: AccordWebSocket) => {
    socket.on('connected', () => {
      console.log('WebSocket connected');
      setAppState(prev => ({ ...prev, isConnected: true }));
    });

    socket.on('disconnected', () => {
      console.log('WebSocket disconnected');
      setAppState(prev => ({ ...prev, isConnected: false }));
    });

    socket.on('message', (msg: WsIncomingMessage) => {
      console.log('WebSocket message:', msg);
    });

    socket.on('channel_message', async (data) => {
      // Handle incoming channel messages
      let content = data.encrypted_data;
      let isEncrypted = false;

      // Try to decrypt the message if we have encryption enabled and keys
      if (encryptionEnabled && keyPair && data.channel_id) {
        try {
          const channelKey = await getChannelKey(keyPair.privateKey, data.channel_id);
          content = await decryptMessage(channelKey, data.encrypted_data);
          isEncrypted = true;
        } catch (error) {
          console.warn('Failed to decrypt message, showing encrypted data:', error);
          // Keep the encrypted data if decryption fails
        }
      }

      const newMessage: Message = {
        id: data.message_id || Math.random().toString(),
        author: data.from || "Unknown",
        content: content,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        timestamp: data.timestamp * 1000,
        channel_id: data.channel_id,
        isEncrypted: isEncrypted,
      };

      setAppState(prev => ({
        ...prev,
        messages: [...prev.messages, newMessage]
      }));
    });

    socket.on('node_info', (data) => {
      // Update node info when received
      if (data.data) {
        setAppState(prev => ({
          ...prev,
          nodes: prev.nodes.map(node => 
            node.id === data.data.id ? data.data : node
          )
        }));
      }
    });

    socket.on('error', (error: Error) => {
      console.error('WebSocket error:', error);
    });
  }, [encryptionEnabled, keyPair]);

  // Load user's nodes
  const loadNodes = useCallback(async () => {
    if (!appState.token || !serverAvailable) return;
    
    try {
      const userNodes = await api.getUserNodes(appState.token);
      setNodes(userNodes);
      
      // Auto-select first node if none selected
      if (userNodes.length > 0 && !selectedNodeId) {
        setSelectedNodeId(userNodes[0].id);
      }
    } catch (error) {
      console.error('Failed to load nodes:', error);
    }
  }, [appState.token, serverAvailable, selectedNodeId]);

  // Load channels for selected node
  const loadChannels = useCallback(async (nodeId: string) => {
    if (!appState.token || !serverAvailable) return;
    
    try {
      const nodeChannels = await api.getNodeChannels(nodeId, appState.token);
      setChannels(nodeChannels);
      
      // Auto-select first channel if none selected
      if (nodeChannels.length > 0 && !selectedChannelId) {
        setSelectedChannelId(nodeChannels[0].id);
      }
    } catch (error) {
      console.error('Failed to load channels:', error);
      handleApiError(error);
      setChannels([]);
    }
  }, [appState.token, serverAvailable, selectedChannelId]);

  // Load members for selected node
  const loadMembers = useCallback(async (nodeId: string) => {
    if (!appState.token || !serverAvailable) return;
    
    try {
      const nodeMembers = await api.getNodeMembers(nodeId, appState.token);
      setMembers(nodeMembers);
      
      // Find current user's role in this node
      const currentUserId = localStorage.getItem('accord_user_id');
      if (currentUserId) {
        const currentUserMember = nodeMembers.find(member => member.user_id === currentUserId);
        if (currentUserMember) {
          setUserRoles(prev => ({
            ...prev,
            [nodeId]: currentUserMember.role
          }));
        }
      }
    } catch (error) {
      console.error('Failed to load members:', error);
      handleApiError(error);
      setMembers([]);
    }
  }, [appState.token, serverAvailable]);

  // Load message history for selected channel
  const loadMessages = useCallback(async (channelId: string) => {
    if (!appState.token || !serverAvailable) return;
    
    try {
      const messages = await api.getChannelMessages(channelId, appState.token);
      
      // Format messages for display
      const formattedMessages = messages.map(msg => ({
        ...msg,
        time: msg.time || new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }));
      
      setAppState(prev => ({
        ...prev,
        messages: formattedMessages,
      }));
    } catch (error) {
      console.error('Failed to load messages:', error);
      handleApiError(error);
      setAppState(prev => ({
        ...prev,
        messages: [],
      }));
    }
  }, [appState.token, serverAvailable]);

  // Handle node selection
  const handleNodeSelect = useCallback((nodeId: string, index: number) => {
    setSelectedNodeId(nodeId);
    setSelectedChannelId(null);
    setActiveServer(index);
    setChannels([]);
    setMembers([]);
    setAppState(prev => ({ ...prev, messages: [] }));
    
    // Load channels and members for the selected node
    loadChannels(nodeId);
    loadMembers(nodeId);
  }, [loadChannels, loadMembers]);

  // Handle channel selection
  const handleChannelSelect = useCallback((channelId: string, channelName: string) => {
    setSelectedChannelId(channelId);
    setActiveChannel(channelName);
    setAppState(prev => ({ ...prev, activeChannel: channelId }));
    
    // Load message history for the selected channel
    loadMessages(channelId);
    
    // Join channel via WebSocket if connected
    if (ws && ws.isSocketConnected()) {
      ws.joinChannel(channelId);
    }
  }, [loadMessages, ws]);

  // Handle creating a new channel
  const handleCreateChannel = async () => {
    if (!selectedNodeId || !appState.token || !newChannelName.trim()) return;
    
    try {
      await api.createChannel(selectedNodeId, newChannelName.trim(), newChannelType, appState.token);
      setShowCreateChannelForm(false);
      setNewChannelName("");
      setNewChannelType("text");
      // Reload channels
      await loadChannels(selectedNodeId);
    } catch (error) {
      console.error('Failed to create channel:', error);
      handleApiError(error);
    }
  };

  // Handle generating an invite
  const handleGenerateInvite = async () => {
    if (!selectedNodeId || !appState.token) return;
    
    try {
      const response = await api.createInvite(selectedNodeId, appState.token);
      setGeneratedInvite(response.invite_code);
      setShowInviteModal(true);
    } catch (error) {
      console.error('Failed to generate invite:', error);
      handleApiError(error);
    }
  };

  // Handle kicking a member
  const handleKickMember = async (userId: string, username: string) => {
    if (!selectedNodeId || !appState.token) return;
    
    const confirmed = window.confirm(`Are you sure you want to kick ${username} from this node?`);
    if (!confirmed) return;
    
    try {
      await api.kickMember(selectedNodeId, userId, appState.token);
      // Reload members
      await loadMembers(selectedNodeId);
    } catch (error) {
      console.error('Failed to kick member:', error);
      handleApiError(error);
    }
  };

  // Handle deleting a channel
  const handleDeleteChannel = async (channelId: string, channelName: string) => {
    if (!appState.token) return;
    
    const confirmed = window.confirm(`Are you sure you want to delete #${channelName}? This action cannot be undone.`);
    if (!confirmed) return;
    
    try {
      await api.deleteChannel(channelId, appState.token);
      // If we deleted the currently selected channel, clear selection
      if (channelId === selectedChannelId) {
        setSelectedChannelId(null);
        setActiveChannel("# general");
      }
      // Reload channels
      if (selectedNodeId) {
        await loadChannels(selectedNodeId);
      }
    } catch (error) {
      console.error('Failed to delete channel:', error);
      handleApiError(error);
    }
  };

  // Handle authentication
  const handleAuth = async () => {
    if (!serverAvailable) {
      // Skip auth if server unavailable - generate keys for demo mode
      if (encryptionEnabled && !keyPair) {
        try {
          const newKeyPair = await generateKeyPair();
          await saveKeyToStorage(newKeyPair);
          setKeyPair(newKeyPair);
        } catch (error) {
          console.warn('Failed to generate demo keys:', error);
        }
      }
      setIsAuthenticated(true);
      setAppState(prev => ({ ...prev, isAuthenticated: true }));
      return;
    }

    setAuthError("");
    
    try {
      if (isLoginMode) {
        // Login
        const response = await api.login(username, password);
        
        // Store token and user info
        localStorage.setItem('accord_token', response.token);
        localStorage.setItem('accord_user_id', response.user_id);

        // Load existing keys or generate new ones
        if (encryptionEnabled) {
          let existingKeyPair = await loadKeyFromStorage();
          if (!existingKeyPair) {
            console.log('No existing keys found, generating new keypair');
            existingKeyPair = await generateKeyPair();
            await saveKeyToStorage(existingKeyPair);
          }
          setKeyPair(existingKeyPair);
        }
        
        setAppState(prev => ({
          ...prev,
          isAuthenticated: true,
          token: response.token,
          user: { id: response.user_id, username, public_key: "", created_at: 0 }
        }));
        setIsAuthenticated(true);

        // Initialize WebSocket connection
        const socket = new AccordWebSocket(response.token);
        setupWebSocketHandlers(socket);
        setWs(socket);
        socket.connect();

        // Load initial data
        setTimeout(() => loadNodes(), 100);

      } else {
        // Register
        let publicKeyToUse = publicKey.trim();
        
        // Auto-generate keypair if no public key provided and crypto is supported
        if (!publicKeyToUse && encryptionEnabled) {
          try {
            const newKeyPair = await generateKeyPair();
            publicKeyToUse = await exportPublicKey(newKeyPair.publicKey);
            await saveKeyToStorage(newKeyPair);
            setKeyPair(newKeyPair);
            setPublicKey(publicKeyToUse);
          } catch (error) {
            setAuthError("Failed to generate encryption keys");
            return;
          }
        }
        
        if (!publicKeyToUse) {
          setAuthError("Public key is required for registration");
          return;
        }
        
        await api.register(username, publicKeyToUse);
        
        // After successful registration, switch to login
        setIsLoginMode(true);
        setPassword("");
        setPublicKey("");
        setAuthError("");
        alert("Registration successful with E2EE enabled! Please log in.");
      }
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Authentication failed");
    }
  };

  // Handle logout
  const handleLogout = () => {
    if (ws) {
      ws.disconnect();
      setWs(null);
    }
    
    localStorage.removeItem('accord_token');
    localStorage.removeItem('accord_user_id');
    
    // Clear encryption state
    setKeyPair(null);
    clearChannelKeyCache();
    
    // Clear navigation state
    setNodes([]);
    setChannels([]);
    setMembers([]);
    setSelectedNodeId(null);
    setSelectedChannelId(null);
    
    setIsAuthenticated(false);
    setAppState({
      isAuthenticated: false,
      nodes: [],
      messages: MOCK_MESSAGES,
      isConnected: false,
    });
    
    setUsername("");
    setPassword("");
    setPublicKey("");
  };

  // Handle sending messages
  const handleSendMessage = async () => {
    if (!message.trim()) return;

    const channelToUse = selectedChannelId || appState.activeChannel;
    
    if (ws && ws.isSocketConnected() && channelToUse) {
      // Send via WebSocket if connected and we have an active channel
      try {
        let messageToSend = message;
        let isEncrypted = false;

        // Encrypt message if encryption is enabled and we have keys
        if (encryptionEnabled && keyPair && channelToUse) {
          try {
            const channelKey = await getChannelKey(keyPair.privateKey, channelToUse);
            messageToSend = await encryptMessage(channelKey, message);
            isEncrypted = true;
          } catch (error) {
            console.warn('Failed to encrypt message, sending plaintext:', error);
          }
        }

        ws.sendChannelMessage(channelToUse, messageToSend);

        // Add to local messages for immediate display
        const newMessage: Message = {
          id: Math.random().toString(),
          author: appState.user?.username || "You",
          content: message, // Show original plaintext locally
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          timestamp: Date.now(),
          channel_id: channelToUse,
          isEncrypted: isEncrypted,
        };

        setAppState(prev => ({
          ...prev,
          messages: [...prev.messages, newMessage]
        }));

      } catch (error) {
        console.error('Failed to send message:', error);
      }
    } else {
      // Add to local messages as fallback
      const newMessage: Message = {
        id: Math.random().toString(),
        author: appState.user?.username || "You",
        content: message,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        timestamp: Date.now(),
        isEncrypted: false,
      };

      setAppState(prev => ({
        ...prev,
        messages: [...prev.messages, newMessage]
      }));
    }

    setMessage("");
  };

  // Check for existing session on mount
  useEffect(() => {
    const checkExistingSession = async () => {
      const token = localStorage.getItem('accord_token');
      const userId = localStorage.getItem('accord_user_id');
      
      if (token && userId && serverAvailable) {
        // Load existing keys if available
        if (encryptionEnabled) {
          const existingKeyPair = await loadKeyFromStorage();
          if (existingKeyPair) {
            setKeyPair(existingKeyPair);
          }
        }

        setAppState(prev => ({
          ...prev,
          isAuthenticated: true,
          token,
          user: { id: userId, username: "User", public_key: "", created_at: 0 }
        }));
        setIsAuthenticated(true);

        // Initialize WebSocket connection
        const socket = new AccordWebSocket(token);
        setupWebSocketHandlers(socket);
        setWs(socket);
        socket.connect();

        // Load initial data
        setTimeout(() => loadNodes(), 100);
      }
    };

    checkExistingSession();
  }, [serverAvailable, setupWebSocketHandlers, encryptionEnabled, loadNodes]);

  // Load channels and members when node is selected
  useEffect(() => {
    if (selectedNodeId && appState.token && serverAvailable) {
      loadChannels(selectedNodeId);
      loadMembers(selectedNodeId);
    }
  }, [selectedNodeId, appState.token, serverAvailable, loadChannels, loadMembers]);

  // Load messages when channel is selected
  useEffect(() => {
    if (selectedChannelId && appState.token && serverAvailable) {
      loadMessages(selectedChannelId);
    }
  }, [selectedChannelId, appState.token, serverAvailable, loadMessages]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (ws) {
        ws.disconnect();
      }
    };
  }, [ws]);

  // Render authentication screen
  if (!isAuthenticated) {
    return (
      <div className="app">
        <div style={{ 
          display: 'flex', 
          justifyContent: 'center', 
          alignItems: 'center', 
          height: '100vh',
          background: '#2c2f33',
          color: '#ffffff'
        }}>
          <div style={{
            background: '#36393f',
            padding: '2rem',
            borderRadius: '8px',
            width: '400px',
            maxWidth: '90vw'
          }}>
            <h2 style={{ textAlign: 'center', marginBottom: '2rem' }}>
              {isLoginMode ? 'Login to Accord' : 'Register for Accord'}
            </h2>
            
            {!serverAvailable && (
              <div style={{ 
                background: '#faa61a', 
                color: '#000', 
                padding: '0.5rem', 
                borderRadius: '4px', 
                marginBottom: '1rem',
                fontSize: '0.9rem'
              }}>
                ⚠️ Server unavailable - click Login to use demo mode
              </div>
            )}

            <div style={{ marginBottom: '1rem' }}>
              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                style={{
                  width: '100%',
                  padding: '0.8rem',
                  borderRadius: '4px',
                  border: 'none',
                  background: '#40444b',
                  color: '#ffffff',
                  fontSize: '1rem'
                }}
              />
            </div>

            {isLoginMode && (
              <div style={{ marginBottom: '1rem' }}>
                <input
                  type="password"
                  placeholder="Password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.8rem',
                    borderRadius: '4px',
                    border: 'none',
                    background: '#40444b',
                    color: '#ffffff',
                    fontSize: '1rem'
                  }}
                />
              </div>
            )}

            {!isLoginMode && (
              <div style={{ marginBottom: '1rem' }}>
                <input
                  type="text"
                  placeholder={encryptionEnabled ? "Public Key (leave empty to auto-generate)" : "Public Key (for E2EE)"}
                  value={publicKey}
                  onChange={(e) => setPublicKey(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.8rem',
                    borderRadius: '4px',
                    border: 'none',
                    background: '#40444b',
                    color: '#ffffff',
                    fontSize: '1rem'
                  }}
                />
                {encryptionEnabled && (
                  <div style={{ 
                    fontSize: '0.8rem', 
                    color: '#b9bbbe', 
                    marginTop: '0.5rem' 
                  }}>
                    🔐 E2EE supported - keys will be auto-generated if empty
                  </div>
                )}
              </div>
            )}

            {authError && (
              <div style={{ 
                color: '#f04747', 
                marginBottom: '1rem', 
                fontSize: '0.9rem' 
              }}>
                {authError}
              </div>
            )}

            <button
              onClick={handleAuth}
              style={{
                width: '100%',
                padding: '0.8rem',
                borderRadius: '4px',
                border: 'none',
                background: '#7289da',
                color: '#ffffff',
                fontSize: '1rem',
                cursor: 'pointer',
                marginBottom: '1rem'
              }}
            >
              {isLoginMode ? 'Login' : 'Register'}
            </button>

            <div style={{ textAlign: 'center' }}>
              <button
                onClick={() => {
                  setIsLoginMode(!isLoginMode);
                  setAuthError("");
                  setPassword("");
                  setPublicKey("");
                }}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#7289da',
                  cursor: 'pointer',
                  textDecoration: 'underline'
                }}
              >
                {isLoginMode ? 'Need to register?' : 'Already have an account?'}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Use server data if available, fallback to mock data
  const servers = nodes.length > 0 ? nodes.map(n => n.name) : MOCK_SERVERS;
  const channelList = channels.length > 0 ? channels.map(ch => `# ${ch.name}`) : MOCK_CHANNELS;
  const users = members.length > 0 ? members.map(m => m.user.username) : MOCK_USERS;

  return (
    <div className="app">
      {/* Server list */}
      <div className="server-list">
        {servers.map((s, i) => {
          const nodeId = nodes.length > 0 ? nodes[i]?.id : null;
          return (
            <div
              key={nodeId || s}
              className={`server-icon ${i === activeServer ? "active" : ""}`}
              onClick={() => {
                if (nodeId) {
                  handleNodeSelect(nodeId, i);
                } else {
                  setActiveServer(i);
                }
              }}
              title={s}
            >
              {s[0]}
            </div>
          );
        })}
        <div className="server-icon add-server" title="Add Server">+</div>
      </div>

      {/* Channel sidebar */}
      <div className="channel-sidebar">
        <div className="sidebar-header" style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              {servers[activeServer]}
              {appState.isConnected && (
                <span style={{ fontSize: '10px', color: '#43b581', marginLeft: '8px' }}>●</span>
              )}
              {!serverAvailable && (
                <span style={{ fontSize: '10px', color: '#faa61a', marginLeft: '8px' }}>DEMO</span>
              )}
            </div>
            
            {/* Admin/Moderator Controls */}
            {selectedNodeId && (hasPermission(selectedNodeId, 'ManageInvites') || hasPermission(selectedNodeId, 'ManageNode')) && (
              <div style={{ display: 'flex', gap: '4px' }}>
                {hasPermission(selectedNodeId, 'ManageInvites') && (
                  <button
                    onClick={handleGenerateInvite}
                    style={{
                      background: '#7289da',
                      border: 'none',
                      color: '#ffffff',
                      padding: '2px 6px',
                      borderRadius: '2px',
                      cursor: 'pointer',
                      fontSize: '10px'
                    }}
                    title="Generate Invite"
                  >
                    Invite
                  </button>
                )}
                {hasPermission(selectedNodeId, 'ManageNode') && (
                  <button
                    onClick={() => alert('Node management features coming soon!')}
                    style={{
                      background: '#f04747',
                      border: 'none',
                      color: '#ffffff',
                      padding: '2px 6px',
                      borderRadius: '2px',
                      cursor: 'pointer',
                      fontSize: '10px'
                    }}
                    title="Manage Node"
                  >
                    Manage
                  </button>
                )}
              </div>
            )}
          </div>
          
          {/* Show current user's role */}
          {selectedNodeId && userRoles[selectedNodeId] && (
            <div style={{ fontSize: '11px', color: '#b9bbbe', opacity: 0.8 }}>
              {getRoleBadge(userRoles[selectedNodeId])} {userRoles[selectedNodeId]}
            </div>
          )}
        </div>
        
        <div className="channel-list">
          {channelList.map((ch, i) => {
            const channel = channels.length > 0 ? channels[i] : null;
            const isActive = channel ? channel.id === selectedChannelId : ch === activeChannel;
            const canDeleteChannel = selectedNodeId && hasPermission(selectedNodeId, 'DeleteChannel');
            
            return (
              <div
                key={channel?.id || ch}
                className={`channel ${isActive ? "active" : ""}`}
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
              >
                <div
                  onClick={() => {
                    if (channel) {
                      handleChannelSelect(channel.id, ch);
                    } else {
                      setActiveChannel(ch);
                    }
                  }}
                  style={{ flex: 1, cursor: 'pointer' }}
                >
                  {ch}
                </div>
                {canDeleteChannel && channel && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDeleteChannel(channel.id, channel.name);
                    }}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: '#f04747',
                      cursor: 'pointer',
                      fontSize: '12px',
                      padding: '2px 4px',
                      borderRadius: '2px',
                      opacity: 0.7,
                    }}
                    title="Delete channel"
                    onMouseEnter={(e) => e.currentTarget.style.opacity = '1'}
                    onMouseLeave={(e) => e.currentTarget.style.opacity = '0.7'}
                  >
                    ×
                  </button>
                )}
              </div>
            );
          })}
          
          {/* Create Channel Button for Admins */}
          {selectedNodeId && hasPermission(selectedNodeId, 'CreateChannel') && (
            <div style={{ marginTop: '8px', padding: '0 16px' }}>
              {!showCreateChannelForm ? (
                <button
                  onClick={() => setShowCreateChannelForm(true)}
                  style={{
                    background: '#43b581',
                    border: 'none',
                    color: '#ffffff',
                    padding: '6px 12px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontSize: '12px',
                    width: '100%'
                  }}
                >
                  + Create Channel
                </button>
              ) : (
                <div style={{ 
                  background: '#40444b', 
                  padding: '8px', 
                  borderRadius: '4px',
                  marginBottom: '8px'
                }}>
                  <input
                    type="text"
                    placeholder="Channel name"
                    value={newChannelName}
                    onChange={(e) => setNewChannelName(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '4px 8px',
                      marginBottom: '4px',
                      border: 'none',
                      borderRadius: '2px',
                      background: '#36393f',
                      color: '#ffffff',
                      fontSize: '12px'
                    }}
                  />
                  <select
                    value={newChannelType}
                    onChange={(e) => setNewChannelType(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '4px 8px',
                      marginBottom: '4px',
                      border: 'none',
                      borderRadius: '2px',
                      background: '#36393f',
                      color: '#ffffff',
                      fontSize: '12px'
                    }}
                  >
                    <option value="text">Text Channel</option>
                    <option value="voice">Voice Channel</option>
                  </select>
                  <div style={{ display: 'flex', gap: '4px' }}>
                    <button
                      onClick={handleCreateChannel}
                      style={{
                        flex: 1,
                        background: '#43b581',
                        border: 'none',
                        color: '#ffffff',
                        padding: '4px 8px',
                        borderRadius: '2px',
                        cursor: 'pointer',
                        fontSize: '11px'
                      }}
                    >
                      Create
                    </button>
                    <button
                      onClick={() => {
                        setShowCreateChannelForm(false);
                        setNewChannelName("");
                        setNewChannelType("text");
                      }}
                      style={{
                        flex: 1,
                        background: '#747f8d',
                        border: 'none',
                        color: '#ffffff',
                        padding: '4px 8px',
                        borderRadius: '2px',
                        cursor: 'pointer',
                        fontSize: '11px'
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
        
        <div className="user-panel">
          <div className="user-avatar">
            {appState.user?.username?.[0] || "U"}
          </div>
          <div className="user-info">
            <div className="username">{appState.user?.username || "You"}</div>
            <div className="user-status">
              {appState.isConnected ? "Online" : "Offline"}
            </div>
          </div>
          <button
            onClick={handleLogout}
            style={{
              background: 'none',
              border: 'none',
              color: '#b9bbbe',
              cursor: 'pointer',
              fontSize: '12px',
              marginLeft: 'auto'
            }}
          >
            Logout
          </button>
        </div>
      </div>

      {/* Main chat area */}
      <div className="chat-area">
        <div className="chat-header">
          <span className="chat-channel-name">{activeChannel}</span>
          <span className="chat-topic">Welcome to {activeChannel}!</span>
          {encryptionEnabled && keyPair && (
            <span 
              style={{ 
                fontSize: '12px', 
                color: '#43b581',
                marginLeft: '16px',
                display: 'flex',
                alignItems: 'center',
                gap: '4px'
              }}
              title="End-to-end encryption enabled"
            >
              🔐 E2EE
            </span>
          )}
          {encryptionEnabled && !keyPair && (
            <span 
              style={{ 
                fontSize: '12px', 
                color: '#faa61a',
                marginLeft: '16px',
                display: 'flex',
                alignItems: 'center',
                gap: '4px'
              }}
              title="Encryption not available"
            >
              🔓 No Keys
            </span>
          )}
          {!encryptionEnabled && (
            <span 
              style={{ 
                fontSize: '12px', 
                color: '#747f8d',
                marginLeft: '16px',
                display: 'flex',
                alignItems: 'center',
                gap: '4px'
              }}
              title="Encryption not supported"
            >
              🚫 No E2EE
            </span>
          )}
        </div>
        <div className="messages">
          {appState.messages.map((msg, i) => (
            <div key={msg.id || i} className="message">
              <div className="message-avatar">{msg.author[0]}</div>
              <div className="message-body">
                <div className="message-header">
                  <span className="message-author">{msg.author}</span>
                  <span className="message-time">{msg.time}</span>
                  {msg.isEncrypted && (
                    <span 
                      style={{ 
                        fontSize: '12px', 
                        color: '#43b581',
                        marginLeft: '8px'
                      }}
                      title="End-to-end encrypted"
                    >
                      🔒
                    </span>
                  )}
                </div>
                <div className="message-content">{msg.content}</div>
              </div>
            </div>
          ))}
        </div>
        <div className="message-input-container">
          {/* File attachment button */}
          {serverAvailable && appState.activeChannel && (
            <FileUploadButton
              channelId={appState.activeChannel}
              token={appState.token || ''}
              keyPair={keyPair}
              encryptionEnabled={encryptionEnabled}
            />
          )}
          <input
            className="message-input"
            type="text"
            placeholder={`Message ${activeChannel}`}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                handleSendMessage();
              }
            }}
          />
          {/* File list button */}
          {serverAvailable && appState.activeChannel && (
            <FileList
              channelId={appState.activeChannel}
              token={appState.token || ''}
              keyPair={keyPair}
              encryptionEnabled={encryptionEnabled}
            />
          )}
        </div>
      </div>

      {/* Member sidebar */}
      <div className="member-sidebar">
        <div className="member-header">Members — {users.length}</div>
        {members.length > 0 ? (
          members.map((member) => {
            const currentUserId = localStorage.getItem('accord_user_id');
            const isCurrentUser = member.user_id === currentUserId;
            const canKick = selectedNodeId && hasPermission(selectedNodeId, 'KickMembers') && !isCurrentUser;
            
            return (
              <div key={member.user.id} className="member" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '4px 12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', flex: 1 }}>
                  <div className="member-avatar">{member.user.username[0]}</div>
                  <span className="member-name" style={{ marginLeft: '8px' }}>
                    {member.user.username}
                  </span>
                  <span 
                    style={{ 
                      fontSize: '12px',
                      marginLeft: '4px'
                    }}
                    title={member.role}
                  >
                    {getRoleBadge(member.role)}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <span 
                    className="member-status"
                    style={{ 
                      fontSize: '12px',
                      color: '#43b581' // Online color - we'll assume all are online for now
                    }}
                  >
                    ●
                  </span>
                  {canKick && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleKickMember(member.user_id, member.user.username);
                      }}
                      style={{
                        background: '#f04747',
                        border: 'none',
                        color: '#ffffff',
                        padding: '2px 6px',
                        borderRadius: '2px',
                        cursor: 'pointer',
                        fontSize: '10px',
                        opacity: 0.7
                      }}
                      title="Kick member"
                      onMouseEnter={(e) => e.currentTarget.style.opacity = '1'}
                      onMouseLeave={(e) => e.currentTarget.style.opacity = '0.7'}
                    >
                      Kick
                    </button>
                  )}
                </div>
              </div>
            );
          })
        ) : (
          users.map((u) => (
            <div key={u} className="member">
              <div className="member-avatar">{u[0]}</div>
              <span className="member-name">{u}</span>
              <span 
                className="member-status"
                style={{ 
                  marginLeft: 'auto', 
                  fontSize: '12px',
                  color: '#43b581'
                }}
              >
                ●
              </span>
            </div>
          ))
        )}
      </div>

      {/* Error Message */}
      {error && (
        <div style={{
          position: 'fixed',
          top: '20px',
          right: '20px',
          background: '#f04747',
          color: '#ffffff',
          padding: '12px 16px',
          borderRadius: '4px',
          zIndex: 1000,
          maxWidth: '300px',
          fontSize: '14px',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)'
        }}>
          {error}
          <button
            onClick={() => setError("")}
            style={{
              background: 'none',
              border: 'none',
              color: '#ffffff',
              cursor: 'pointer',
              fontSize: '16px',
              marginLeft: '8px',
              padding: '0'
            }}
          >
            ×
          </button>
        </div>
      )}

      {/* Invite Modal */}
      {showInviteModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.8)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1001
        }}>
          <div style={{
            background: '#36393f',
            padding: '24px',
            borderRadius: '8px',
            maxWidth: '400px',
            width: '90%',
            color: '#ffffff'
          }}>
            <h3 style={{ margin: '0 0 16px 0', color: '#ffffff' }}>Invite Generated</h3>
            <p style={{ margin: '0 0 16px 0', color: '#b9bbbe' }}>
              Share this invite code with others to let them join this node:
            </p>
            <div style={{
              background: '#40444b',
              padding: '12px',
              borderRadius: '4px',
              marginBottom: '16px',
              fontFamily: 'monospace',
              fontSize: '14px',
              wordBreak: 'break-all',
              userSelect: 'text'
            }}>
              {generatedInvite}
            </div>
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(generatedInvite).then(() => {
                    alert('Invite code copied to clipboard!');
                  }).catch(() => {
                    // Fallback for browsers that don't support clipboard API
                    const textArea = document.createElement('textarea');
                    textArea.value = generatedInvite;
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                    alert('Invite code copied to clipboard!');
                  });
                }}
                style={{
                  background: '#7289da',
                  border: 'none',
                  color: '#ffffff',
                  padding: '8px 16px',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                Copy
              </button>
              <button
                onClick={() => {
                  setShowInviteModal(false);
                  setGeneratedInvite("");
                }}
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
          </div>
        </div>
      )}
    </div>
  );
}

export default App;