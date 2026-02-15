import { useState, useEffect, useCallback } from "react";
import { api } from "./api";
import { AccordWebSocket } from "./ws";
import { AppState, Message, WsIncomingMessage } from "./types";

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

    socket.on('channel_message', (data) => {
      // Handle incoming channel messages
      const newMessage: Message = {
        id: data.message_id || Math.random().toString(),
        author: data.from || "Unknown",
        content: data.encrypted_data, // In real app, this would be decrypted
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        timestamp: data.timestamp * 1000,
        channel_id: data.channel_id,
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
  }, []);

  // Handle authentication
  const handleAuth = async () => {
    if (!serverAvailable) {
      // Skip auth if server unavailable
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

      } else {
        // Register
        if (!publicKey.trim()) {
          setAuthError("Public key is required for registration");
          return;
        }
        
        await api.register(username, publicKey);
        
        // After successful registration, switch to login
        setIsLoginMode(true);
        setPassword("");
        setPublicKey("");
        setAuthError("");
        alert("Registration successful! Please log in.");
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
  const handleSendMessage = () => {
    if (!message.trim()) return;

    if (ws && ws.isSocketConnected() && appState.activeChannel) {
      // Send via WebSocket if connected and we have an active channel
      ws.sendPlainChannelMessage(appState.activeChannel, message);
    } else {
      // Add to local messages as fallback
      const newMessage: Message = {
        id: Math.random().toString(),
        author: appState.user?.username || "You",
        content: message,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        timestamp: Date.now(),
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
    const token = localStorage.getItem('accord_token');
    const userId = localStorage.getItem('accord_user_id');
    
    if (token && userId && serverAvailable) {
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
    }
  }, [serverAvailable, setupWebSocketHandlers]);

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
                  placeholder="Public Key (for E2EE)"
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
  const servers = appState.nodes.length > 0 ? appState.nodes.map(n => n.name) : MOCK_SERVERS;
  const channels = MOCK_CHANNELS; // TODO: Replace with real channel data from selected node
  const users = MOCK_USERS; // TODO: Replace with real member data from selected node

  return (
    <div className="app">
      {/* Server list */}
      <div className="server-list">
        {servers.map((s, i) => (
          <div
            key={s}
            className={`server-icon ${i === activeServer ? "active" : ""}`}
            onClick={() => setActiveServer(i)}
            title={s}
          >
            {s[0]}
          </div>
        ))}
        <div className="server-icon add-server" title="Add Server">+</div>
      </div>

      {/* Channel sidebar */}
      <div className="channel-sidebar">
        <div className="sidebar-header">
          {servers[activeServer]}
          {appState.isConnected && (
            <span style={{ fontSize: '10px', color: '#43b581', marginLeft: '8px' }}>●</span>
          )}
          {!serverAvailable && (
            <span style={{ fontSize: '10px', color: '#faa61a', marginLeft: '8px' }}>DEMO</span>
          )}
        </div>
        <div className="channel-list">
          {channels.map((ch) => (
            <div
              key={ch}
              className={`channel ${ch === activeChannel ? "active" : ""}`}
              onClick={() => setActiveChannel(ch)}
            >
              {ch}
            </div>
          ))}
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
        </div>
        <div className="messages">
          {appState.messages.map((msg, i) => (
            <div key={msg.id || i} className="message">
              <div className="message-avatar">{msg.author[0]}</div>
              <div className="message-body">
                <div className="message-header">
                  <span className="message-author">{msg.author}</span>
                  <span className="message-time">{msg.time}</span>
                </div>
                <div className="message-content">{msg.content}</div>
              </div>
            </div>
          ))}
        </div>
        <div className="message-input-container">
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
        </div>
      </div>

      {/* Member sidebar */}
      <div className="member-sidebar">
        <div className="member-header">Members — {users.length}</div>
        {users.map((u) => (
          <div key={u} className="member">
            <div className="member-avatar">{u[0]}</div>
            <span className="member-name">{u}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default App;