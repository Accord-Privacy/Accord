import { useState } from "react";

const MOCK_SERVERS = ["Accord Dev", "Gaming", "Music"];
const MOCK_CHANNELS = ["# general", "# random", "# dev", "# off-topic"];
const MOCK_USERS = ["Alice", "Bob", "Charlie", "Diana", "Eve"];
const MOCK_MESSAGES = [
  { author: "Alice", content: "Hey everyone! Welcome to Accord 👋", time: "12:01 PM" },
  { author: "Bob", content: "This is looking great so far!", time: "12:02 PM" },
  { author: "Charlie", content: "Can't wait for E2EE to land", time: "12:03 PM" },
  { author: "Diana", content: "The UI is giving me good vibes", time: "12:05 PM" },
  { author: "Alice", content: "We're building something special here", time: "12:06 PM" },
];

function App() {
  const [message, setMessage] = useState("");
  const [activeChannel, setActiveChannel] = useState("# general");
  const [activeServer, setActiveServer] = useState(0);

  return (
    <div className="app">
      {/* Server list */}
      <div className="server-list">
        {MOCK_SERVERS.map((s, i) => (
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
        <div className="sidebar-header">{MOCK_SERVERS[activeServer]}</div>
        <div className="channel-list">
          {MOCK_CHANNELS.map((ch) => (
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
          <div className="user-avatar">U</div>
          <div className="user-info">
            <div className="username">You</div>
            <div className="user-status">Online</div>
          </div>
        </div>
      </div>

      {/* Main chat area */}
      <div className="chat-area">
        <div className="chat-header">
          <span className="chat-channel-name">{activeChannel}</span>
          <span className="chat-topic">Welcome to {activeChannel}!</span>
        </div>
        <div className="messages">
          {MOCK_MESSAGES.map((msg, i) => (
            <div key={i} className="message">
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
              if (e.key === "Enter" && message.trim()) setMessage("");
            }}
          />
        </div>
      </div>

      {/* Member sidebar */}
      <div className="member-sidebar">
        <div className="member-header">Members — {MOCK_USERS.length}</div>
        {MOCK_USERS.map((u) => (
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
