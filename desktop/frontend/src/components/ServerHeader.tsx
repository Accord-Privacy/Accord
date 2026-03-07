import React, { useState, useRef, useEffect, useCallback } from "react";
import { useAppContext } from "./AppContext";
import { Icon } from "./Icon";

export const ServerHeader: React.FC = () => {
  const ctx = useAppContext();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [showLeaveConfirm, setShowLeaveConfirm] = useState(false);
  const headerRef = useRef<HTMLDivElement>(null);

  const nodeName = ctx.servers[ctx.activeServer] || "Server";
  const currentNode = ctx.selectedNodeId
    ? ctx.nodes.find((n) => n.id === ctx.selectedNodeId)
    : null;
  const hasNode = !!ctx.selectedNodeId;
  const canManage = hasNode && ctx.hasPermission(ctx.selectedNodeId!, "ManageNode");
  const canInvite = hasNode && ctx.hasPermission(ctx.selectedNodeId!, "ManageInvites");
  const canCreateChannel = hasNode && ctx.hasPermission(ctx.selectedNodeId!, "CreateChannel");

  const toggleDropdown = useCallback(() => {
    if (!hasNode) return;
    setDropdownOpen((prev) => !prev);
    setShowLeaveConfirm(false);
  }, [hasNode]);

  // Close on click-outside
  useEffect(() => {
    if (!dropdownOpen) return;
    const handleClick = (e: MouseEvent) => {
      if (headerRef.current && !headerRef.current.contains(e.target as Node)) {
        setDropdownOpen(false);
        setShowLeaveConfirm(false);
      }
    };
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [dropdownOpen]);

  // Close on Escape
  useEffect(() => {
    if (!dropdownOpen) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setDropdownOpen(false);
        setShowLeaveConfirm(false);
      }
    };
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [dropdownOpen]);

  const handleLeaveNode = useCallback(async () => {
    if (!ctx.selectedNodeId || !ctx.appState.token) return;
    try {
      const { api } = await import("../api");
      await api.leaveNode(ctx.selectedNodeId, ctx.appState.token);
      setDropdownOpen(false);
      setShowLeaveConfirm(false);
      // Reload nodes after leaving
      ctx.loadNodes?.();
    } catch (err) {
      console.error("Failed to leave node:", err);
    }
  }, [ctx.selectedNodeId, ctx.appState.token]);

  return (
    <div className="server-header" ref={headerRef}>
      <button
        className={`server-header-button ${dropdownOpen ? "open" : ""}`}
        onClick={toggleDropdown}
        aria-expanded={dropdownOpen}
        aria-haspopup="menu"
      >
        <span className="server-header-name">
          {nodeName}
          {currentNode && (
            <span className="server-header-badge" title="Verified">
              ✓
            </span>
          )}
        </span>
        {hasNode && (
          <span className={`server-header-arrow ${dropdownOpen ? "open" : ""}`}>
            {dropdownOpen ? "✕" : "▼"}
          </span>
        )}
        {ctx.serverAvailable && ctx.nodes.length > 0 && ctx.connectionInfo.status !== "connected" && (
          <span className="connection-status" title={ctx.connectionInfo.status}>
            <span className={`connection-dot ${ctx.connectionInfo.status}`}>●</span>
            <span className="connection-label">
              {ctx.connectionInfo.status === "reconnecting" && "Reconnecting..."}
              {ctx.connectionInfo.status === "disconnected" && !ctx.appState.isConnected && "Offline"}
            </span>
          </span>
        )}
      </button>

      {dropdownOpen && (
        <div className="server-header-dropdown" role="menu">
          {canInvite && (
            <button
              className="server-dropdown-item"
              role="menuitem"
              onClick={() => {
                setDropdownOpen(false);
                ctx.handleGenerateInvite();
              }}
            >
              <Icon name="user-plus" size={16} />
              <span>Invite People</span>
            </button>
          )}

          {canManage && (
            <button
              className="server-dropdown-item"
              role="menuitem"
              onClick={() => {
                setDropdownOpen(false);
                ctx.setShowNodeSettings(true);
              }}
            >
              <Icon name="settings" size={16} />
              <span>Node Settings</span>
            </button>
          )}

          {(canInvite || canManage) && (canCreateChannel || true) && (
            <div className="server-dropdown-divider" />
          )}

          {canCreateChannel && (
            <button
              className="server-dropdown-item"
              role="menuitem"
              onClick={() => {
                setDropdownOpen(false);
                ctx.setNewChannelCategoryId("");
                ctx.setShowCreateChannelForm(true);
              }}
            >
              <Icon name="hash" size={16} />
              <span>Create Channel</span>
            </button>
          )}

          {canManage && (
            <button
              className="server-dropdown-item"
              role="menuitem"
              onClick={() => {
                setDropdownOpen(false);
                ctx.setNewChannelCategoryId("");
                ctx.setNewChannelType("category");
                ctx.setShowCreateChannelForm(true);
              }}
            >
              <Icon name="folder" size={16} />
              <span>Create Category</span>
            </button>
          )}

          <div className="server-dropdown-divider" />

          <button
            className="server-dropdown-item"
            role="menuitem"
            onClick={() => {
              setDropdownOpen(false);
              ctx.setShowNotificationSettings(true);
            }}
          >
            <Icon name="bell" size={16} />
            <span>Notification Settings</span>
          </button>

          <div className="server-dropdown-divider" />

          {!showLeaveConfirm ? (
            <button
              className="server-dropdown-item server-dropdown-item-danger"
              role="menuitem"
              onClick={() => setShowLeaveConfirm(true)}
            >
              <Icon name="log-out" size={16} />
              <span>Leave Node</span>
            </button>
          ) : (
            <div className="server-dropdown-confirm">
              <span>Are you sure?</span>
              <div className="server-dropdown-confirm-actions">
                <button
                  className="btn btn-sm btn-danger"
                  onClick={handleLeaveNode}
                >
                  Leave
                </button>
                <button
                  className="btn btn-sm btn-outline"
                  onClick={() => setShowLeaveConfirm(false)}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
