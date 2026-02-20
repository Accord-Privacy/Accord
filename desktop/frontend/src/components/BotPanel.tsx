import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import type { InstalledBot, BotCommand, BotResponseContent, EmbedSection } from '../types';

// ── Embed Renderer ──

const EmbedSectionRenderer: React.FC<{
  section: EmbedSection;
  onInvokeCommand?: (botId: string, command: string, params: Record<string, any>) => void;
  botId?: string;
}> = ({ section, onInvokeCommand, botId }) => {
  switch (section.type) {
    case 'text':
      return <div className="bot-embed-text">{section.text}</div>;
    case 'grid':
      return (
        <div className="bot-embed-grid">
          <table>
            <thead>
              <tr>{section.columns?.map((col, i) => <th key={i}>{col}</th>)}</tr>
            </thead>
            <tbody>
              {section.rows?.map((row, i) => (
                <tr key={i}>{row.map((cell, j) => <td key={j}>{cell}</td>)}</tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    case 'image':
      return (
        <div className="bot-embed-image">
          <img src={section.url} alt={section.alt || ''} style={{ maxWidth: '100%', borderRadius: '4px' }} />
        </div>
      );
    case 'actions':
      return (
        <div className="bot-embed-actions">
          {section.buttons?.map((btn, i) => (
            <button
              key={i}
              className="bot-action-btn"
              onClick={() => {
                if (btn.command && onInvokeCommand && botId) {
                  onInvokeCommand(botId, btn.command, btn.params || {});
                }
              }}
            >
              {btn.label}
            </button>
          ))}
        </div>
      );
    case 'divider':
      return <hr className="bot-embed-divider" />;
    case 'fields':
      return (
        <div className="bot-embed-fields">
          {section.fields?.map((f, i) => (
            <div key={i} className={`bot-embed-field ${f.inline ? 'inline' : ''}`}>
              <div className="bot-field-name">{f.name}</div>
              <div className="bot-field-value">{f.value}</div>
            </div>
          ))}
        </div>
      );
    case 'progress':
      return (
        <div className="bot-embed-progress">
          <div className="bot-progress-label">{section.label}</div>
          <div className="bot-progress-bar">
            <div
              className="bot-progress-fill"
              style={{ width: `${((section.value || 0) / (section.max || 100)) * 100}%` }}
            />
          </div>
        </div>
      );
    case 'code':
      return (
        <pre className="bot-embed-code">
          <code>{section.code}</code>
        </pre>
      );
    case 'input':
      return (
        <div className="bot-embed-input">
          <input type="text" placeholder={section.placeholder || section.name || ''} className="bot-input-field" />
        </div>
      );
    default:
      return null;
  }
};

export const BotResponseRenderer: React.FC<{
  content: BotResponseContent;
  botId?: string;
  onInvokeCommand?: (botId: string, command: string, params: Record<string, any>) => void;
}> = ({ content, botId, onInvokeCommand }) => {
  if (content.type === 'text') {
    return <div className="bot-response-text">{content.text}</div>;
  }
  if (content.type === 'embed') {
    return (
      <div className="bot-embed">
        {content.title && <div className="bot-embed-title">{content.title}</div>}
        {content.sections?.map((section, i) => (
          <EmbedSectionRenderer key={i} section={section} onInvokeCommand={onInvokeCommand} botId={botId} />
        ))}
      </div>
    );
  }
  return null;
};

// ── Slash Command Autocomplete ──

export const SlashCommandAutocomplete: React.FC<{
  query: string;
  bots: InstalledBot[];
  onSelect: (bot: InstalledBot, command: BotCommand) => void;
  visible: boolean;
}> = ({ query, bots, onSelect, visible }) => {
  if (!visible) return null;
  const search = query.toLowerCase();
  const matches: Array<{ bot: InstalledBot; command: BotCommand }> = [];
  for (const bot of bots) {
    for (const cmd of bot.commands) {
      if (cmd.name.toLowerCase().startsWith(search)) {
        matches.push({ bot, command: cmd });
      }
    }
  }
  if (matches.length === 0) return null;
  return (
    <div className="slash-command-autocomplete">
      {matches.slice(0, 10).map(({ bot, command }) => (
        <div
          key={`${bot.bot_id}-${command.name}`}
          className="slash-command-item"
          onClick={() => onSelect(bot, command)}
        >
          <span className="slash-command-icon">{bot.icon || '🤖'}</span>
          <span className="slash-command-name">/{command.name}</span>
          <span className="slash-command-desc">{command.description}</span>
          <span className="slash-command-bot">{bot.name}</span>
        </div>
      ))}
    </div>
  );
};

// ── Command Parameter Form ──

export const CommandParamForm: React.FC<{
  bot: InstalledBot;
  command: BotCommand;
  onSubmit: (params: Record<string, any>) => void;
  onCancel: () => void;
}> = ({ bot, command, onSubmit, onCancel }) => {
  const [values, setValues] = useState<Record<string, string>>({});

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const params: Record<string, any> = {};
    for (const p of command.params) {
      if (values[p.name] !== undefined && values[p.name] !== '') {
        params[p.name] = p.type === 'integer' ? parseInt(values[p.name]) :
                         p.type === 'number' ? parseFloat(values[p.name]) :
                         p.type === 'boolean' ? values[p.name] === 'true' :
                         values[p.name];
      } else if (p.default !== undefined) {
        params[p.name] = p.default;
      }
    }
    onSubmit(params);
  };

  return (
    <div className="bot-param-form-overlay">
      <form className="bot-param-form" onSubmit={handleSubmit}>
        <div className="bot-param-form-header">
          <span>{bot.icon || '🤖'} {bot.name} — /{command.name}</span>
          <button type="button" className="bot-param-close" onClick={onCancel}>×</button>
        </div>
        <div className="bot-param-form-desc">{command.description}</div>
        {command.params.map(p => (
          <div key={p.name} className="bot-param-field">
            <label>
              {p.name} {p.required && <span className="required">*</span>}
              {p.description && <span className="param-desc">{p.description}</span>}
            </label>
            <input
              type={p.type === 'integer' || p.type === 'number' ? 'number' : 'text'}
              value={values[p.name] || ''}
              onChange={e => setValues(prev => ({ ...prev, [p.name]: e.target.value }))}
              placeholder={p.default !== undefined ? `Default: ${p.default}` : ''}
              required={p.required}
            />
          </div>
        ))}
        <div className="bot-param-form-actions">
          <button type="submit" className="bot-param-submit">Run Command</button>
          <button type="button" className="bot-param-cancel" onClick={onCancel}>Cancel</button>
        </div>
      </form>
    </div>
  );
};

// ── Bot Install Modal ──

const BotInstallModal: React.FC<{
  nodeId: string;
  onClose: () => void;
  onInstalled: () => void;
}> = ({ nodeId, onClose, onInstalled }) => {
  const [name, setName] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [manifestJson, setManifestJson] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleInstall = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      let manifest;
      try {
        manifest = JSON.parse(manifestJson);
      } catch {
        setError('Invalid JSON in manifest');
        setLoading(false);
        return;
      }
      if (!manifest.bot_id) manifest.bot_id = name.toLowerCase().replace(/\s+/g, '-');
      if (!manifest.name) manifest.name = name;
      await api.installBot(nodeId, manifest, webhookUrl);
      onInstalled();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to install bot');
    }
    setLoading(false);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content bot-install-modal" onClick={e => e.stopPropagation()}>
        <h3>Install Bot</h3>
        <form onSubmit={handleInstall}>
          <div className="form-group">
            <label>Bot Name</label>
            <input type="text" value={name} onChange={e => setName(e.target.value)} required placeholder="Weather Bot" />
          </div>
          <div className="form-group">
            <label>Webhook URL</label>
            <input type="url" value={webhookUrl} onChange={e => setWebhookUrl(e.target.value)} required placeholder="https://example.com/bot/webhook" />
          </div>
          <div className="form-group">
            <label>Command Manifest (JSON)</label>
            <textarea
              value={manifestJson}
              onChange={e => setManifestJson(e.target.value)}
              required
              rows={8}
              placeholder='{"commands": [{"name": "hello", "description": "Say hello", "params": []}]}'
              style={{ fontFamily: 'monospace', fontSize: '12px' }}
            />
          </div>
          {error && <div className="form-error">{error}</div>}
          <div className="form-actions">
            <button type="submit" disabled={loading}>{loading ? 'Installing...' : 'Install Bot'}</button>
            <button type="button" onClick={onClose}>Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
};

// ── Bot Panel (sidebar section) ──

export const BotPanel: React.FC<{
  nodeId: string;
  isAdmin: boolean;
}> = ({ nodeId, isAdmin }) => {
  const [bots, setBots] = useState<InstalledBot[]>([]);
  const [showInstall, setShowInstall] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const loadBots = useCallback(async () => {
    try {
      const result = await api.listBots(nodeId);
      setBots(result);
    } catch (err) {
      console.warn('Failed to load bots:', err);
    }
  }, [nodeId]);

  useEffect(() => { loadBots(); }, [loadBots]);

  const handleUninstall = async (botId: string) => {
    if (!confirm(`Uninstall bot "${botId}"?`)) return;
    try {
      await api.uninstallBot(nodeId, botId);
      loadBots();
    } catch (err: any) {
      alert(`Failed to uninstall: ${err.message}`);
    }
  };

  return (
    <div className="bot-panel">
      <div className="bot-panel-header" onClick={() => setExpanded(!expanded)}>
        <span className="bot-panel-toggle">{expanded ? '▾' : '▸'}</span>
        <span>🤖 Bots ({bots.length})</span>
        {isAdmin && (
          <button
            className="bot-panel-add"
            onClick={e => { e.stopPropagation(); setShowInstall(true); }}
            title="Install bot"
          >+</button>
        )}
      </div>
      {expanded && (
        <div className="bot-panel-list">
          {bots.length === 0 && <div className="bot-panel-empty">No bots installed</div>}
          {bots.map(bot => (
            <div key={bot.bot_id} className="bot-panel-item">
              <span className="bot-panel-icon">{bot.icon || '🤖'}</span>
              <div className="bot-panel-info">
                <span className="bot-panel-name">{bot.name}</span>
                <span className="bot-panel-cmds">{bot.commands.length} commands</span>
              </div>
              {isAdmin && (
                <button
                  className="bot-panel-remove"
                  onClick={() => handleUninstall(bot.bot_id)}
                  title="Uninstall"
                >×</button>
              )}
            </div>
          ))}
        </div>
      )}
      {showInstall && (
        <BotInstallModal nodeId={nodeId} onClose={() => setShowInstall(false)} onInstalled={loadBots} />
      )}
    </div>
  );
};

export default BotPanel;
