import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { BotPanel, BotResponseRenderer, SlashCommandAutocomplete, CommandParamForm } from '../components/BotPanel';
import type { InstalledBot, BotCommand, BotResponseContent } from '../types';
import * as apiModule from '../api';

vi.mock('../api', () => ({
  api: {
    listBots: vi.fn(),
    installBot: vi.fn(),
    uninstallBot: vi.fn(),
  },
}));

const mockBot = (id: string, name: string, cmdCount: number = 1): InstalledBot => ({
  bot_id: id,
  name,
  icon: undefined,
  commands: Array.from({ length: cmdCount }, (_, i) => ({
    name: `cmd${i + 1}`,
    description: `Command ${i + 1}`,
    params: [],
  })),
  installed_at: Date.now(),
  invocation_count: 0,
});

const mockCommand = (name: string, params: any[] = []): BotCommand => ({
  name,
  description: `Description of ${name}`,
  params,
});

describe('BotPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (apiModule.api.listBots as any).mockResolvedValue([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders nothing when no bots are installed', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([]);
    const { container } = render(<BotPanel nodeId="node-1" isAdmin={true} />);
    await waitFor(() => {
      expect(container.querySelector('.bot-panel')).not.toBeInTheDocument();
    });
  });

  it('renders bot panel header with bot count', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([
      mockBot('bot1', 'Bot 1'),
      mockBot('bot2', 'Bot 2'),
    ]);
    render(<BotPanel nodeId="node-1" isAdmin={false} />);
    await waitFor(() => {
      expect(screen.getByText(/BOTS \(2\)/)).toBeInTheDocument();
    });
  });

  it('expands and collapses panel on header click', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);
    render(<BotPanel nodeId="node-1" isAdmin={false} />);
    await waitFor(() => screen.getByText(/BOTS/));

    const header = screen.getByText(/BOTS \(1\)/);

    // Initially collapsed
    expect(screen.queryByText('Bot 1')).not.toBeInTheDocument();

    // Expand
    fireEvent.click(header);
    expect(screen.getByText('Bot 1')).toBeInTheDocument();

    // Collapse
    fireEvent.click(header);
    expect(screen.queryByText('Bot 1')).not.toBeInTheDocument();
  });

  it('displays bot list when expanded', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([
      mockBot('bot1', 'Weather Bot', 3),
      mockBot('bot2', 'Music Bot', 5),
    ]);
    render(<BotPanel nodeId="node-1" isAdmin={false} />);
    await waitFor(() => screen.getByText(/BOTS/));

    fireEvent.click(screen.getByText(/BOTS \(2\)/));

    expect(screen.getByText('Weather Bot')).toBeInTheDocument();
    expect(screen.getByText('Music Bot')).toBeInTheDocument();
    expect(screen.getByText('3 commands')).toBeInTheDocument();
    expect(screen.getByText('5 commands')).toBeInTheDocument();
  });

  it('shows install button for admin users', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);
    const { container } = render(<BotPanel nodeId="node-1" isAdmin={true} />);
    await waitFor(() => screen.getByText(/BOTS/));

    const addButton = container.querySelector('.bot-panel-add');
    expect(addButton).toBeInTheDocument();
    expect(addButton?.textContent).toBe('+');
  });

  it('hides install button for non-admin users', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);
    const { container } = render(<BotPanel nodeId="node-1" isAdmin={false} />);
    await waitFor(() => screen.getByText(/BOTS/));

    expect(container.querySelector('.bot-panel-add')).not.toBeInTheDocument();
  });

  it('opens install modal when add button is clicked', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);
    render(<BotPanel nodeId="node-1" isAdmin={true} />);
    await waitFor(() => screen.getByText(/BOTS/));

    const addButton = screen.getByTitle('Install bot');
    fireEvent.click(addButton);

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Install Bot' })).toBeInTheDocument();
    });
  });

  it('shows uninstall button for admin users', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);
    const { container } = render(<BotPanel nodeId="node-1" isAdmin={true} />);
    await waitFor(() => screen.getByText(/BOTS/));

    fireEvent.click(screen.getByText(/BOTS \(1\)/));

    expect(container.querySelector('.bot-panel-remove')).toBeInTheDocument();
  });

  it('hides uninstall button for non-admin users', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);
    const { container } = render(<BotPanel nodeId="node-1" isAdmin={false} />);
    await waitFor(() => screen.getByText(/BOTS/));

    fireEvent.click(screen.getByText(/BOTS \(1\)/));

    expect(container.querySelector('.bot-panel-remove')).not.toBeInTheDocument();
  });

  it('calls uninstallBot when uninstall button is clicked', async () => {
    global.confirm = vi.fn(() => true);
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);
    (apiModule.api.uninstallBot as any).mockResolvedValue({});

    const { container } = render(<BotPanel nodeId="node-1" isAdmin={true} />);
    await waitFor(() => screen.getByText(/BOTS/));

    fireEvent.click(screen.getByText(/BOTS \(1\)/));

    const removeButton = container.querySelector('.bot-panel-remove') as HTMLElement;
    fireEvent.click(removeButton);

    expect(global.confirm).toHaveBeenCalled();
    await waitFor(() => {
      expect(apiModule.api.uninstallBot).toHaveBeenCalledWith('node-1', 'bot1');
    });
  });

  it('does not uninstall if user cancels confirmation', async () => {
    global.confirm = vi.fn(() => false);
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);

    const { container } = render(<BotPanel nodeId="node-1" isAdmin={true} />);
    await waitFor(() => screen.getByText(/BOTS/));

    fireEvent.click(screen.getByText(/BOTS \(1\)/));

    const removeButton = container.querySelector('.bot-panel-remove') as HTMLElement;
    fireEvent.click(removeButton);

    expect(global.confirm).toHaveBeenCalled();
    expect(apiModule.api.uninstallBot).not.toHaveBeenCalled();
  });

  it('handles uninstall error with alert', async () => {
    global.confirm = vi.fn(() => true);
    global.alert = vi.fn();
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);
    (apiModule.api.uninstallBot as any).mockRejectedValue(new Error('Network error'));

    const { container } = render(<BotPanel nodeId="node-1" isAdmin={true} />);
    await waitFor(() => screen.getByText(/BOTS/));

    fireEvent.click(screen.getByText(/BOTS \(1\)/));

    const removeButton = container.querySelector('.bot-panel-remove') as HTMLElement;
    fireEvent.click(removeButton);

    await waitFor(() => {
      expect(global.alert).toHaveBeenCalledWith('Failed to uninstall: Network error');
    });
  });

  it('reloads bot list after successful uninstall', async () => {
    global.confirm = vi.fn(() => true);
    (apiModule.api.listBots as any)
      .mockResolvedValueOnce([mockBot('bot1', 'Bot 1')])
      .mockResolvedValueOnce([]);
    (apiModule.api.uninstallBot as any).mockResolvedValue({});

    const { container } = render(<BotPanel nodeId="node-1" isAdmin={true} />);
    await waitFor(() => screen.getByText(/BOTS/));

    fireEvent.click(screen.getByText(/BOTS \(1\)/));

    const removeButton = container.querySelector('.bot-panel-remove') as HTMLElement;
    fireEvent.click(removeButton);

    await waitFor(() => {
      expect(apiModule.api.listBots).toHaveBeenCalledTimes(2);
    });
  });

  it('displays bot icon when provided', async () => {
    const botWithIcon: InstalledBot = { ...mockBot('bot1', 'Bot 1'), icon: '🤖' };
    (apiModule.api.listBots as any).mockResolvedValue([botWithIcon]);
    render(<BotPanel nodeId="node-1" isAdmin={false} />);
    await waitFor(() => screen.getByText(/BOTS/));

    fireEvent.click(screen.getByText(/BOTS \(1\)/));

    expect(screen.getByText('🤖')).toBeInTheDocument();
  });

  it('handles API error gracefully when loading bots', async () => {
    const consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    (apiModule.api.listBots as any).mockRejectedValue(new Error('API error'));

    const { container } = render(<BotPanel nodeId="node-1" isAdmin={false} />);
    await waitFor(() => {
      expect(consoleWarn).toHaveBeenCalledWith('Failed to load bots:', expect.any(Error));
      expect(container.querySelector('.bot-panel')).not.toBeInTheDocument();
    });

    consoleWarn.mockRestore();
  });
});

describe('BotPanel - Install Modal Integration', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders install modal with form fields', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);
    render(<BotPanel nodeId="node-1" isAdmin={true} />);
    await waitFor(() => screen.getByText(/BOTS/));

    fireEvent.click(screen.getByTitle('Install bot'));

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Install Bot' })).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Weather Bot')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('https://example.com/bot/webhook')).toBeInTheDocument();
    });
  });

  it('displays error for invalid JSON manifest', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);
    render(<BotPanel nodeId="node-1" isAdmin={true} />);
    await waitFor(() => screen.getByText(/BOTS/));

    fireEvent.click(screen.getByTitle('Install bot'));

    await waitFor(() => screen.getByRole('heading', { name: 'Install Bot' }));

    fireEvent.change(screen.getByPlaceholderText('Weather Bot'), {
      target: { value: 'My Bot' },
    });
    fireEvent.change(screen.getByPlaceholderText('https://example.com/bot/webhook'), {
      target: { value: 'https://example.com/webhook' },
    });
    const textarea = screen.getByPlaceholderText(/commands/);
    fireEvent.change(textarea, {
      target: { value: 'invalid json' },
    });

    const form = screen.getByRole('button', { name: 'Install Bot' }).closest('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(screen.getByText('Invalid JSON in manifest')).toBeInTheDocument();
    });
  });

  it('submits valid bot installation', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);
    (apiModule.api.installBot as any).mockResolvedValue({});
    render(<BotPanel nodeId="node-1" isAdmin={true} />);
    await waitFor(() => screen.getByText(/BOTS/));

    fireEvent.click(screen.getByTitle('Install bot'));
    await waitFor(() => screen.getByRole('heading', { name: 'Install Bot' }));

    fireEvent.change(screen.getByPlaceholderText('Weather Bot'), {
      target: { value: 'Weather Bot' },
    });
    fireEvent.change(screen.getByPlaceholderText('https://example.com/bot/webhook'), {
      target: { value: 'https://example.com/webhook' },
    });
    const textarea = screen.getByPlaceholderText(/commands/);
    fireEvent.change(textarea, {
      target: { value: '{"commands": [{"name": "weather", "description": "Get weather", "params": []}]}' },
    });

    const form = screen.getByRole('button', { name: 'Install Bot' }).closest('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(apiModule.api.installBot).toHaveBeenCalledWith(
        'node-1',
        expect.objectContaining({ name: 'Weather Bot', bot_id: 'weather-bot' }),
        'https://example.com/webhook'
      );
    });
  });

  it('displays loading state during installation', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);
    (apiModule.api.installBot as any).mockImplementation(() => new Promise(() => {}));
    render(<BotPanel nodeId="node-1" isAdmin={true} />);
    await waitFor(() => screen.getByText(/BOTS/));

    fireEvent.click(screen.getByTitle('Install bot'));
    await waitFor(() => screen.getByRole('heading', { name: 'Install Bot' }));

    fireEvent.change(screen.getByPlaceholderText('Weather Bot'), {
      target: { value: 'Weather Bot' },
    });
    fireEvent.change(screen.getByPlaceholderText('https://example.com/bot/webhook'), {
      target: { value: 'https://example.com/webhook' },
    });
    const textarea = screen.getByPlaceholderText(/commands/);
    fireEvent.change(textarea, {
      target: { value: '{"commands": []}' },
    });

    const form = screen.getByRole('button', { name: 'Install Bot' }).closest('form')!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Installing...' })).toBeInTheDocument();
    });
  });

  it('closes modal when clicking cancel', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);
    render(<BotPanel nodeId="node-1" isAdmin={true} />);
    await waitFor(() => screen.getByText(/BOTS/));

    fireEvent.click(screen.getByTitle('Install bot'));
    await waitFor(() => screen.getByRole('heading', { name: 'Install Bot' }));

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    await waitFor(() => {
      expect(screen.queryByRole('heading', { name: 'Install Bot' })).not.toBeInTheDocument();
    });
  });

  it('closes modal when clicking outside', async () => {
    (apiModule.api.listBots as any).mockResolvedValue([mockBot('bot1', 'Bot 1')]);
    const { container } = render(<BotPanel nodeId="node-1" isAdmin={true} />);
    await waitFor(() => screen.getByText(/BOTS/));

    fireEvent.click(screen.getByTitle('Install bot'));
    await waitFor(() => screen.getByRole('heading', { name: 'Install Bot' }));

    const overlay = container.querySelector('.modal-overlay') as HTMLElement;
    fireEvent.click(overlay);

    await waitFor(() => {
      expect(screen.queryByRole('heading', { name: 'Install Bot' })).not.toBeInTheDocument();
    });
  });
});

describe('SlashCommandAutocomplete', () => {
  const bots: InstalledBot[] = [
    {
      ...mockBot('bot1', 'Weather Bot'),
      commands: [
        mockCommand('weather'),
        mockCommand('forecast'),
      ],
    },
    {
      ...mockBot('bot2', 'Music Bot'),
      commands: [
        mockCommand('play'),
        mockCommand('pause'),
      ],
    },
  ];

  it('does not render when not visible', () => {
    const { container } = render(
      <SlashCommandAutocomplete query="w" bots={bots} onSelect={vi.fn()} visible={false} />
    );
    expect(container.querySelector('.slash-command-autocomplete')).not.toBeInTheDocument();
  });

  it('filters commands by query', () => {
    render(<SlashCommandAutocomplete query="w" bots={bots} onSelect={vi.fn()} visible={true} />);
    expect(screen.getByText('/weather')).toBeInTheDocument();
    expect(screen.queryByText('/play')).not.toBeInTheDocument();
  });

  it('displays matching commands', () => {
    render(<SlashCommandAutocomplete query="p" bots={bots} onSelect={vi.fn()} visible={true} />);
    expect(screen.getByText('/play')).toBeInTheDocument();
    expect(screen.getByText('/pause')).toBeInTheDocument();
  });

  it('limits results to 10 items', () => {
    const manyBots: InstalledBot[] = Array.from({ length: 20 }, (_, i) => ({
      ...mockBot(`bot${i}`, `Bot ${i}`),
      commands: [mockCommand(`cmd${i}`)],
    }));

    const { container } = render(
      <SlashCommandAutocomplete query="c" bots={manyBots} onSelect={vi.fn()} visible={true} />
    );

    const items = container.querySelectorAll('.slash-command-item');
    expect(items.length).toBeLessThanOrEqual(10);
  });

  it('calls onSelect when command is clicked', () => {
    const onSelect = vi.fn();
    render(<SlashCommandAutocomplete query="w" bots={bots} onSelect={onSelect} visible={true} />);

    fireEvent.click(screen.getByText('/weather'));

    expect(onSelect).toHaveBeenCalledWith(bots[0], bots[0].commands[0]);
  });

  it('returns null when no matches', () => {
    const { container } = render(
      <SlashCommandAutocomplete query="xyz" bots={bots} onSelect={vi.fn()} visible={true} />
    );
    expect(container.querySelector('.slash-command-autocomplete')).not.toBeInTheDocument();
  });
});

describe('CommandParamForm', () => {
  const bot = mockBot('bot1', 'Weather Bot');
  const command: BotCommand = {
    name: 'weather',
    description: 'Get weather forecast',
    params: [
      { name: 'city', type: 'string', required: true, description: 'City name' },
      { name: 'units', type: 'string', required: false, default: 'metric', description: 'Temperature units' },
      { name: 'days', type: 'integer', required: false, description: 'Number of days' },
    ],
  };

  it('renders form with command details', () => {
    render(<CommandParamForm bot={bot} command={command} onSubmit={vi.fn()} onCancel={vi.fn()} />);

    expect(screen.getByText(/Weather Bot/)).toBeInTheDocument();
    expect(screen.getByText(/\/weather/)).toBeInTheDocument();
    expect(screen.getByText('Get weather forecast')).toBeInTheDocument();
  });

  it('displays all parameter fields', () => {
    const { container } = render(
      <CommandParamForm bot={bot} command={command} onSubmit={vi.fn()} onCancel={vi.fn()} />
    );

    const labels = container.querySelectorAll('.bot-param-field label');
    const labelTexts = Array.from(labels).map(l => l.textContent);

    expect(labelTexts.some(text => text?.includes('city'))).toBe(true);
    expect(labelTexts.some(text => text?.includes('units'))).toBe(true);
    expect(labelTexts.some(text => text?.includes('days'))).toBe(true);
  });

  it('marks required fields', () => {
    const { container } = render(
      <CommandParamForm bot={bot} command={command} onSubmit={vi.fn()} onCancel={vi.fn()} />
    );

    const requiredMarkers = container.querySelectorAll('.required');
    expect(requiredMarkers.length).toBeGreaterThan(0);
  });

  it('shows default values in placeholders', () => {
    render(<CommandParamForm bot={bot} command={command} onSubmit={vi.fn()} onCancel={vi.fn()} />);

    expect(screen.getByPlaceholderText('Default: metric')).toBeInTheDocument();
  });

  it('submits form with parameter values', () => {
    const onSubmit = vi.fn();
    const { container } = render(
      <CommandParamForm bot={bot} command={command} onSubmit={onSubmit} onCancel={vi.fn()} />
    );

    const inputs = container.querySelectorAll('input[type="text"], input[type="number"]');
    fireEvent.change(inputs[0], { target: { value: 'London' } });

    fireEvent.submit(screen.getByText('Run Command').closest('form')!);

    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({
        city: 'London',
        units: 'metric',
      })
    );
  });

  it('converts integer parameters', () => {
    const onSubmit = vi.fn();
    const { container } = render(
      <CommandParamForm bot={bot} command={command} onSubmit={onSubmit} onCancel={vi.fn()} />
    );

    const inputs = container.querySelectorAll('input[type="text"], input[type="number"]');
    fireEvent.change(inputs[0], { target: { value: 'London' } });
    fireEvent.change(inputs[2], { target: { value: '5' } });

    fireEvent.submit(screen.getByText('Run Command').closest('form')!);

    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({
        city: 'London',
        days: 5,
        units: 'metric',
      })
    );
  });

  it('calls onCancel when cancel button is clicked', () => {
    const onCancel = vi.fn();
    render(<CommandParamForm bot={bot} command={command} onSubmit={vi.fn()} onCancel={onCancel} />);

    fireEvent.click(screen.getByText('Cancel'));

    expect(onCancel).toHaveBeenCalled();
  });

  it('closes form when X button is clicked', () => {
    const onCancel = vi.fn();
    render(<CommandParamForm bot={bot} command={command} onSubmit={vi.fn()} onCancel={onCancel} />);

    fireEvent.click(screen.getByText('×'));

    expect(onCancel).toHaveBeenCalled();
  });
});

describe('BotResponseRenderer', () => {
  it('renders text response', () => {
    const content: BotResponseContent = { type: 'text', text: 'Hello, world!' };
    render(<BotResponseRenderer content={content} />);

    expect(screen.getByText('Hello, world!')).toBeInTheDocument();
  });

  it('renders embed with title', () => {
    const content: BotResponseContent = {
      type: 'embed',
      title: 'Weather Report',
      sections: [],
    };
    render(<BotResponseRenderer content={content} />);

    expect(screen.getByText('Weather Report')).toBeInTheDocument();
  });

  it('renders embed text section', () => {
    const content: BotResponseContent = {
      type: 'embed',
      sections: [{ type: 'text', text: 'Sunny today' }],
    };
    render(<BotResponseRenderer content={content} />);

    expect(screen.getByText('Sunny today')).toBeInTheDocument();
  });

  it('renders embed image section', () => {
    const content: BotResponseContent = {
      type: 'embed',
      sections: [{ type: 'image', url: 'https://example.com/image.png', alt: 'Weather map' }],
    };
    const { container } = render(<BotResponseRenderer content={content} />);

    const img = container.querySelector('img');
    expect(img).toBeInTheDocument();
    expect(img?.getAttribute('src')).toBe('https://example.com/image.png');
    expect(img?.getAttribute('alt')).toBe('Weather map');
  });

  it('renders embed grid section', () => {
    const content: BotResponseContent = {
      type: 'embed',
      sections: [
        {
          type: 'grid',
          columns: ['Day', 'Temp'],
          rows: [['Monday', '20°C'], ['Tuesday', '22°C']],
        },
      ],
    };
    render(<BotResponseRenderer content={content} />);

    expect(screen.getByText('Day')).toBeInTheDocument();
    expect(screen.getByText('Temp')).toBeInTheDocument();
    expect(screen.getByText('Monday')).toBeInTheDocument();
    expect(screen.getByText('20°C')).toBeInTheDocument();
  });

  it('renders embed action buttons', () => {
    const onInvokeCommand = vi.fn();
    const content: BotResponseContent = {
      type: 'embed',
      sections: [
        {
          type: 'actions',
          buttons: [
            { label: 'Refresh', command: 'refresh', params: {} },
            { label: 'Details', command: 'details', params: { id: '123' } },
          ],
        },
      ],
    };
    render(<BotResponseRenderer content={content} botId="bot1" onInvokeCommand={onInvokeCommand} />);

    expect(screen.getByText('Refresh')).toBeInTheDocument();
    expect(screen.getByText('Details')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Refresh'));
    expect(onInvokeCommand).toHaveBeenCalledWith('bot1', 'refresh', {});
  });

  it('renders embed fields section', () => {
    const content: BotResponseContent = {
      type: 'embed',
      sections: [
        {
          type: 'fields',
          fields: [
            { name: 'Temperature', value: '20°C', inline: true },
            { name: 'Humidity', value: '65%', inline: true },
          ],
        },
      ],
    };
    render(<BotResponseRenderer content={content} />);

    expect(screen.getByText('Temperature')).toBeInTheDocument();
    expect(screen.getByText('20°C')).toBeInTheDocument();
    expect(screen.getByText('Humidity')).toBeInTheDocument();
    expect(screen.getByText('65%')).toBeInTheDocument();
  });

  it('renders embed progress bar', () => {
    const content: BotResponseContent = {
      type: 'embed',
      sections: [
        { type: 'progress', label: 'Download', value: 75, max: 100 },
      ],
    };
    const { container } = render(<BotResponseRenderer content={content} />);

    expect(screen.getByText('Download')).toBeInTheDocument();
    const progressFill = container.querySelector('.bot-progress-fill') as HTMLElement;
    expect(progressFill?.style.width).toBe('75%');
  });

  it('renders embed code block', () => {
    const content: BotResponseContent = {
      type: 'embed',
      sections: [{ type: 'code', code: 'console.log("Hello");' }],
    };
    render(<BotResponseRenderer content={content} />);

    expect(screen.getByText('console.log("Hello");')).toBeInTheDocument();
  });

  it('renders embed divider', () => {
    const content: BotResponseContent = {
      type: 'embed',
      sections: [{ type: 'divider' }],
    };
    const { container } = render(<BotResponseRenderer content={content} />);

    expect(container.querySelector('.bot-embed-divider')).toBeInTheDocument();
  });

  it('renders embed input field', () => {
    const content: BotResponseContent = {
      type: 'embed',
      sections: [{ type: 'input', name: 'username', placeholder: 'Enter username' }],
    };
    render(<BotResponseRenderer content={content} />);

    expect(screen.getByPlaceholderText('Enter username')).toBeInTheDocument();
  });
});
