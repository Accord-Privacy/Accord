import { AppLayout } from './AppLayout';
import { GuildsLayout } from './GuildsLayout';
import { GuildLayout } from './GuildLayout';
import { GuildNavbar } from './GuildNavbar';
import { GuildHeader as FluxerGuildHeader } from './GuildHeader';
import { UserArea } from './UserArea';
import { ServerList, ChannelSidebar, ChatArea, MemberSidebar } from '../index';
import { UpdateBanner } from '../../UpdateChecker';

interface AccordShellProps {
  serverName?: string;
}

export function AccordShell({ serverName }: AccordShellProps) {
  return (
    <AppLayout>
      <UpdateBanner />
      <GuildsLayout
        guildList={<ServerList />}
        userArea={<UserArea />}
      >
        <GuildLayout
          navbar={
            <GuildNavbar
              header={<FluxerGuildHeader name={serverName || ''} />}
            >
              <ChannelSidebar />
            </GuildNavbar>
          }
        >
          <ChatArea />
          <MemberSidebar />
        </GuildLayout>
      </GuildsLayout>
    </AppLayout>
  );
}
