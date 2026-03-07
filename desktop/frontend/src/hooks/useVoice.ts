import { useState } from "react";

export interface VoiceChannelUser {
  userId: string;
  displayName: string;
  isSpeaking: boolean;
  isMuted?: boolean;
}

export function useVoice() {
  const [voiceChannelId, setVoiceChannelId] = useState<string | null>(null);
  const [voiceChannelName, setVoiceChannelName] = useState<string>("");
  const [voiceConnectedAt, setVoiceConnectedAt] = useState<number | null>(null);
  const [voiceMuted, setVoiceMuted] = useState(false);
  const [voiceDeafened, setVoiceDeafened] = useState(false);
  const [voiceChannelUsers, setVoiceChannelUsers] = useState<VoiceChannelUser[]>([]);

  return {
    voiceChannelId, setVoiceChannelId,
    voiceChannelName, setVoiceChannelName,
    voiceConnectedAt, setVoiceConnectedAt,
    voiceMuted, setVoiceMuted,
    voiceDeafened, setVoiceDeafened,
    voiceChannelUsers, setVoiceChannelUsers,
  };
}
