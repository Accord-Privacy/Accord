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
  // SPEC-03 REQ-9: the node recorded together with the voice channel when the
  // user selected it (the channel directory). Never the currently selected node.
  const [voiceNodeId, setVoiceNodeId] = useState<string | null>(null);
  const [voiceConnectedAt, setVoiceConnectedAt] = useState<number | null>(null);
  const [voiceMuted, setVoiceMuted] = useState(false);
  const [voiceDeafened, setVoiceDeafened] = useState(false);
  const [voiceChannelUsers, setVoiceChannelUsers] = useState<VoiceChannelUser[]>([]);

  return {
    voiceChannelId, setVoiceChannelId,
    voiceChannelName, setVoiceChannelName,
    voiceNodeId, setVoiceNodeId,
    voiceConnectedAt, setVoiceConnectedAt,
    voiceMuted, setVoiceMuted,
    voiceDeafened, setVoiceDeafened,
    voiceChannelUsers, setVoiceChannelUsers,
  };
}
