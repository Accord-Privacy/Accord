import { useState } from "react";

export function useVoice() {
  const [voiceChannelId, setVoiceChannelId] = useState<string | null>(null);
  const [voiceChannelName, setVoiceChannelName] = useState<string>("");
  const [voiceConnectedAt, setVoiceConnectedAt] = useState<number | null>(null);
  const [voiceMuted, setVoiceMuted] = useState(false);
  const [voiceDeafened, setVoiceDeafened] = useState(false);

  return {
    voiceChannelId, setVoiceChannelId,
    voiceChannelName, setVoiceChannelName,
    voiceConnectedAt, setVoiceConnectedAt,
    voiceMuted, setVoiceMuted,
    voiceDeafened, setVoiceDeafened,
  };
}
