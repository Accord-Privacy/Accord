/** Try to get device identity from Tauri (returns null in browser) */
export async function getDeviceInfo(): Promise<{
  fingerprint_hash: string;
  public_key: string;
  label: string;
} | null> {
  try {
    if (
      typeof window !== "undefined" &&
      (window as any).__TAURI__ &&
      (window as any).__TAURI__.core
    ) {
      const result = await (window as any).__TAURI__.core.invoke(
        "get_device_identity"
      );
      return {
        fingerprint_hash: result.device_fingerprint_hash,
        public_key: result.device_public_key,
        label: result.device_label,
      };
    }
  } catch (e) {
    console.warn("Device identity unavailable:", e);
  }
  return null;
}
