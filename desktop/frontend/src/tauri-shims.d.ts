// Type declarations for optional Tauri plugins (only available in Tauri desktop builds)
declare module '@tauri-apps/plugin-store' {
  export class Store {
    static load(name: string): Promise<Store>;
    get(key: string): Promise<any>;
    set(key: string, value: any): Promise<void>;
    delete(key: string): Promise<void>;
    save(): Promise<void>;
  }
}
