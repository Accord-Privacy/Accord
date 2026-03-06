// Stub for @tauri-apps/plugin-store when running in browser
export class Store {
  static async load(_name: string): Promise<Store> { return new Store(); }
  async get<T>(_key: string): Promise<T | undefined> { return undefined; }
  async set(_key: string, _value: unknown): Promise<void> {}
  async delete(_key: string): Promise<void> {}
  async save(): Promise<void> {}
}
