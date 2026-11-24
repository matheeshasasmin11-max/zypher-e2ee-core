export interface SecureVaultAdapter {
  setItem(key: string, value: string): Promise<void>;
  getItem(key: string): Promise<string | null>;
  deleteItem(key: string): Promise<void>;
}

function sanitizeSecureStoreKey(rawKey: string): string {
  return rawKey.replace(/[^a-zA-Z0-9._-]/g, "_");
}

let activeVaultAdapter: SecureVaultAdapter | null = null;

/**
 * Configures a custom hardware keystore adapter (e.g., Expo SecureStore on iOS/Android,
 * or an isolated in-memory vault during automated test suites).
 */
export function configureSecureVault(adapter: SecureVaultAdapter): void {
  activeVaultAdapter = adapter;
}

async function resolveDefaultExpoSecureVault(): Promise<SecureVaultAdapter> {
  if (activeVaultAdapter) return activeVaultAdapter;
  try {
    // Dynamic import of optional Expo SecureStore peer dependency
    const moduleName = "expo-secure-store";
    const SecureStore = await import(moduleName);
    activeVaultAdapter = {
      async setItem(key: string, value: string): Promise<void> {
        await SecureStore.setItemAsync(sanitizeSecureStoreKey(key), value, {
          keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        });
      },
      async getItem(key: string): Promise<string | null> {
        return await SecureStore.getItemAsync(sanitizeSecureStoreKey(key));
      },
      async deleteItem(key: string): Promise<void> {
        await SecureStore.deleteItemAsync(sanitizeSecureStoreKey(key));
      },
    };
    return activeVaultAdapter;
  } catch {
    throw new Error(
      "Hardware KeyStore (expo-secure-store) is not available in this runtime. " +
        "On non-Expo runtimes or tests, inject a vault explicitly via configureSecureVault()."
    );
  }
}

/**
 * Stores sensitive cryptographic material in hardware-backed Android KeyStore / iOS Keychain
 * with `WHEN_UNLOCKED_THIS_DEVICE_ONLY` (excluded from cloud backups and device migrations).
 */
export async function setSecureItem(key: string, value: string): Promise<void> {
  const vault = await resolveDefaultExpoSecureVault();
  await vault.setItem(key, value);
}

export async function getSecureItem(key: string): Promise<string | null> {
  const vault = await resolveDefaultExpoSecureVault();
  return await vault.getItem(key);
}

export async function removeSecureItem(key: string): Promise<void> {
  const vault = await resolveDefaultExpoSecureVault();
  await vault.deleteItem(key);
}
