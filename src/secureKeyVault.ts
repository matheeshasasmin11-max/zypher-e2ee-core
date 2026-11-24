import { Platform } from "react-native";
import * as SecureStore from "expo-secure-store";

/**
 * Sanitizes key identifiers for Android KeyStore & iOS Keychain compatibility.
 */
function sanitizeKey(key: string): string {
  return key.replace(/[^a-zA-Z0-9._-]/g, "_");
}

/**
 * Checks whether hardware-backed SecureStore (Android KeyStore / iOS Secure Enclave Keychain)
 * is available on the current device runtime.
 */
export async function isHardwareSecureStorageAvailable(): Promise<boolean> {
  if (Platform.OS === "web") return false;
  try {
    return await SecureStore.isAvailableAsync();
  } catch {
    return false;
  }
}

/**
 * Stores sensitive cryptographic key material strictly inside hardware-backed device storage
 * (`WHEN_UNLOCKED_THIS_DEVICE_ONLY` — non-migratable, never backed up to cloud).
 */
export async function setSecureItem(key: string, value: string): Promise<void> {
  if (Platform.OS === "web") {
    throw new Error("Hardware SecureStore is required for private key storage.");
  }
  const isAvailable = await SecureStore.isAvailableAsync();
  if (!isAvailable) {
    throw new Error("Device hardware keystore is unavailable.");
  }
  await SecureStore.setItemAsync(sanitizeKey(key), value, {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
}

/**
 * Reads sensitive cryptographic key material from Android KeyStore / iOS Keychain.
 */
export async function getSecureItem(key: string): Promise<string | null> {
  if (Platform.OS === "web") return null;
  try {
    const isAvailable = await SecureStore.isAvailableAsync();
    if (!isAvailable) return null;
    const val = await SecureStore.getItemAsync(sanitizeKey(key));
    return val && val.length > 0 ? val : null;
  } catch {
    return null;
  }
}

/**
 * Permanently erases a cryptographic key from hardware-backed storage.
 */
export async function removeSecureItem(key: string): Promise<void> {
  if (Platform.OS === "web") return;
  try {
    const isAvailable = await SecureStore.isAvailableAsync();
    if (isAvailable) {
      await SecureStore.deleteItemAsync(sanitizeKey(key));
    }
  } catch {}
}
