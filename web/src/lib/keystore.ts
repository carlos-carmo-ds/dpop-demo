/**
 * Guarda o par de chaves DPoP no IndexedDB.
 * O IndexedDB armazena o objeto CryptoKey em si, mantendo a chave privada NÃO extraível
 * (localStorage não serve: só guarda texto, o que exigiria exportar a chave).
 */

const DB_NAME = "dpop-demo";
const STORE = "keys";
const KEY_ID = "dpop-key-pair";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function withStore<T>(mode: IDBTransactionMode, action: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const transaction = db.transaction(STORE, mode);
      const request = action(transaction.objectStore(STORE));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
    });
  } finally {
    db.close();
  }
}

export async function loadKeyPair(): Promise<CryptoKeyPair | undefined> {
  return withStore<CryptoKeyPair | undefined>("readonly", (store) => store.get(KEY_ID));
}

export async function saveKeyPair(keyPair: CryptoKeyPair): Promise<void> {
  await withStore("readwrite", (store) => store.put(keyPair, KEY_ID));
}

export async function deleteKeyPair(): Promise<void> {
  await withStore("readwrite", (store) => store.delete(KEY_ID));
}
