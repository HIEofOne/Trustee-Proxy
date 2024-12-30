import * as fs from 'fs'

/**
 * A utility class that shows how a File based JSON storage system could work.
 * This is not recommended for large databases since every write operation rewrites the entire database.
 */
export class JsonFileStore {
  notifyUpdate
  dids
  keys
  privateKeys
  credentials
  claims
  presentations
  messages
  file

  constructor(file) {
    this.file = file
    this.notifyUpdate = async(oldState, newState) => {
      await this.save(newState)
    }
    this.dids = {}
    this.keys = {}
    this.privateKeys = {}
    this.credentials = {}
    this.claims = {}
    this.presentations = {}
    this.messages = {}
  }

  static async fromFile(file) {
    const store = new JsonFileStore(file)
    return await store.load()
  }

  async load() {
    let cache
    try {
      const rawCache = await fs.promises.readFile(this.file, { encoding: 'utf8' })
      cache = JSON.parse(rawCache)
    } catch (e) {
      console.log(e)
      cache = {}
    }
    ; ({
      dids: this.dids,
      keys: this.keys,
      credentials: this.credentials,
      claims: this.claims,
      presentations: this.presentations,
      messages: this.messages,
      privateKeys: this.privateKeys,
    } = {
      dids: {},
      keys: {},
      credentials: {},
      claims: {},
      presentations: {},
      messages: {},
      privateKeys: {},
      ...cache,
    })
    return this
  }

  async save(newState) {
    await fs.promises.writeFile(this.file, JSON.stringify(newState), {
      encoding: 'utf8',
    })
  }
}