import dotenv from 'dotenv'
dotenv.config()
import { createAgent } from '@veramo/core'
import { DIDManager } from '@veramo/did-manager'
import { KeyManager } from '@veramo/key-manager'
import { KeyManagementSystem, SecretBox } from '@veramo/kms-local'
import { CredentialPlugin } from '@veramo/credential-w3c'
import { EthrDIDProvider } from '@veramo/did-provider-ethr'
import { KeyDIDProvider } from '@veramo/did-provider-key'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { Resolver } from 'did-resolver'
import { getResolver as ethrDidResolver } from 'ethr-did-resolver'
import { getResolver as webDidResolver } from 'web-did-resolver'
import { DataStoreJson, KeyStoreJson, DIDStoreJson, PrivateKeyStoreJson } from '@veramo/data-store-json'
import fs from 'fs'
import { JsonFileStore } from './jsonstore.mjs'

const INFURA_PROJECT_ID = process.env.INFURIA_API_KEY
// const INFURA_PROJECT_ID = '62cfe5babc774c1aaffa9eac6dbbf47f'
// const KMS_SECRET_KEY = 'cd198a03032e8d072066e3195b8e1e176e78b5cfbb378a5fc00ae4ded5c002e9'
let KMS_SECRET_KEY = null
if (fs.existsSync('/data/kms')) {
// if (fs.existsSync('./kms')) {  
  KMS_SECRET_KEY = fs.readFileSync('/data/kms', 'utf8')
  // KMS_SECRET_KEY = fs.readFileSync('./kms', 'utf8')
  console.log(KMS_SECRET_KEY)
} else {
  KMS_SECRET_KEY = await SecretBox.createSecretKey()
  console.log(KMS_SECRET_KEY)
  fs.writeFileSync('/data/kms', KMS_SECRET_KEY)
  // fs.writeFileSync('./kms', KMS_SECRET_KEY)
}

const jsonFileStore = await JsonFileStore.fromFile('/data/store.json')

export const agent = createAgent({
  plugins: [
    new KeyManager({
      store: new KeyStoreJson(jsonFileStore),
      kms: {
        local: new KeyManagementSystem(new PrivateKeyStoreJson(jsonFileStore, new SecretBox(KMS_SECRET_KEY))),
      }
    }),
    new DIDManager({
      store: new DIDStoreJson(jsonFileStore),
      defaultProvider: 'did:key',
      providers: {
        'did:ethr:sepolia': new EthrDIDProvider({
          defaultKms: 'local',
          network: 'sepolia',
          rpcUrl: 'https://sepolia.infura.io/v3/' + INFURA_PROJECT_ID,
        }),
        'did:key': new KeyDIDProvider({
          defaultKms: 'local'
        })
      },
    }),
    new DIDResolverPlugin({
      resolver: new Resolver({
        ...ethrDidResolver({ infuraProjectId: INFURA_PROJECT_ID }),
        ...webDidResolver(),
      })
    }),
    new DataStoreJson(jsonFileStore),
    new CredentialPlugin()
  ],
})
  