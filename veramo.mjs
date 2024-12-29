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
import { Entities, KeyStore, DIDStore, PrivateKeyStore, migrations } from '@veramo/data-store'
import { DataSource } from 'typeorm'
import fs from 'fs'

const INFURA_PROJECT_ID = process.env.INFURIA_API_KEY
let KMS_SECRET_KEY = null
try {
  KMS_SECRET_KEY = fs.readFileSync('./kms', 'utf8')
  console.log(KMS_SECRET_KEY)
} catch (err) {
  KMS_SECRET_KEY = await SecretBox.createSecretKey()
  console.log(KMS_SECRET_KEY)
  KMS_SECRET_KEY = 'cd198a03032e8d072066e3195b8e1e176e78b5cfbb378a5fc00ae4ded5c002e9'
  fs.writeFileSync('./kms', KMS_SECRET_KEY)
}

const dbConnection = new DataSource({
  type: 'sqlite',
  database: './database.sqlite',
  synchronize: false,
  migrations,
  migrationsRun: true,
  logging: ['error', 'info', 'warn'],
  entities: Entities,
}).initialize()

export const agent = createAgent({
  plugins: [
    new KeyManager({
      store: new KeyStore(dbConnection),
      kms: {
        local: new KeyManagementSystem(new PrivateKeyStore(dbConnection, new SecretBox(KMS_SECRET_KEY))),
      }
    }),
    new DIDManager({
      store: new DIDStore(dbConnection),
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
    new CredentialPlugin()
  ],
})
  