import dotenv from 'dotenv'
dotenv.config()
import express from 'express'
import axios from 'axios'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import isReachable from 'is-reachable'
import * as jose from 'jose'
import morgan from 'morgan'
import { nanoid } from 'nanoid'
import objectPath from 'object-path'
import path from 'path'
import {fileURLToPath} from 'url'
import * as oidcclient from 'openid-client'
import PouchDB from 'pouchdb'
import PouchDBFind from 'pouchdb-find'
PouchDB.plugin(PouchDBFind)
import QRCode from 'qrcode'
import { PassThrough } from 'stream'
import { v4 as uuidv4 } from 'uuid'
import { SiweMessage } from 'siwe'
import { agent } from './veramo.mjs'
import { createJWK } from '@veramo/utils'
import util from 'util'

import { createJWT, couchdbDatabase, couchdbInstall, getNumberOrUndefined, urlFix, verify } from './core.mjs'
import settings from './settings.mjs'
const app = express()
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const client = __dirname + '/public/'

const vcIssuerConf = {
  "credential_issuer": process.env.DOMAIN,
  "credential_endpoint": process.env.DOMAIN + "/credential",
  "token_endpoint": process.env.DOMAIN + "/token",
  "jwks_uri": process.env.DOMAIN + "/jwks",
  "grant_types_supported": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
  "credential_configurations_supported": {
    "OpenBadgeCredential": {
      "format": "jwt_vc_json",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": ["ES256"],
      "credential_definition": {
        "type": [
          "VerifiableCredential",
          "OpenBadgeCredential"
        ]
      },
      "display": [{"name": 'OpenBadge Credential'}]
    },
    "NPICredential": {
      "format": "jwt_vc_json",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": ["ES256"],
      "credential_definition": {
        "type": [
          "VerifiableCredential",
          "NPICredential"
        ]
      },
      "display": [
        {
          "text_color": '#12107c',
          "locale": 'en-US',
          "logo": {
            "alt_text": 'a square logo of a university',
            "url": 'https://dir.hieofone.org/logo.png',
          },
          "name": 'NPI Credential',
          "background_color": '#FFFFFF'
        }
      ],
      "claims": [
        {
          "path": ["credentialSubject", "npi"],
          "display": [{"name": 'NPI'}]
        },
        {
          "path": ["credentialSubject", "name"],
          "display": [{"name": 'Name'}]
        },
        {
          "path": ["credentialSubject", "description"],
          "display": [{"name": 'Description'}]
        },
        {
          "path": ["credentialSubject", "gender"],
          "display": [{"name": 'Gender'}]
        },
        {
          "path": ["credentialSubject", "city"],
          "display": [{"name": 'City'}]
        },
        {
          "path": ["credentialSubject", "state"],
          "display": [{"name": 'State'}]
        },
        {
          "path": ["credentialSubject", "zip"],
          "display": [{"name": 'Zip Code'}]
        },
        {
          "path": ["credentialSubject", "credentials"],
          "display": [{"name": 'Credentials'}]
        },
        {
          "path": ["credentialSubject", "specialty"],
          "display": [{"name": 'Specialty'}]
        },
        {
          "path": ["credentialSubject", "medicalSchool"],
          "display": [{"name": 'Medical School'}]
        },
        {
          "path": ["credentialSubject", "residencies"],
          "display": [{"name": 'Residencies'}]
        },
        {
          "path": ["credentialSubject", "profilePhoto"],
          "display": [{"name": 'Profile Photo'}]
        }
      ]
    }
  }
}

app.enable('trust proxy')
app.use(morgan('tiny'))
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(express.static(client))
app.set('view engine', 'hbs')

app.post('/ssx', async(req, res) => {
  const {message, signature} = req.body
  try {
    const siweMessage = new SiweMessage(message)
    console.log(siweMessage)
    const status = await siweMessage.verify({signature})
    console.log(status)
    res.status(200).send('OK')
  } catch (e) {
    console.log(util.inspect(e, {showHidden: true, depth: null, colors: true}))
    res.status(500).send(e)
  }
})

app.get('/.well-known/openid-configuration', (req, res) => {
  res.set({
    'Cache-Control': 'no-store',
    Pragma: 'no-cache',
  })
  res.status(200).json(vcIssuerConf)
})

app.get('/.well-known/openid-credential-issuer', (req, res) => {
  res.set({
    'Cache-Control': 'no-store',
    Pragma: 'no-cache',
  })
  res.status(200).json(vcIssuerConf)
})

app.post('/credential', async(req, res) => {
  const authHeader = req.headers.authorization
  if (!authHeader) {
    console.log('no header')
    res.status(400).json({error: 'invalid_token'})
  } else {
    const jwt = authHeader.split(' ')[1]
    const response = await verify(jwt)
    if (response.status === 'isValid') {
      if (objectPath.has(response.payload.preAuthorizedCode)) {
        const opts = JSON.parse(JSON.stringify(settings.couchdb_auth))
        const vc_db = new PouchDB(urlFix(settings.couchdb_uri) + 'vc', opts)
        try {
          const result = await vc_db.get(response.payload.preAuthorizedCode)
          if (req.body.format !== 'jwt_vc' && req.body.format !== 'jwt_vc_json' && req.body.format !== 'jwt_vc_json-ld') {
            console.log('wrong format')
            res.status(400).json({error: 'invalid_request'})
          } else {
            if (!objectPath.has(req, 'body.proof')) {
              console.log('no proof')
              res.status(400).json({error: 'invalid_request'})
            } else {
              const header = jose.decodeProtectedHeader(req.body.proof.jwt)
              const payload = jose.decodeJwt(req.body.proof.jwt)
              if (header.typ !== 'openid4vci-proof+jwt' && header.typ !== 'jwt') {
                console.log('invalid jwt header type')
                res.status(400).json({error: 'invalid_request'})
              } else {
                if (!objectPath.has(payload, 'iat')) {
                  console.log('no iat in proof')
                  res.status(400).json({error: 'invalid_request'})
                } else {
                  if (objectPath.get(payload, 'iat') > result.c_nonce_timestamp + 300000) {
                    console.log('proof expired')
                    res.status(400).json({error: 'invalid_request'})
                  } else {
                    if (!objectPath.has(payload, 'aud')) {
                      console.log('no aud in proof')
                      res.status(400).json({error: 'invalid_request'})
                    } else {
                      if (objectPath.get(payload, 'aud') !== vcIssuerConf.credential_issuer) {
                        console.log('aud does not match issuer')
                        res.status(400).json({error: 'invalid_request'})
                      } else {
                        const new_c_nonce = uuidv4()
                        const new_c_nonce_timestamp = Date.now()
                        objectPath.set(result, 'new_c_nonce', new_c_nonce)
                        objectPath.set(result, 'new_c_nonce_timestamp', new_c_nonce_timestamp)
                        await vc_db.put(result)
                        try {
                          const identifier = await agent.didManagerGetOrCreate({ alias: 'default' })
                          const verifiableCredential = await agent.createVerifiableCredential({
                            credential: {
                              issuer: { id: identifier.did },
                              type: ['NPICredential'],
                              credentialSubject: result.credential_subject
                            },
                            proofFormat: 'jwt'
                          })
                          objectPath.set(result, 'verfiableCredential', verifiableCredential)
                          const response = {
                            'credential': verifiableCredential.proof.jwt,
                          }
                          res.status(200).json(response)
                        } catch (e) {
                          console.log(util.inspect(e, {showHidden: true, depth: null, colors: true}))
                          res.status(400).json({error: 'invalid_token'})
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        } catch (e) {
          console.log('wrong preauth code')
          res.status(400).json({error: 'invalid_token'})
        }
      } else {
        console.log('token missing payload')
        res.status(400).json({error: 'invalid_token'})
      }
    } else {
      console.log('jwt invalid')
      res.status(400).json({error: 'invalid_token'})
    }
  }
})

app.get('/credential_offer/:offer_reference', async(req, res) => {
  const opts = JSON.parse(JSON.stringify(settings.couchdb_auth))
  const vc_db = new PouchDB(urlFix(settings.couchdb_uri) + 'vc', opts)
  const result = await vc_db.find({selector: {'offer_reference': {$eq: req.params.offer_reference}}, limit: 100})
  if (result.docs.length > 0) {
    const response = {
      "credential_issuer": vcIssuerConf.credential_issuer,
      "credential_configuration_ids": [
        result.docs[0].credential_type
      ],
      "grants": {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
          "pre-authorized_code": result.docs[0]._id,
          "tx_code": {
            "length": 4,
            "input_mode": "numeric",
            "description": "Please provide the one-time code"
          }
        }
      }
    }
    res.status(200).json(response)
  } else {
    res.status(400).json({error: 'no_offers'})
  }
})

app.get('/doximity', async(req, res) => {
  const config = await oidcclient.discovery(
    new URL('https://auth.doximity.com/.well-known/oauth-authorization-server'),
    process.env.DOXIMITY_CLIENT_ID,
    process.env.DOXIMITY_CLIENT_SECRET
  )
  const code_verifier = oidcclient.randomPKCECodeVerifier()
  const code_challenge = await oidcclient.calculatePKCECodeChallenge(code_verifier)
  const state = await nanoid()
  const parameters = {
    redirect_uri: urlFix(process.env.DOMAIN) + 'doximity_redirect',
    scope: 'openid basic',
    code_challenge: code_challenge,
    state: state,
    code_challenge_method: 'S256'
  }
  const url = oidcclient.buildAuthorizationUrl(config, parameters)
  const doc = {
    _id: 'id_' + state,
    code_verifier: code_verifier,
  }
  const opts = JSON.parse(JSON.stringify(settings.couchdb_auth))
  const db = new PouchDB(urlFix(settings.couchdb_uri) + 'doximity', opts)
  await db.put(doc)
  res.redirect(url)
})

app.get('/doximity_redirect', async(req, res) => {
  const config = await oidcclient.discovery(
    new URL('https://auth.doximity.com/.well-known/oauth-authorization-server'),
    process.env.DOXIMITY_CLIENT_ID,
    process.env.DOXIMITY_CLIENT_SECRET
  )
  const opts = JSON.parse(JSON.stringify(settings.couchdb_auth))
  try {
    const db = new PouchDB(urlFix(settings.couchdb_uri) + 'doximity', opts)
    const db_result = await db.get('id_' + req.query.state)
    const check = {
      pkceCodeVerifier: db_result.code_verifier,
      expectedState: req.query.state
    }
    try {
      const tokenSet = await oidcclient.authorizationCodeGrant(
        config,
        new URL(req.protocol + '://' + req.get('host') + req.originalUrl),
        check
      )
      console.log('received and validated tokens %j', tokenSet)
      console.log('validated ID Token claims %j', tokenSet.claims())
      const opts1 = {headers: {Authorization: 'Bearer ' + tokenSet.access_token, Accept: 'application/json'}}
      try {
        const userinfo = await axios.get('https://www.doximity.com/api/v1/users/current', opts1)
        const credentialSubject = {
          "npi": userinfo.data.npi.toString(),
          "name": userinfo.data.full_name,
          "description": userinfo.data.description,
          "gender": userinfo.data.gender,
          "city": userinfo.data.city,
          "state": userinfo.data.state,
          "zip": userinfo.data.zip,
          "credentials": userinfo.data.credentials,
          "specialty": userinfo.data.specialty,
          "medicalSchool": userinfo.data.medical_school,
          "residencies": userinfo.data.residencies,
          "profilePhoto": userinfo.data.profile_photo
        }
        const vc_db = new PouchDB(urlFix(settings.couchdb_uri) + 'vc', opts)
        await vc_db.info()
        const vc_doc = {}
        const preauth_code = uuidv4()
        const offer_reference = uuidv4()
        objectPath.set(vc_doc, '_id', preauth_code)
        objectPath.set(vc_doc, 'credential_subject', credentialSubject)
        objectPath.set(vc_doc, 'offer_reference', offer_reference)
        objectPath.set(vc_doc, 'timestamp', Date().now)
        objectPath.set(vc_doc, 'credential_type', 'NPICredential')
        const randomNum = Math.random() * 9000
        const tx_code = Math.floor(1000 + randomNum).toString()
        const tx_code_split = tx_code.split('')
        objectPath.set(vc_doc, 'tx_code', tx_code)
        await vc_db.put(vc_doc)
        const uri = 'credential_offer_uri=' + encodeURIComponent(process.env.DOMAIN + "/credential_offer/" + offer_reference)
        const vc = {
          uri: 'openid-credential-offer://?' + uri,
          uri_enc: uri,
          tx_code1: tx_code_split[0],
          tx_code2: tx_code_split[1],
          tx_code3: tx_code_split[2],
          tx_code4: tx_code_split[3]
        }
        res.render('index.hbs', {vc: vc})
      } catch (e) {
        res.status(200).json(e)
      }
    } catch (e) {
      res.status(200).json(e)
    }
  } catch (e) {
    res.status(200).json({error: 'no state found'})
  }
})

app.get('/jwks', async(req, res) => {
  const keys = []
  const identifier = await agent.didManagerGetOrCreate({ alias: 'default' });
  for (const key of identifier.keys) {
    const jwk = createJWK("Ed25519", key.publicKeyHex);
    keys.push(jwk)
  }
  res.status(200).json({"keys": keys});
})

app.post('/oidc_relay', async(req, res) => {
  const opts = JSON.parse(JSON.stringify(settings.couchdb_auth))
  const db = new PouchDB(urlFix(settings.couchdb_uri) + 'proxy', opts)
  try {
    await db.get('id_' + req.body.state)
    res.status(200).send('Not authorized - duplicate state')
  } catch (e) {
    const doc = req.body
    objectPath.set(doc, '_id', 'id_' + req.body.state)
    await db.put(doc)
    res.status(200).send('OK')
  }
})

app.get('/oidc_relay/:state', async(req, res) => {
  const opts = JSON.parse(JSON.stringify(settings.couchdb_auth))
  const db = new PouchDB(urlFix(settings.couchdb_uri) + 'proxy', opts)
  if (objectPath.has(req, 'params.state')) {
    try {
      const doc = await db.get('id_' + req.params.state)
      if (objectPath.has(doc, 'access_token')) {
        res.status(200).json(doc)
      } else {
        res.status(200).send('Authorization canceled')
      }
    } catch (e) {
      res.status(200).send('Not authorized - state does not exist')
    }
  } else {
    res.status(200).send('Not authorized - no state given')
  }
})

app.get('/oidc_relay_connect', async(req, res) => {
  let proceed = true
  const opts = JSON.parse(JSON.stringify(settings.couchdb_auth))
  const db = new PouchDB(urlFix(settings.couchdb_uri) + 'proxy', opts)
  let doc = {}
  if (objectPath.has(req, 'query.proxystate')) {
    try {
      doc = await db.get('id_' + req.query.proxystate)
    } catch (e) {
      res.status(200).send('Not authorized - state does not exist')
      proceed = false
    }
  } else {
    if (objectPath.has(req, 'query.state')) {
      try {
        doc = await db.get('id_' + req.query.state)
      } catch (e) {
        res.status(200).send('Not authorized - state does not exist')
        proceed = false
      }
    } else {
      res.status(200).send('Not authorized - no state given')
      proceed = false
    }
  }
  if (proceed) {
    let client_id = ''
    let client_secret = ''
    let scope = ''
    let base_url = ''
    let config = null
    if (doc.type === 'epic' || doc.type === 'cerner') {
      if (doc.type === 'epic') {
        if (process.env.OPENEPIC_CLIENT_ID === null) {
          objectPath.set(doc, 'error', 'OpenEpic Client ID is not set')
          await db.put(doc)
          res.redirect(doc.response_uri)
        }
        client_id = process.env.OPENEPIC_CLIENT_ID
      } else {
        if (process.env.CERNER_CLIENT_ID === null) {
          objectPath.set(doc, 'error', 'Cerner Client ID is not set')
          await db.put(doc)
          res.redirect(doc.response_uri)
        }
        client_id = process.env.CERNER_CLIENT_ID
      }
      if (!objectPath.has(doc, 'fhir_url')) {
        objectPath.set(doc, 'error', 'fhir_url is not set')
        await db.put(doc)
        res.redirect(doc.response_uri)
      }
      if (doc.fhir_url === 'https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4/') {
        if (process.env.OPENEPIC_SANDBOX_CLIENT_ID === null) {
          objectPath.set(doc, 'error', 'OpenEpic Sandbox Client ID is not set')
          await db.put(doc)
          res.redirect(doc.response_uri)
        }
        client_id = process.env.OPENEPIC_SANDBOX_CLIENT_ID
      }
      scope = 'openid patient/*.read user/*.* profile launch launch/patient offline_access online_access'
      if (doc.type === 'cerner') {
        try {
          const opts = {headers: {Accept: 'application/json'}}
          const { data } = await axios.get(doc.fhir_url + '.well-known/smart-configuration', opts)
          const url = new URL(data.management_endpoint)
          const pathParts = url.pathname.split('/')
          const issuer_arr = [url.protocol + '/', url.hostname, pathParts[1], pathParts[2], 'oidc', 'idsps', pathParts[2] + '-ch', '']
          objectPath.set(data, 'issuer', issuer_arr.join('/'))
          config = new oidcclient.Configuration(
            data,
            client_id,
            '',
            oidcclient.None()
          )
          const scopes_exclude = ['launch', 'launch/patient']
          const scopes_arr = data.scopes_supported.filter(item => !scopes_exclude.includes(item))
          scope = scopes_arr.join(' ')
        } catch (e) {
          console.log(util.inspect(e, {showHidden: true, depth: null, colors: true}))
          objectPath.set(doc, 'error', 'Problem processing OpenID Configuration')
          await db.put(doc)
          res.status(200).send('Not authorized - Problem processing OpenID Configuration')
          proceed = false
        }
      } else {
        try {
          config = await oidcclient.discovery(
            new URL(doc.fhir_url + '.well-known/openid-configuration'),
            client_id,
            '',
            oidcclient.None()
          )
        } catch (e) {
          console.log(util.inspect(e, {showHidden: true, depth: null, colors: true}))
          objectPath.set(doc, 'error', 'Problem accessing OpenID Configuration')
          await db.put(doc)
          res.status(200).send('Not authorized - Problem accessing OpenID Configuration')
          proceed = false
        }
      }
    } else {
      if (doc.type === 'cms_bluebutton_sandbox') {
        if (process.env.CMS_BLUEBUTTON_SANDBOX_CLIENT_ID === null) {
          objectPath.set(doc, 'error', 'CMS Bluebuton Sandbox credentials are not set')
          await db.put(doc)
          res.redirect(doc.response_uri)
        }
        client_id = process.env.CMS_BLUEBUTTON_SANDBOX_CLIENT_ID
        client_secret = process.env.CMS_BLUEBUTTON_SANDBOX_CLIENT_SECRET
        base_url = 'https://sandbox.bluebutton.cms.gov'
        // var resource_url = base_url + '/v1/fhir/Patient/20140000008325'
      }
      if (doc.type === 'cms_bluebutton') {
        if (process.env.CMS_BLUEBUTTON_CLIENT_ID === null) {
          objectPath.set(doc, 'error', 'CMS Bluebuton credentials are not set')
          await db.put(doc)
          res.redirect(doc.response_uri)
        }
        client_id = process.env.CMS_BLUEBUTTON_CLIENT_ID
        client_secret = process.env.CMS_BLUEBUTTON_CLIENT_SECRET
        base_url = 'https://api.bluebutton.cms.gov'
      }
      scope = 'patient/Patient.read patient/ExplanationOfBenefit.read patient/Coverage.read profile'
      try {
        config = await oidcclient.discovery(
          new URL(base_url + '/.well-known/openid-configuration'),
          client_id,
          client_secret
        )
      } catch (e) {
        objectPath.set(doc, 'error', 'Problem accessing OpenID Configuration')
        await db.put(doc)
        res.status(200).send('Not authorized - Problem accessing OpenID Configuration')
        proceed = false
      }
    }
    if (objectPath.has(req, 'query.proxystate')) {
      if (proceed) {
        const code_verifier = oidcclient.randomPKCECodeVerifier()
        const code_challenge = await oidcclient.calculatePKCECodeChallenge(code_verifier)
        let url = null
        let parameters = {
          redirect_uri: urlFix(process.env.DOMAIN) + 'oidc_relay_connect',
          scope: scope,
          code_challenge: code_challenge,
          state: req.query.proxystate,
          code_challenge_method: 'S256'
        }
        if (doc.type === 'epic' || doc.type === 'cerner') {
          objectPath.set(parameters, 'aud', doc.fhir_url)
          // if (doc.type === 'cerner') {
          //   const launch = await nanoid()
          //   objectPath.set(parameters, 'launch', launch)
          // }
        }
        url = oidcclient.buildAuthorizationUrl(config, parameters)
        objectPath.set(doc, 'code_verifier', code_verifier)
        await db.put(doc)
        res.redirect(url)
      }
    } else {
      const check = {
        pkceCodeVerifier: doc.code_verifier,
        expectedState: req.query.state
      }
      try {
        let tokenSet = null
        if (doc.type === 'epic' || doc.type === 'cerner') {
          tokenSet = await oidcclient.authorizationCodeGrant(
            config,
            new URL(req.protocol + '://' + req.get('host') + req.originalUrl),
            check
          )
          console.log('validated ID Token claims %j', tokenSet.claims())
        } else {
          tokenSet = await oidcclient.authorizationCodeGrant(
            config,
            new URL(req.protocol + '://' + req.get('host') + req.originalUrl),
            check
          )
        }
        console.log('received and validated tokens %j', tokenSet)
        objectPath.set(doc, 'access_token', tokenSet.access_token)
        if (doc.type === 'epic') {
          objectPath.set(doc, 'patient_token', tokenSet.patient)
        } else if (doc.type === 'cerner') {
          const { profile } = tokenSet.claims()
          const profile_url = new URL(profile)
          const profile_parts = profile_url.pathname.split('/')
          const patient_id = profile_parts[profile_parts.length - 1]
          objectPath.set(doc, 'patient_token', patient_id)
        } else {
          objectPath.set(doc, 'patient_token', tokenSet.patient_token)
          objectPath.set(doc, 'refresh_token', tokenSet.refresh_token)
        }
        await db.put(doc)
        res.redirect(doc.response_uri)
      } catch (e) {
        console.log(util.inspect(e, {showHidden: true, depth: null, colors: true}))
        res.status(200).json(e)
      }
    }
  }
})

app.get('/oidc_relay_start/:state', (req, res) => {
  res.redirect(urlFix(process.env.DOMAIN) + 'oidc_relay_connect?proxystate=' + req.params.state)
})

app.get('/qr/:content', async(req, res) => {
  try {
    const content = 'openid-credential-offer://?' + req.params.content
    console.log(content)
    const qrStream = new PassThrough()
    await QRCode.toFileStream(qrStream, content, {
      type: 'png',
      width: 200,
      errorCorrectionLevel: 'H'
    })
    qrStream.pipe(res)
  } catch (e) {
    console.error('fail qr load')
  }
})

app.get('/start', async(req, res) => {
  const opts = JSON.parse(JSON.stringify(settings.couchdb_auth))
  objectPath.set(opts, 'skip_setup', true)
  const check = new PouchDB(urlFix(settings.couchdb_uri) + 'proxy', opts)
  const info = await check.info()
  if (objectPath.has(info, 'error')) {
    if (info.error == 'not_found') {
      await couchdbInstall()
      let b = false
      let c = 0
      while (!b && c < 40) {
        b = await isReachable(settings.couchdb_uri)
        if (b || c === 39) {
          break
        } else {
          c++
        }
      }
      if (b) {
        await couchdbDatabase()
        res.status(200).send('Ready!')
      } else {
        res.status(200).send('CouchDB is not restarting for some reason; try again')
      }
    } else {
      console.log('something is wrong with your CouchDB install.')
    }
  } else {
    res.status(200).send('Ready!')
  }
})

app.post('/token', async(req, res) => {
  const opts = JSON.parse(JSON.stringify(settings.couchdb_auth))
  const vc_db = new PouchDB(urlFix(settings.couchdb_uri) + 'vc', opts)
  if (req.body.grant_type === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
    try {
      const result = await vc_db.get(objectPath.get(req, 'body.pre-authorized_code'))
      const preauth_code_duration = getNumberOrUndefined(process.env.PRE_AUTHORIZED_CODE_EXPIRATION_DURATION) ?? 300000
      const comp_timestamp = result.timestamp + preauth_code_duration
      if (objectPath.get(req, 'body.tx_code') !== result.tx_code) {
        console.log('tx_code does not match')
        res.status(400).json({error: 'invalid_grant'})
      } else {
        if (Date.now() >= comp_timestamp) {
          console.log('preauth code expired')
          res.status(400).json({error: 'invalid_grant'})
        } else {
          res.set({
            'Cache-Control': 'no-store',
            Pragma: 'no-cache',
          })
          const preAuthorizedCode = result._id
          const payload = {
            ...(preAuthorizedCode && { preAuthorizedCode })
          }
          try {
            const access_token = await createJWT(vcIssuerConf.credential_issuer, payload)
            const c_nonce = uuidv4()
            objectPath.set(result, 'c_nonce', c_nonce)
            objectPath.set(result, 'c_nonce_timestamp', Date.now())
            await vc_db.put(result)
            const response = {
              access_token,
              token_type: 'bearer',
              expires_in: 300
            }
            res.status(200).json(response)
          } catch (e) {
            console.log(util.inspect(e, {showHidden: true, depth: null, colors: true}))
            res.status(400).json({error: 'invalid_grant'})
          }
        }
      }
    } catch (e) {
      console.log('can not find doc')
      res.status(400).json({error: 'invalid_grant'})
    }
  } else {
    res.status(400).json({error: 'unsupported_grant_type'})
  }
})

const port = process.env.PORT || 4000;
app.listen(port, () => {
    console.log(`listening on ${port}`)
})

export default app