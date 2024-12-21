import Docker from 'dockerode'
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
// import { Issuer, generators } from 'openid-client'
import * as oidcclient from 'openid-client'
import PouchDB from 'pouchdb'
import PouchDBFind from 'pouchdb-find'
import streams from 'memory-streams'
PouchDB.plugin(PouchDBFind)
// import hbs from 'hbs'
import QRCode from 'qrcode'
import { PassThrough } from 'stream'
import { v4 as uuidv4 } from 'uuid'
import { SiweMessage } from 'siwe';

import { createJWT, couchdbDatabase, couchdbInstall, didkitIssue, didkitVerify, determinePath, getNumberOrUndefined, urlFix, verify } from './core.mjs'
import settings from './settings.mjs'
const app = express()
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const client = __dirname + '/public/'

const vcIssuerConf = {
  "issuer": process.env.DOMAIN,
  "credential_endpoint": process.env.DOMAIN + "/credential",
  "token_endpoint": process.env.DOMAIN + "/token",
  "jwks_uri": process.env.DOMAIN + "/jwks",
  "grant_types_supported": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
  "credentials_supported": {
    "OpenBadgeCredential": {
      "formats": {
        "jwt_vc": {
          "types": ["VerifiableCredential","OpenBadgeCredential"],
          "cryptographic_binding_methods_supported": ["did"],
          "cryptographic_suites_supported": ["ES256","ES256K", "RS256"]
        },
        "ldp_vc": {
          "types": ["VerifiableCredential","OpenBadgeCredential"],
          "cryptographic_binding_methods_supported": ["did"],
          "cryptographic_suites_supported":["Ed25519Signature2018"]
        }
      },
      "display": [{"name": 'OpenBadge Credential'}],
    },
    "NPICredential": {
      "formats": {
        "jwt_vc": {
          "types": ["VerifiableCredential","NPICredential"],
          "cryptographic_binding_methods_supported": ["did"],
          "cryptographic_suites_supported": ["ES256","ES256K", "RS256"],
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
          "credentialSubject": {
            "npi": {"display": [{"name": 'NPI'}]},
            "name": {"display": [{"name": 'Name'}]},
            "description": {"display": [{"name": 'Description'}]},
            "gender": {"display": [{"name": 'Gender'}]},
            "city": {"display": [{"name": 'NPI'}]},
            "state": {"display": [{"name": 'State'}]},
            "zip": {"display": [{"name": 'ZIP Code'}]},
            "credentials": {"display": [{"name": 'Credentials'}]},
            "specialty": {"display": [{"name": 'Specialty'}]},
            "medicalSchool": {"display": [{"name": 'Medical School'}]},
            "residencies": {"display": [{"name": 'Residencies'}]},
            "profilePhoto": {"display": [{"name": 'Profile Photo'}]}
          }
        }
      },
      "display": [{"name": 'NPI Credential'}]
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
    console.log(e)
    res.status(500).send(e)
  }
})

app.get('/.well-known/did.json', async(req, res) => {
  const url = new URL(process.env.DOMAIN)
  const db = new PouchDB(urlFix(settings.couchdb_uri) + 'didkit', settings.couchdb_auth)
  try {
    const result = await db.get('did_doc')
    console.log(result)
    const jwk = JSON.parse(JSON.stringify(result))
    objectPath.del(jwk, '_id')
    objectPath.del(jwk, '_rev')
    const did_web = "did:web:" + url.hostname
    objectPath.set(jwk, 'verificationMethod.0.id', did_web)
    objectPath.set(jwk, 'verificationMethod.0.controller', did_web)
    objectPath.set(jwk, 'authentication.0', did_web)
    objectPath.set(jwk, 'assertionMethod.0', did_web)
    res.status(200).json(jwk)
  } catch (e) {
    res.status(200).json({error: "not found", message: e})
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

// app.get('/didstart', async(req, res) => {
//   const did = createDIDKey()
//   const db = new PouchDB(urlFix(settings.couchdb_uri) + 'keys', settings.couchdb_auth)
//   const result = await db.find({
//     selector: {_id: {"$gte": null}, privateKey: {"$gte": null}}
//   })
//   if (result.docs.length === 0) {
//     res.status(200).json({message: 'Install first'})
//   } else {
//     var doc = result.docs[0]
//     objectPath.set(doc, 'didKey', did.didKey)
//     objectPath.set(doc, 'didJWK', did.didJWK)
//     await db.put(doc)
//     res.status(200).json({message: 'DID Key install complete'})
//   }
// })

app.post('/credential', async(req, res) => {
  console.log(req.body)
  console.log(req.headers)
  const authHeader = req.headers.authorization
  if (!authHeader) {
    console.log('no header')
    res.status(400).json({error: 'invalid_token'})
  } else {
    const jwt = authHeader.split(' ')[1]
    const response = await verify(jwt)
    console.log(response)
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
              console.log(payload)
              console.log(header)
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
                      if (objectPath.get(payload, 'aud') !== vcIssuerConf.issuer) {
                        console.log('aud does not match issuer')
                        res.status(400).json({error: 'invalid_request'})
                      } else {
                        const new_c_nonce = uuidv4()
                        const new_c_nonce_timestamp = Date.now()
                        objectPath.set(result, 'new_c_nonce', new_c_nonce)
                        objectPath.set(result, 'new_c_nonce_timestamp', new_c_nonce_timestamp)
                        await vc_db.put(result)
                        const response = {
                          'credential': result.verifiableCredential,
                          'format': 'jwt_vc',
                          new_c_nonce,
                          c_nonce_expires_in: 300
                        }
                        res.status(200).json(response)
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

app.get('/did_generate', async(req, res) => {
  const docker = new Docker()
  const key = new streams.WritableStream()
  const did = new streams.WritableStream()
  const doc = new streams.WritableStream()
  try {
    await docker.run('ghcr.io/spruceid/didkit-cli:latest', ['generate-ed25519-key'], key)
    const key_final = key.toString()
    try {
      await docker.run('ghcr.io/spruceid/didkit-cli:latest', ['key-to-did', 'key', '-j', key_final], did)
      const did_final = did.toString().replace( /[\r\n]+/gm, "" )
      try {
        await docker.run('ghcr.io/spruceid/didkit-cli:latest', ['did-resolve', did_final], doc)
        const doc_final = doc.toString()
        const ret = {
          key: JSON.parse(key_final),
          did: did_final,
          doc: JSON.parse(doc_final)
        }
        res.status(200).json(ret)
      } catch (e) {
        console.log(e)
      }
    } catch (e) {
      console.log(e)
    }
  } catch (e) {
    console.log(e)
  }
})

app.get('/did_vc_issue', async(req, res) => {
  const ret = await didkitIssue()
  res.status(200).json(ret)
})

app.post('/did_vc_verify', async (req, res) => {
  const ret = await didkitVerify(req.body.jwt)
  res.status(200).json(ret)
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
  // console.log(url)
  // const url_fix = url.replaceAll('profile%3A', 'profile:').replaceAll('read%3A', 'read:')
  // console.log(url_fix)
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
        const vc_doc = await didkitIssue(credentialSubject)
        const preauth_code = uuidv4()
        objectPath.set(vc_doc, '_id', preauth_code)
        objectPath.set(vc_doc, 'timestamp', Date().now)
        await vc_db.put(vc_doc)
        const uri = 'issuer=' + encodeURIComponent(vcIssuerConf.issuer) + '&credential_type=NPICredential&pre-authorized_code=' + preauth_code + '&user_pin_required=false'
        const vc = {
          uri: 'openid-initiate-issuance://?' + uri,
          uri_enc: uri
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

app.get('/jwks', (req, res) => {
  const ret = {
    "keys": JSON.parse(process.env.DIDKIT_HTTP_ISSUER_KEYS)
  }
  res.status(200).json(ret)
})

app.get('/identifiers/:uri', async(req, res) => {
  const opts = {headers: {'Content-Type': 'application/json'}}
  const result = await axios.get('http://didkit:9000/identifiers/' + req.params.uri, opts)
  res.status(200).json(result.data)
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
  const opts = JSON.parse(JSON.stringify(settings.couchdb_auth))
  const db = new PouchDB(urlFix(settings.couchdb_uri) + 'proxy', opts)
  let doc = {}
  if (objectPath.has(req, 'query.proxystate')) {
    try {
      doc = await db.get('id_' + req.query.proxystate)
    } catch (e) {
      res.status(200).send('Not authorized - state does not exist')
    }
  } else {
    if (objectPath.has(req, 'query.state')) {
      try {
        doc = await db.get('id_' + req.query.state)
      } catch (e) {
        res.status(200).send('Not authorized - state does not exist')
      }
    } else {
      res.status(200).send('Not authorized - no state given')
    }
  }
  let client_id = ''
  let client_secret = ''
  let scope = ''
  let base_url = ''
  let config = null
  if (doc.type === 'epic') {
    if (process.env.OPENEPIC_CLIENT_ID === null) {
      objectPath.set(doc, 'error', 'OpenEpic Client ID is not set')
      await db.put(doc)
      res.redirect(doc.response_uri)
    }
    if (!objectPath.has(doc, 'fhir_url')) {
      objectPath.set(doc, 'error', 'fhir_url is not set')
      await db.put(doc)
      res.redirect(doc.response_uri)
    }
    client_id = process.env.OPENEPIC_CLIENT_ID
    if (doc.fhir_url === 'https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4/') {
      if (process.env.OPENEPIC_SANDBOX_CLIENT_ID === null) {
        objectPath.set(doc, 'error', 'OpenEpic Sandbox Client ID is not set')
        await db.put(doc)
        res.redirect(doc.response_uri)
      }
      client_id = process.env.OPENEPIC_SANDBOX_CLIENT_ID
    }
    scope = 'openid patient/*.read user/*.* profile launch launch/patient offline_access online_access'
    try {
      config = await oidcclient.discovery(
        new URL(doc.fhir_url + '.well-known/openid-configuration'),
        client_id,
        '',
        oidcclient.None()
      )
    } catch (e) {
      objectPath.set(doc, 'error', 'Problem accessing OpenID Configuration')
      await db.put(doc)
      res.redirect(doc.response_uri)
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
      res.redirect(doc.response_uri)
    }
  }
  if (objectPath.has(req, 'query.proxystate')) {
    const code_verifier = oidcclient.randomPKCECodeVerifier()
    const code_challenge = await oidcclient.calculatePKCECodeChallenge(code_verifier)
    let url = null
    let parameters = {}
    if (doc.type === 'epic') {
      parameters = {
        redirect_uri: urlFix(process.env.DOMAIN) + 'oidc_relay_connect',
        scope: scope,
        code_challenge: code_challenge,
        state: req.query.proxystate,
        aud: doc.fhir_url,
        code_challenge_method: 'S256'
      }
    } else {
      parameters = {
        redirect_uri: urlFix(process.env.DOMAIN) + 'oidc_relay_connect',
        scope: scope,
        code_challenge: code_challenge,
        state: req.query.proxystate,
        code_challenge_method: 'S256'
      }
    }
    console.log(config)
    url = oidcclient.buildAuthorizationUrl(config, parameters)
    objectPath.set(doc, 'code_verifier', code_verifier)
    await db.put(doc)
    res.redirect(url)
  } else {
    const check = {
      pkceCodeVerifier: doc.code_verifier,
      expectedState: req.query.state
    }
    try {
      let tokenSet = null
      if (doc.type === 'epic') {
        tokenSet = await oidcclient.authorizationCodeGrant(
          config,
          new URL(req.protocol + '://' + req.get('host') + req.originalUrl),
          check
        )
        // tokenSet = await oidcclient.callback(urlFix(process.env.DOMAIN) + 'oidc_relay_connect', params, check)
        console.log(tokenSet)
        console.log('validated ID Token claims %j', tokenSet.claims())
      } else {
        tokenSet = await oidcclient.authorizationCodeGrant(
          config,
          new URL(req.protocol + '://' + req.get('host') + req.originalUrl),
          check
        )
        // tokenSet = await oidcclient.oauthCallback(urlFix(process.env.DOMAIN) + 'oidc_relay_connect', params, check)
      }
      console.log('received and validated tokens %j', tokenSet)
      objectPath.set(doc, 'access_token', tokenSet.access_token)
      if (doc.type === 'epic') {
        objectPath.set(doc, 'patient_token', tokenSet.patient)
      } else {
        objectPath.set(doc, 'patient_token', tokenSet.patient_token)
        objectPath.set(doc, 'refresh_token', tokenSet.refresh_token)
      }
      await db.put(doc)
      res.redirect(doc.response_uri)
    } catch (e) {
      console.log(e)
      res.status(200).json(e)
    }
  }
})

app.get('/oidc_relay_start/:state', (req, res) => {
  res.redirect(urlFix(process.env.DOMAIN) + 'oidc_relay_connect?proxystate=' + req.params.state)
})

app.get('/qr/:content', async(req, res) => {
  try {
    const content = 'openid-initiate-issuance://?' + req.params.content
    console.log(content)
    const qrStream = new PassThrough()
    const result = await QRCode.toFileStream(qrStream, content, {
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
  console.log(req.body)
  const opts = JSON.parse(JSON.stringify(settings.couchdb_auth))
  const vc_db = new PouchDB(urlFix(settings.couchdb_uri) + 'vc', opts)
  if (req.body.grant_type === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
    if (!objectPath.has(req, 'body.user_pin')) {
      try {
        const result = await vc_db.get(objectPath.get(req, 'body.pre-authorized_code'))
        const preauth_code_duration = getNumberOrUndefined(process.env.PRE_AUTHORIZED_CODE_EXPIRATION_DURATION) ?? 300000
        const comp_timestamp = result.timestamp + preauth_code_duration
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
          const access_token = await createJWT(vcIssuerConf.issuer, payload)
          const interval = getNumberOrUndefined(process.env.INTERVAL) ?? 300000
          const c_nonce = uuidv4()
          objectPath.set(result, 'c_nonce', c_nonce)
          objectPath.set(result, 'c_nonce_timestamp', Date.now())
          await vc_db.put(result)
          const response = {
            access_token,
            token_type: 'bearer',
            expires_in: 300,
            c_nonce,
            c_nonce_expires_in: 300000,
            authorization_pending: false,
            interval,
          }
          console.log(response)
          res.status(200).json(response)
        }
      } catch (e) {
        console.log('can not find doc')
        res.status(400).json({error: 'invalid_grant'})
      }
    } else {
      console.log('pin included but not needed')
      res.status(400).json({error: 'invalid_request'})
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