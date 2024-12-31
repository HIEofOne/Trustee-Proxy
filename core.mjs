import dotenv from 'dotenv'
dotenv.config()
import axios from 'axios'
import crypto from 'crypto'
import * as jose from 'jose'
import objectPath from 'object-path'
import PouchDB from 'pouchdb'
import settings from './settings.mjs'
import { v4 as uuidv4 } from 'uuid'
import PouchDBFind from 'pouchdb-find'
PouchDB.plugin(PouchDBFind)

async function createJWT(iss, payload=null, alg='RS256', key_header=false) {
  // aud is audience - base url of this server
  let use_key = null
  const keys = await getKeys()
  if (keys.length === 0) {
    const pair = await createKeyPair(alg)
    keys.push(pair)
  } else {
    const filter_keys = keys.filter((key) => {key.privateKey.alg === alg})
    if (filter_keys.length === 0) {
      use_key = await createKeyPair(alg)
    } else {
      use_key = filter_keys[0]
    }
  }
  const rsaPrivateKey = await jose.importJWK(use_key.privateKey, alg)
  const header = { alg: alg }
  if (key_header) {
    objectPath.set(header, 'jwk', use_key.publicKey)
  }
  const jwt = await new jose.SignJWT(payload)
    .setProtectedHeader(header)
    .setIssuedAt()
    .setIssuer(iss)
    .setExpirationTime('5m')
    .sign(rsaPrivateKey)
  return jwt
}

async function createSigner(alg, key) {
  let signer
  switch (alg) {
    case 'hmac-sha256':
      signer = async (data) => crypto.createHmac('sha256', key).update(data).digest()
      break
    case 'rsa-pss-sha512':
      signer = async (data) => crypto.createSign('sha512').update(data).sign({
        key: key,
        format: 'jwk',
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING
      })
      break
    case 'rsa-v1_5-sha256':
      signer = async (data) => crypto.createSign('sha256').update(data).sign({
        key: key,
        format: 'jwk',
        padding: crypto.constants.RSA_PKCS1_PADDING
      })
      break
    case 'ecdsa-p256-sha256':
      signer = async (data) => crypto.createSign('sha256').update(data).sign(key)
      break
    default:
      throw new Error(`Unsupported signing algorithm ${alg}`)
  }
  return Object.assign(signer, { alg })
}

function determinePath(endpoint, opts) {
  let path = endpoint
  if (opts?.prependUrl) {
    path = adjustUrl(path, { prepend: opts.prependUrl })
  }
  if (opts?.skipBaseUrlCheck !== true) {
    this.assertEndpointHasIssuerBaseUrl(endpoint)
  }
  if (endpoint.includes('://')) {
    path = new URL(endpoint).pathname
  }
  path = `/${trimBoth(path, '/')}`
  if (opts?.stripBasePath && path.startsWith(getBasePath())) {
    path = trimStart(path, getBasePath())
    path = `/${trimBoth(path, '/')}`
  }
  return path
}

function getBasePath() {
  const basePath = new URL(process.env.DOMAIN).pathname
  if (basePath === '' || basePath === '/') {
    return ''
  }
  return `/${trimBoth(basePath, '/')}`
}

function getNumberOrUndefined(input) {
  return input && !isNaN(+input) ? +input : undefined;
}

async function couchdbConfig(section, key, value) {
  const opts = JSON.parse(JSON.stringify(settings.couchdb_auth))
  objectPath.set(opts, 'headers', {'Content-Type': 'application/json'})
  const data = JSON.stringify(value).replace(/\\/g, "\\\\")
  try {
    const res = await axios.put(settings.couchdb_uri + '/_node/_local/_config/' + section + '/' + key, data, opts)
    return res.data
  } catch (e) {
    console.log(e.response.data)
    return e
  }
}

async function couchdbDatabase(patient_id='') {
  const db1 = new PouchDB(urlFix(settings.couchdb_uri) + 'doximity', settings.couchdb_auth)
  await db1.info()
  const db2 = new PouchDB(urlFix(settings.couchdb_uri) + 'proxy', settings.couchdb_auth)
  await db2.info()
}

async function couchdbInstall() {
  const keys = await getKeys()
  if (keys.length === 0) {
    const pair = await createKeyPair()
    keys.push(pair)
  }
  const key = await jose.importJWK(keys[0].publicKey)
  const pem = await jose.exportSPKI(key)
  const result = []
  const commands = [
    {section: 'jwt_keys', key: 'rsa:_default', value: pem}
  ]
  for (const command of commands) {
    console.log(command)
    const a = await couchdbConfig(command.section, command.key, command.value)
    result.push({command: command, result: a})
  }
  await couchdbRestart()
  await sleep(5)
  return result
}

async function couchdbRestart() {
  var opts = settings.couchdb_auth
  objectPath.set(opts, 'headers', {'Content-Type': 'application/json'})
  try {
    const res = await axios.post(settings.couchdb_uri + '/_node/_local/_restart', '', opts)
    objectPath.del(opts, 'headers')
    return res.data
  } catch (e) {
    console.log(e.response.data)
    return e
  }
}

async function createKeyPair(alg='RS256') {
  const { publicKey, privateKey } = await jose.generateKeyPair(alg)
  const public_key = await jose.exportJWK(publicKey)
  const kid = uuidv4()
  objectPath.set(public_key, 'kid', kid)
  objectPath.set(public_key, 'alg', alg)
  const private_key = await jose.exportJWK(privateKey)
  objectPath.set(private_key, 'kid', kid)
  objectPath.set(private_key, 'alg', alg)
  const keys = await getKeys()
  let doc = {}
  if (keys.length > 0) {
    doc = keys[0]
    objectPath.set(doc, 'publicKey', public_key)
    objectPath.set(doc, 'privateKey', private_key)
  } else {
    doc = {_id: kid, publicKey: public_key, privateKey: private_key}
  }
  const db = new PouchDB(urlFix(settings.couchdb_uri) + 'keys', settings.couchdb_auth)
  await db.put(doc)
  return doc
}

function equals (a, b) {
  if (a === b) {
    return true
  }
  if (a instanceof Date && b instanceof Date) {
    return a.getTime() === b.getTime()
  }
  if (!a || !b || (typeof a !== 'object' && typeof b !== 'object')) {
    return a === b
  }
  if (a.prototype !== b.prototype) {
    return false
  }
  const keys = Object.keys(a)
  if (keys.length !== Object.keys(b).length) {
    return false
  }
  return keys.every(k => equals(a[k], b[k]))
}

function extractComponent(message, component) {
  switch (component) {
    case '@method':
      return message.method.toUpperCase();
    case '@target-uri':
      return message.url;
    case '@authority': {
      const url = new URL(message.url);
      const port = url.port ? parseInt(url.port, 10) : null;
      return `${url.host}${port && ![80, 443].includes(port) ? `:${port}` : ''}`;
    }
    case '@scheme': {
      const { protocol } = new URL(message.url);
      return protocol.slice(0, -1);
    }
    case '@request-target': {
      const { pathname, search } = new URL(message.url);
      return `${pathname}${search}`;
    }
    case '@path': {
      const { pathname } = new URL(message.url);
      return pathname;
    }
    case '@query': {
      const { search } = new URL(message.url);
      return search;
    }
    case '@status':
      if (!(message).status) {
        throw new Error(`${component} is only valid for responses`);
      }
      return (message).status.toString();
    case '@query-params':
    case '@request-response':
      throw new Error(`${component} is not implemented yet`);
    default:
      throw new Error(`Unknown specialty component ${component}`);
  }
}

function extractHeader({ headers }, header, opts) {
  const lcHeader = header.toLowerCase();
  const key = Object.keys(headers).find((name) => name.toLowerCase() === lcHeader);
  const allowMissing = opts?.allowMissing ?? true;
  if (!allowMissing && !key) {
    throw new Error(`Unable to extract header "${header}" from message`);
  }
  let val = key ? headers[key] ?? '' : '';
  if (Array.isArray(val)) {
      val = val.join(', ');
  }
  return val.toString().replace(/\s+/g, ' ');
}

async function getAllKeys() {
  const keys = []
  let publicKey = ''
  const db = new PouchDB((settings.couchdb_uri + '/keys'), settings.couchdb_auth)
  const result = await db.find({
    selector: {_id: {"$gte": null}}, limit: 0
  })
  for (const a in result.docs) {
    keys.push(result.docs[a].publicKey)
    if (objectPath.has(result, 'docs.' + a + '.privateKey')) {
      publicKey = result.docs[a].publicKey
    }
  }
  return {keys: keys, publicKey: publicKey}
}

async function getKeys() {
  const db = new PouchDB(urlFix(settings.couchdb_uri) + 'keys', settings.couchdb_auth)
  const result = await db.find({
    selector: {_id: {"$gte": null}, privateKey: {"$gte": null}}, limit: 0
  })
  return result.docs
}

async function getPIN(patient_id) {
  const db = new PouchDB('pins', {skip_setup: true})
  const info = await db.info()
  if (objectPath.has(info, 'error')) {
    return false
  }
  try {
    const result = await db.get(patient_id)
    return result.pin
  } catch (e) {
    return false
  }
  
}

async function signatureHeader(resource, opts) {
  const headers = resource.headers
  const parts = opts.components.map((component) => {
    let value
    if (component.startsWith('@')) {
      value = extractComponent(resource, component)
    } else {
      value = extractHeader(resource, component)
    }
    return`"${component.toLowerCase()}": ${value}`
  })
  const components = opts.components.map((name) => `"${name.toLowerCase()}"`).join(' ');
  const params = Object.entries(opts.parameters).map(([parameter, value]) => {
    if (typeof value === 'number') {
      return `;${parameter}=${value}`
    } else if (value instanceof Date) {
      return `;${parameter}=${Math.floor(value.getTime() / 1000)}`
    } else {
      return `;${parameter}="${value.toString()}"`
    }
  }).join('')
  const signatureInputString = `(${components})${params}`
  parts.push(`"@signature-params": ${signatureInputString}`)
  const data = parts.join('\n')
  const signer = await createSigner(opts.parameters.alg, opts.key.privateKey)
  const signature = await signer(Buffer.from(data))
  objectPath.set(headers, 'Signature-Input', 'sig1=' + signatureInputString)
  objectPath.set(headers, 'Signature', 'sig1=:' + signature.toString('base64'))
  return headers
}

async function sleep(seconds) {
  return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}

function urlFix(url) {
  return url.replace(/\/?$/, '/')
}

async function verify(jwt) {
  const keys = await getAllKeys()
  const response = {}
  let found = false
  if (keys.keys.length > 0) {
    for (const a in keys.keys) {
      const jwk = await jose.importJWK(keys.keys[a])
      try {
        const { payload, protectedHeader } = await jose.jwtVerify(jwt, jwk)
        objectPath.set(response, 'status', 'isValid')
        objectPath.set(response, 'payload', payload)
        objectPath.set(response, 'protectedHeader', protectedHeader)
        found = true
      } catch (err) {
        if (found !== true) {
          objectPath.set(response, 'status', 'notValid')
          objectPath.set(response, 'error', err)
        }
      }
    }
  } else {
    objectPath.set(response, 'status', 'noKeys')
  }
  return response
}


export { createJWT, createSigner, couchdbConfig, couchdbDatabase, couchdbInstall, determinePath, equals, extractComponent, extractHeader, getKeys, getNumberOrUndefined, getPIN, signatureHeader, sleep, urlFix, verify }