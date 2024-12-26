import dotenv from 'dotenv'
dotenv.config()
import axios from 'axios'
import crypto from 'crypto'
// import { createJWT, decodeJWT, ES256KSigner, hexToBytes, verifyJWT } from 'did-jwt'
// import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyCredential, verifyPresentation } from 'did-jwt-vc'
// import { Resolver } from 'did-resolver'
// import elliptic from 'elliptic'
import * as jose from 'jose'
import moment from 'moment'
import objectPath from 'object-path'
import PouchDB from 'pouchdb'
import settings from './settings.mjs'
import { v4 as uuidv4 } from 'uuid'
import Docker from 'dockerode'

// import { getResolver } from 'web-did-resolver'

import PouchDBFind from 'pouchdb-find'
PouchDB.plugin(PouchDBFind)

// const jwksService = jose.createRemoteJWKSet(new URL(settings.jwks_uri))

// async function createDIDIssuer() {
//   var keys = await getKeys()
//   const url = new URL(process.env.DOMAIN)
//   if (keys.length > 0) {
//     if (objectPath.has(keys[0], 'didKey')) {
//       const signer = ES256KSigner(hexToBytes(keys[0].didKey))
//       const issuer = {
//         did: 'did:web:' + url.pathname,
//         signer: signer
//       }
//       return issuer
//     }
//   }
//   return false
// }

// function createDIDKey() {
//   const size = parseInt(process.argv.slice(2)[0]) || 32
//   const prv_key = crypto.randomBytes(size).toString('hex')
//   const ec = new elliptic.ec('secp256k1')
//   const prv = ec.keyFromPrivate(prv_key, 'hex')
//   const pub = prv.getPublic()
//   const x = pub.x.toBuffer().toString('base64')
//   const y = pub.y.toBuffer().toString('base64')
//   const jwk = {
//     "kty":"EC",
//     "crv":"secp256k1",
//     "x": x,
//     "y": y,
//   }
//   const ret = {didKey: prv_key, didJWK: jwk}
//   return ret
// }

// async function createDIDSigner(name) {
//   var keys = await getKeys()
//   const url = new URL(process.env.DOMAIN)
//   if (keys.length > 0) {
//     if (objectPath.has(keys[0], 'didKey')) {
//       const signer = ES256KSigner(hexToBytes(keys[0].didKey))
//       const jwt = await createJWT(
//         { aud: 'did:web:' + url.pathname, name: name },
//         { issuer: 'did:web:' + url.pathname, signer },
//         { alg: 'ES256K' }
//       )
//       return jwt
//     }
//   }
//   return false
// }

// async function createDIDVC(vcPayload) {
  // const issuer = await createDIDIssuer()
  // const vcPayload = {
  //   sub: 'did:web:' + url.pathname,
  //   nbf: 1562950282,
  //   vc: {
  //     '@context': ['https://www.w3.org/2018/credentials/v1'],
  //     type: ['VerifiableCredential'],
  //     credentialSubject: {
  //       degree: {
  //         type: 'BachelorDegree',
  //         name: 'Baccalauréat en musiques numériques'
  //       }
  //     }
  //   }
  // }
  // const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer)
  // console.log('//// Verifiable Credential:\n', vcJwt)
  // return vcJwt
// }

// async function createDIDVP(vpPayload) {
//   const issuer = await createDIDIssuer()
  // const vpPayload = {
  //   vp: {
  //     '@context': ['https://www.w3.org/2018/credentials/v1'],
  //     type: ['VerifiablePresentation'],
  //     verifiableCredential: [vcJwt],
  //     foo: "bar"
  //   }
  // }
//   const vpJwt = await createVerifiablePresentationJwt(vpPayload, issuer)
//   console.log('\n//// Verifiable Presentation:\n', vpJwt)
//   return vpJwt
// } 

async function createJWT(iss, payload=null) {
  // aud is audience - base url of this server
  const keys = await getKeys()
  if (keys.length === 0) {
    const pair = await createKeyPair()
    keys.push(pair)
  }
  const rsaPrivateKey = await jose.importJWK(keys[0].privateKey, 'RS256')
  const payload_vc = {
  //   "vc": {
  //     "@context": [
  //       "https://www.w3.org/2018/credentials/v1",
  //       "https://www.w3.org/2018/credentials/examples/v1"
  //     ],
  //     "id": "http://example.edu/credentials/3732",
  //     "type": [
  //       "VerifiableCredential",
  //       "UniversityDegreeCredential"
  //     ],
  //     "issuer": "https://example.edu/issuers/565049",
  //     "issuanceDate": "2010-01-01T00:00:00Z",
  //     "credentialSubject": {
  //       "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
  //       "degree": {
  //         "type": "BachelorDegree",
  //         "name": "Bachelor of Science and Arts"
  //       }
  //     }
  //   },
  //   // app specific payload
  //   "_couchdb.roles": ["_admin"],
  //   "_nosh": {
  //     "role": "provider" // provider, patient, support, proxy
  //   }
  }
  let payload_final = {}
  if (payload !== null) {
    payload_final = {
      // ...payload_vc,
      ...payload
    }
  } else {
    payload_final = payload_vc
  }
  const header = { alg: 'RS256' }
  const jwt = await new jose.SignJWT(payload_final)
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

async function didkitIssue_alt(credentialSubject) {
  // const opts = {headers: {'Content-Type': 'application/json'}}
  const db = new PouchDB(urlFix(settings.couchdb_uri) + 'didkit', settings.couchdb_auth)
  try {
    const result = await db.get('did_doc')
    console.log(credentialSubject)
    const cmd = [
      'vc-issue-credential',
      '-j',
      process.env.JWK,
      '-v',
      result.assertionMethod[0],
      '-p',
      'assertionMethod',
    ]
    const opts = {
      Image: 'ghcr.io/spruceid/didkit-cli:latest',
      Cmd: cmd,
    }
    const stdin = {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://dir.hieofone.org"
      ],
      "id": "http://example.org/credentials/3731", //need to set
      "type": ["VerifiableCredential", "ExampleNPICredential"],
      "issuer": result.id,
      "issuanceDate": moment().format('YYYY-MM-DDTHH:mm:ss.SSSZ'),
      "credentialSubject": credentialSubject
    }
    try {
      const a = await dockerRunWithStdIn(JSON.stringify(stdin), opts)
      try {
        return JSON.parse(a)
      } catch (e) {
        return a
      }
    } catch(e) {
      console.log(e)
    }
  } catch (e) {
    console.log(e)
  }
}

async function didkitIssue(credentialSubject) {
  const opts = {headers: {'Content-Type': 'application/json'}}
  const db = new PouchDB(urlFix(settings.couchdb_uri) + 'didkit', settings.couchdb_auth)
  try {
    const result = await db.get('did_doc')
    console.log(credentialSubject)
    const body = {
      "credential": {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://www.w3.org/ns/credentials/examples/v2",
          urlFix(process.env.DOMAIN) + "contexts/v1"
        ],
        // "id": "http://example.org/credentials/3731", //need to set
        "type": ["VerifiableCredential", "NPICredential", "OpenBadgeCredential"],
        "issuer": result.id,
        "issuanceDate": moment().format('YYYY-MM-DDTHH:mm:ss.SSSZ'),
        "credentialSubject": credentialSubject
      },
      "options": {
        // "type": "Ed25519Signature2020"
      }
      // "options": {
      //   "verificationMethod": result.assertionMethod[0],
      //   "proofPurpose": "assertionMethod",
      //   "proofFormat": "jwt"
      // }
    }
    try {
      const res = await axios.post('http://didkit:3000/credentials/issue', body, opts)
      console.log(res.data)
      return res.data
    } catch (e) {
      console.log(e)
      return e
    }
  } catch (e) {
    console.log(e)
  }
}

async function didkitVerify(vc) {
  const opts = {headers: {'Content-Type': 'application/json'}}
  const db = new PouchDB(urlFix(settings.couchdb_uri) + 'didkit', settings.couchdb_auth)
  try {
    const result = await db.get('did_doc')
    const body = {
      "verifiableCredential": vc,
      "options": {
        "verificationMethod": result.assertionMethod[0],
        "proofPurpose": "assertionMethod",
        "proofFormat": "jwt"
      }
    }
    try {
      const res = await axios.post('http://didkit:3000/credentials/verify', body, opts)
      return res.data
    } catch (e) {
      console.log(e.response.data)
      return e
    }
  } catch (e) {
    console.log(e)
  }
}

async function dockerRunWithStdIn(stdin, options) {
  const docker = new Docker()
  const container = await docker.createContainer(Object.assign({
    OpenStdin: true,
    AttachStdin: true,
    AttachStdout: true,
    AttachStderr: true,
    StdinOnce: true
  }, options))
  const stream = await container.attach({
    hijack: true,
    stderr: true,
    stdin: true,
    stdout: true,
    stream: true
  })
  const stdout = new Promise((resolve) => {
    stream.on('data', (data) => {
      // The first 8 bytes are used to define the response header.
      // Please refer to https://docs.docker.com/engine/api/v1.37/#operation/ContainerAttach
      const response = data && data.slice(8).toString()
      console.log(data)
      console.log(response)
      resolve(response)
    })
  })
  console.log(stdin)
  stream.write(stdin)
  await container.start()
  stream.end()
  await container.wait()
  container.remove()
  return stdout
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
  const did = createDIDKey()
  const keys = await getKeys()
  let doc = {}
  if (keys.length > 0) {
    doc = keys[0]
    objectPath.set(doc, 'publicKey', public_key)
    objectPath.set(doc, 'privateKey', private_key)
    objectPath.set(doc, 'didKey', did.didKey)
    objectPath.set(doc, 'didJWK', did.didJWK)
  } else {
    doc = {_id: kid, publicKey: public_key, privateKey: private_key, didKey: did.didKey, didJWK: did.didJWK}
  }
  const db = new PouchDB(urlFix(settings.couchdb_uri) + 'keys', settings.couchdb_auth)
  await db.put(doc)
  return doc
}


// function decodeDIDJWT(jwt) {
//   const decoded = decodeJWT(jwt)
//   return decoded
// console.log('\n//// JWT Decoded:\n',decoded)
// }

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
  // var trustee_key = null
  // Trustee key
  // try {
  //   var trustee_key = await axios.get(urlFix(process.env.TRUSTEE_URL) + 'jwks')
  // } catch (err) {
  //   console.log(err)
  // }
  // if (trustee_key !== null && trustee_key.status === 200 && objectPath.has(trustee_key, 'data.keys')) {
  //   for (var b in trustee_key.data.keys) {
  //     keys.push(trustee_key.data.keys[b])
  //   }
  // }
  // Local key
  const db = new PouchDB((settings.couchdb_uri + '/keys'), settings.couchdb_auth)
  const result = await db.find({
    selector: {_id: {"$gte": null}}
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
    selector: {_id: {"$gte": null}, privateKey: {"$gte": null}}
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

// async function verifyDIDJWT(orignal_jwt) {
//   const url = new URL(process.env.DOMAIN)
//   const webResolver = getResolver()
//   const resolver = new Resolver({
//     ...webResolver
//   })
//   try {
//     const { payload, doc, did, signer, jwt } = await verifyJWT(orignal_jwt, {
//       resolver,
//       audience: 'did:web:' + url.pathname
//     })
//     console.log('\n//// Verified:\n', payload)
//     return payload
//   } catch (e) {
//     return e
//   }
// }

// async function verifyDIDVC(vcJwt) {
//   const resolver = new Resolver(getResolver())
//   try {
//     const verifiedVC = await verifyCredential(vcJwt, resolver)
//     console.log('//// Verified Credentials:\n', verifiedVC)
//     return verifiedVC
//   } catch (e) {
//     return false
//   }
// }

// async function verifyDIDVP(vpJwt) {
//   const resolver = new Resolver(getResolver())
//   try {
//     const verifiedVP = await verifyPresentation(vpJwt, resolver)
//     console.log('\n//// Verified Presentation:\n', verifiedVP)
//     return verifiedVP
//   } catch (e) {
//     return false
//   }
// }

export { createJWT, createSigner, couchdbConfig, couchdbDatabase, couchdbInstall, determinePath, didkitIssue, didkitVerify, equals, extractComponent, extractHeader, getKeys, getNumberOrUndefined, getPIN, signatureHeader, sleep, urlFix, verify }