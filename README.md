# Trustee Proxy

Trustee Proxy is a hosted server that provides several key functionalities that compliment [Trustee Community](https://github.com/HIEofOne/Trustee-Community)

- Generates [verifible credientials](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) through [Doximity API](https://www.doximity.com/developers/home/) authentication for medical providers.  This is made possible through [SpruceID's DIDKit libraries](https://github.com/spruceid/didkit).
- Proxy connection via the [SMART on FHIR API](https://docs.smarthealthit.org/) for access to [open.epic](https://open.epic.com/) and [BlueButton 2.0](https://bluebutton.cms.gov/developers/) resources.  This allows one-way sync of patient health information, gathered by the patient, into [NOSH3](https://github.com/shihjay2/nosh3), an open source patient health record system.

## Installation
#### 1. Gather all API keys for Doximity, open.epic, Bluebutton 2.0
- have these ready for the installer in step 3
- details on getting API keys are in the section [More on Additional API Services](#more-on-additional-api-services)
- assume you have a domain name (mydomain.xyz) and email address needed for LetsEncrypt SSL (my@email.xyz)
#### 2. Create a DigitalOcean Droplet with the minimum parameters:
- size: 's-1vcpu-1gb',
- image: 'ubuntu-22-10-x64'
#### 3. Login to the console (should be root user) and enter this command:
```
git clone -b deploy --single-branch https://github.com/HIEofOne/Trustee-Proxy.git
cd Trustee-Proxy
./do-install.sh
```

## More on Additional API Services (TBD)


## Architecture
Trustee-Proxy is based around Docker containers.  This repository source code is for the Trustee core which is express.js based application and served by Node.JS.

The docker-compose.yml (template found in docker-compose.tmp under the docker directory) defines the specific containers that when working together, allow Trustee to be able to fully featured (e.g. a bundle).  Below are the different containers and what they do:
#### 1. [Traefik](https://doc.traefik.io/traefik/providers/docker/) - this is the router, specifying the ports and routing to the containers in the bundle 
#### 2. [CouchDB](https://couchdb.apache.org/) - this is the NoSQL database that stores all documents
#### 3. [DIDKit](https://github.com/spruceid/didkit) - this generates the verifiable credential
#### 4. [Watchtower](https://github.com/containrrr/watchtower) - this service pulls and applies updates to all Docker Images in the bundle automatically without manager intervention

## Developer API

### Doximity Verifiable Credential endpoint
```
GET /doximity
```
Upon successful authentication with the Doximity API, a Verifiable Credential can then be issued to a Verfiable Credential wallet such as [Sphereon](https://github.com/Sphereon-Opensource/ssi-mobile-wallet).  For GNAP claims gathering for [Trustee-Community](https://github.com/HIEofOne/Trustee-Community), this Verfiable Credential can then be presented from the wallet.

### Begin SMART on FHIR flow
```
POST /oidc_relay
Content-Type: application/json
{
  "origin_uri": "https://my.emr.xyz/123?oidc=epic",
  "response_uri": "https://my.emr.xyz/123?oidc=epic",
  "type": "epic",
  "state": "5f809eef-0107-4b2f-8c14-9386b75234f2",
  "fhir_url": "https://haiku.wacofhc.org/FHIR/api/FHIR/R4/"
  "refresh_token": ""
}
```
where type can be "epic" or "cms_bluebutton"
and "fhir_url" field is needed for "epic" type

If verified successfuly, Trustee-Proxy responds with:
```
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
"OK"
```

Client then redirects the browser to this endpoint:
```
GET /oidc_relay_start/5f809eef-0107-4b2f-8c14-9386b75234f2
```
Where the last path refers to the "state" value

The remainder of the OIDC OAuth 2.0 flow continues.
Following sucessful authentication,
```
GET /oidc_relay/5f809eef-0107-4b2f-8c14-9386b75234f2
```
Whereupon the access token is provided for resource gathering by the client.

```
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
{
  "access_token": "023940293480293423"
}
```

