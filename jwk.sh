#!/bin/bash
# update jwk script for Trustee-Proxy in a DigitalOcean Ubuntu Droplet
set -e
if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root.  Aborting." 1>&2
	exit 1
fi
FILE=./.env
read -e -p "Enter your CouchDB Password for admin user: " -i "" COUCHDB_PASSWORD
KEY=`/usr/bin/docker run ghcr.io/spruceid/didkit-cli:latest generate-ed25519-key`
REV1=$(curl -X GET http://admin:$COUCHDB_PASSWORD@localhost:5984/didkit/issuer_key | jq -r '._rev')
echo $REV1
UKEY=$(echo $KEY | jq --arg rev1 $REV1 '. += {"_rev": $rev1}')
curl -X PUT http://admin:$COUCHDB_PASSWORD@localhost:5984/didkit/issuer_key -d "$UKEY"
DID=`/usr/bin/docker run ghcr.io/spruceid/didkit-cli:latest key-to-did key -j $KEY`
DOC=`/usr/bin/docker run ghcr.io/spruceid/didkit-cli:latest did-resolve $DID`
REV2=$(curl -X GET http://admin:$COUCHDB_PASSWORD@localhost:5984/didkit/did_doc | jq -r '._rev')
echo $REV2
UDOC=$(echo $DOC | jq --arg rev2 $REV2 '. += {"_rev": $rev2}')
curl -X PUT http://admin:$COUCHDB_PASSWORD@localhost:5984/didkit/did_doc -d "$UDOC"
sed -i '/^DIDKIT_HTTP_ISSUER_KEYS=/s/=.*/='"[$KEY]"'/' ./.env
TEST=$(curl -X GET http://admin:$COUCHDB_PASSWORD@localhost:5984/didkit/issuer_key)
echo $TEST
TEST1=$(curl -X GET http://admin:$COUCHDB_PASSWORD@localhost:5984/didkit/did_doc)
echo $TEST1
exit 0