#!/bin/bash
# install script for Trustee-Proxy in a DigitalOcean Ubuntu Droplet
set -e
if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root.  Aborting." 1>&2
	exit 1
fi
FILE=./.env
read -e -p "Enter your CouchDB Password for admin user: " -i "" COUCHDB_PASSWORD
if [ ! -f "$FILE" ]; then
  # set domain entries
  read -e -p "Enter your Root Domain Name (domain.com): " -i "" ROOT_DOMAIN
  read -e -p "Enter your E-Mail address for Let's Encrypt (your@email.com): " -i "" EMAIL
  read -e -p "Enter your Doximity Client ID: " -i "" DOXIMITY_CLIENT_ID
  read -e -p "Enter your Doximity Client Secret: " -i "" DOXIMITY_CLIENT_SECRET
  read -e -p "Enter your OpenEPIC Client ID: " -i "" OPENEPIC_CLIENT_ID
  read -e -p "Enter your OpenEPIC Sandbox Client ID: " -i "" OPENEPIC_SANDBOX_CLIENT_ID
  read -e -p "Enter your CMS Bluebutton Sandbox Client ID: " -i "" CMS_BLUEBUTTON_SANDBOX_CLIENT_ID 
  read -e -p "Enter your CMS Bluebutton Sandbox Client Secret: " -i "" CMS_BLUEBUTTON_SANDBOX_CLIENT_SECRET
  read -e -p "Enter your CMS Bluebutton Client ID: " -i "" CMS_BLUEBUTTON_CLIENT_ID
  read -e -p "Enter your CMS Bluebutton Client Secret: " -i "" CMS_BLUEBUTTON_CLIENT_SECRET
  sed -i "s/example.com/$ROOT_DOMAIN/" ./docker-compose.yml
  sed -i "s/example@example.com/$EMAIL/" ./docker-compose.yml
  cp ./env ./.env
  sed -i "s/example.com/$ROOT_DOMAIN/" ./.env
  sed -i '/^COUCHDB_USER=/s/=.*/='"admin"'/' ./.env
  sed -i '/^COUCHDB_PASSWORD=/s/=.*/='"$COUCHDB_PASSWORD"'/' ./.env
  sed -i '/^DOXIMITY_CLIENT_ID=/s/=.*/='"$DOXIMITY_CLIENT_ID"'/' ./.env
  sed -i '/^DOXIMITY_CLIENT_SECRET=/s/=.*/='"$DOXIMITY_CLIENT_SECRET"'/' ./.env
  sed -i '/^OPENEPIC_CLIENT_ID=/s/=.*/='"$OPENEPIC_CLIENT_ID"'/' ./.env
  sed -i '/^OPENEPIC_SANDBOX_CLIENT_ID=/s/=.*/='"$OPENEPIC_SANDBOX_CLIENT_ID"'/' ./.env
  sed -i '/^CMS_BLUEBUTTON_SANDBOX_CLIENT_ID=/s/=.*/='"$CMS_BLUEBUTTON_SANDBOX_CLIENT_ID"'/' ./.env
  sed -i '/^CMS_BLUEBUTTON_SANDBOX_CLIENT_SECRET=/s/=.*/='"$CMS_BLUEBUTTON_SANDBOX_CLIENT_SECRET"'/' ./.env
  sed -i '/^CMS_BLUEBUTTON_CLIENT_ID=/s/=.*/='"$CMS_BLUEBUTTON_CLIENT_ID"'/' ./.env
  sed -i '/^CMS_BLUEBUTTON_CLIENT_SECRET=/s/=.*/='"$CMS_BLUEBUTTON_CLIENT_SECRET"'/' ./.env
fi
curl -X PUT http://admin:$COUCHDB_PASSWORD@localhost:5984/didkit
KEY=`/usr/bin/docker run ghcr.io/spruceid/didkit-cli:latest generate-ed25519-key`
curl -X PUT http://admin:$COUCHDB_PASSWORD@localhost:5984/didkit/issuer_key -d "$KEY"
DID=`/usr/bin/docker run ghcr.io/spruceid/didkit-cli:latest key-to-did key -j $KEY`
DOC=`/usr/bin/docker run ghcr.io/spruceid/didkit-cli:latest did-resolve $DID`
curl -X PUT http://admin:$COUCHDB_PASSWORD@localhost:5984/didkit/did_doc -d "$DOC"
sed -i '/^DIDKIT_HTTP_ISSUER_KEYS=/s/=.*/='"[$KEY]"'/' ./.env
exit 0
