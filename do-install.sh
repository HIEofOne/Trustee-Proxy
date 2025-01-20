#!/bin/bash
# install script for Trustee-Proxy in a DigitalOcean Ubuntu Droplet
set -e
if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root.  Aborting." 1>&2
	exit 1
fi
if [ -d "${HOME}/.nvm/.git" ]; then
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
    read -e -p "Enter your Cerner Client ID: " -i "" CERNER_CLIENT_ID
    read -e -p "Enter your CMS Bluebutton Sandbox Client ID: " -i "" CMS_BLUEBUTTON_SANDBOX_CLIENT_ID 
    read -e -p "Enter your CMS Bluebutton Sandbox Client Secret: " -i "" CMS_BLUEBUTTON_SANDBOX_CLIENT_SECRET
    read -e -p "Enter your CMS Bluebutton Client ID: " -i "" CMS_BLUEBUTTON_CLIENT_ID
    read -e -p "Enter your CMS Bluebutton Client Secret: " -i "" CMS_BLUEBUTTON_CLIENT_SECRET
    read -e -p "Enter your Infuria API Key: " -i "" INFURIA_API_KEY
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
    sed -i '/^CERNER_CLIENT_ID=/s/=.*/='"$CERNER_CLIENT_ID"'/' ./.env
    sed -i '/^CMS_BLUEBUTTON_SANDBOX_CLIENT_ID=/s/=.*/='"$CMS_BLUEBUTTON_SANDBOX_CLIENT_ID"'/' ./.env
    sed -i '/^CMS_BLUEBUTTON_SANDBOX_CLIENT_SECRET=/s/=.*/='"$CMS_BLUEBUTTON_SANDBOX_CLIENT_SECRET"'/' ./.env
    sed -i '/^CMS_BLUEBUTTON_CLIENT_ID=/s/=.*/='"$CMS_BLUEBUTTON_CLIENT_ID"'/' ./.env
    sed -i '/^CMS_BLUEBUTTON_CLIENT_SECRET=/s/=.*/='"$CMS_BLUEBUTTON_CLIENT_SECRET"'/' ./.env
    sed -i '/^INFURIA_API_KEY=/s/=.*/='"$INFURIA_API_KEY"'/' ./.env
  fi
  mkdir dbconfig
  cd dbconfig
  curl -O https://raw.githubusercontent.com/HIEofOne/Trustee-Proxy/master/docker.ini
  exit 0
else
  echo "NVM not installed.  Installing all dependencies for Trustee-Community..."  
  apt update
  # install dependencies
  apt install -y apt-transport-https ca-certificates curl software-properties-common jq
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
  add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
  # get nvm
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
  echo "Now is also a good time to make sure your domain name is associated with the public IP of this droplet."
  echo "Afterwards, logout and log back in and run cd Trustee-Proxy;./do-install.sh again"
  exit 0
fi
