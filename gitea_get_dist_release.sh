#!/bin/bash

returned_data=$(/usr/bin/curl -k -X 'GET' \
  "https://git.leshe4ka.ru/api/v1/repos/webauthn/front/releases/latest" \
  -H 'accept: application/json')

download_url=$(echo "$returned_data" | grep -oP '"browser_download_url": *"\K[^"]+')

echo "Downloading dist from: $download_url"

/usr/bin/curl -k --output .download.tar.gz "$download_url"
tar -xvf .download.tar.gz
rm -rf .download.tar.gz