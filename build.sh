#!/bin/sh

cd web
if [ ! -d "node_modules" ]; then
  npm install
fi
npm run build