# Auth in hotspot via passkeys

```
docker run \
    -p 8080:8080 \
    -e DB_USER=postgres \
    -e DB_PASSWORD=admin \
    -e DB_HOST=localhost \
    -e DB_PORT=5432 \
    -e DB_NAME=radius \
    -e WEBAUTHN_EXTERNAL_URL=http://localhost:8080 \
    -e WEBAUTHN_DISPLAY_NAME=Webauthn \
    -e WEBAUTHN_CONVEYANCE_PREFERENCE=none \
    -e WEBAUTHN_USER_VERIFICATION_REQUIREMENT=required \
    -e COOKIE_DOMAIN=localhost \
    -e COOKIE_LIFETIME=604800 \
    -e RADCHECK_LIFETIME=604800 \
    -e MAC_EXPIRE_POLL_TIME=3600 \
    --name auth \
    -d registry.git.leshe4ka.ru/leshe4ka/webauthn/main:latest
```

Sample configuration fot Mikrotik router is in `config.rsc` and `login.html` file