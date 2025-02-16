# Auth in hotspot via passkeys
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fleshe4ka46%2Fhotspot_passkey_auth_server.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fleshe4ka46%2Fhotspot_passkey_auth_server?ref=badge_shield)


```
docker run \
    --net=host \
    -e DB_USER=postgres \
    -e DB_PASSWORD=12345678 \
    -e DB_HOST=172.17.0.2 \
    -e DB_PORT=5432 \
    -e DB_NAME=radius \
    -e WEBAUTHN_EXTERNAL_URL=http://localhost:8080 \
    -e WEBAUTHN_DISPLAY_NAME=Webauthn \
    -e WEBAUTHN_CONVEYANCE_PREFERENCE=indirect \
    -e WEBAUTHN_AUTHENTICATOR_ATTACHMENT=cross-platform \
    -e WEBAUTHN_USER_VERIFICATION_REQUIREMENT=preferred \
    -e COOKIE_DOMAIN=localhost \
    --name auth \
    -d git.leshe4ka.ru/webauthn/server
```

Sample configuration fot Mikrotik router is in `config.rsc` and `login.html` file

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fleshe4ka46%2Fhotspot_passkey_auth_server.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fleshe4ka46%2Fhotspot_passkey_auth_server?ref=badge_large)