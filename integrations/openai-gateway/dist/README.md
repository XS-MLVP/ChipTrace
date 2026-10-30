# Gateway admin UI (compiled)

`gateway-admin-ui.tar.gz` is the compiled `admin-next` single-page app served by the
18084 gateway. `server.js` serves `PUBLIC_DIR`, which defaults to `public/` next to
`server.js`; unpack this archive there before starting the gateway:

```bash
install -d integrations/openai-gateway/public
tar -xzf integrations/openai-gateway/dist/gateway-admin-ui.tar.gz \
  -C integrations/openai-gateway --strip-components=1
```

The archive contains no secrets. It is a build artifact: the source is the upstream
`web/admin-spa` SPA, which is not vendored in this repository, so keep the archive in
version control rather than rebuilding it blindly. Its contents were byte-identical to
what the production gateway served on 2026-10-30.
