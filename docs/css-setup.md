# Setup with CSS
This markdown explains how to setup the css to work with the aggregator.
Start by cloning `https://github.com/SolidLabResearch/user-managed-access`:
```bash
git clone https://github.com/SolidLabResearch/user-managed-access
cd user-managed-access
```

The uma package needs to trust `*.local` adresses over http (by default this is only for localhost adresses) so the `@solid/access-token-verifier` package needs to be overwritten with the `access-token-verifier-local`package. This can be done by changing two package.json lines.
in toplevel package.json:
```json
{
  ...
  "resolutions": {
    "@types/node": "^20.19.1",
    "@solid/access-token-verifier": "npm:access-token-verifier-local@^2.1.1" // add this line
  },
  ...
}
```
and in packages/uma/package.json:
```json
{
  ...
  "dependencies": {
    ...
    "@solid/access-token-verifier": "npm:access-token-verifier-local@^2.1.1", // change this line
    ...
  }
  ...
}
```

Then you can follow the instructions in their readme:
1. Install the [eye reasoner](https://github.com/eyereasoner/eye/) and have `eye` available on your path.
2. Ensure that you are using Node.js 20 or higher, e.g. by running `nvm use`. (see [.nvmrc](./.nvmrc))
3. Enable Node.js Corepack with `corepack enable`.
4. Run `yarn install` in the project root (this will automatically call `yarn build`).

## Start Authoriation server
Make sure `uma.local` host is setup corectly acording to `docs/name-resolving.md`.
In the `user-managed-access` repo go to `packages/uma` and start the server.
```bash
cd packages/uma
node bin/main.js -p 4000 -b "http://uma.local:4000/uma"
```

## Start CSS
Make sure `rs.local` host is setup corectly acording to `docs/name-resolving.md`.
If you start the server with `--seedConfig ./config/seed.json` note that the authorization servers in this seed file (`./packages/css/config/seed.json`) need to be updated, so:
```json
"authz": {
  "server": "http://localhost:4000/uma"
}
```
needs to become:
```json
"authz": {
  "server": "http://uma.local:4000/uma"
}
```

In the `user-managed-access` repo go to `packages/css` and start the server.
```bash
cd packages/uma
yarn run community-solid-server -m . -c ./config/default.json ./config/init-pat.json  --seedConfig ./config/seed.json -b "http://rs.local:3000/" -p 3000
```
