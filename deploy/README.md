# Demo deployment

Runs `signprint-proxy` in front of `signprint-demo` (a small fake shop with a
paginated catalogue, a login form and a scoreboard). Everything under `/api/`
needs a signed session.

```sh
git clone https://github.com/C00LVansh/signprint && cd signprint/deploy
./setup.sh            # builds the image, writes config/keyring.json and .env
docker compose up -d
curl -s localhost:8090/ | head -3
```

The first build takes a while (about 20 minutes on a Raspberry Pi 5). `setup.sh`
keeps existing keys, so it's safe to run again after pulling.

## Behind a Cloudflare tunnel

The proxy speaks plain HTTP on port 8090 inside Docker. Join the tunnel
connector's Docker network and route a hostname to the proxy container:

```sh
TUNNEL_NETWORK=<cloudflared's network> ./setup.sh
TUNNEL_NETWORK=<cloudflared's network> docker compose up -d
```

Then add a public hostname to the tunnel with service `http://signprint-proxy:8090`.

Cloudflare terminates TLS, so the proxy never sees the browser's ClientHello and
there's no JA4. Sessions are still scored on everything else; the network
signals just come back empty. The client IP is taken from `cf-connecting-ip`,
which is only trusted from the Docker ranges listed in
`config/signprint.toml`. To get JA4 back, terminate TLS in the proxy instead
(`[listen] tls` plus a `[tls]` section) and forward TCP to it.

## Calibrating

The canvas check only knows the devices you've taught it. Open the demo on a
few real browsers and run this in the console, with the token from `.env`:

```js
const { SignprintClient } = await import("/static/signprint.js");
await new SignprintClient().calibrate("<SIGNPRINT_CALIBRATE>");
```

A device class is trusted once `min_devices` (2 in the demo config) different
devices have reported the same answer. The answers are stored in the
`signprint-data` volume.
