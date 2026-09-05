# attacker-proxy/certs

The TLS cert pair that terminates `https://kaaval.demo` on the attacker/host
laptop (Laptop B). These are generated **per machine** with mkcert and are
**not committed** — see `.gitignore`.

Generate on Laptop B (KAAVAL_Demo_LAN_Reengineering.md §3.2):

```bash
mkcert -install          # trusts mkcert's local CA on Laptop B
mkcert kaaval.demo       # produces kaaval.demo.pem + kaaval.demo-key.pem
```

Then move both files here:

```
attacker-proxy/certs/kaaval.demo.pem
attacker-proxy/certs/kaaval.demo-key.pem
```

Trust the same CA on Laptop A (§3.3): copy `rootCA.pem` (found via
`mkcert -CAROOT` on Laptop B) to Laptop A and import it into the OS trust
store, then confirm `https://kaaval.demo` shows a clean padlock with no
warning before demo day.
