# JAM privacy wallet and explorer

Themed for the README's film: the wallet is the **JAM Rebel Wallet** and the explorer the
**Imperial Ledger**, since what the chain shows is what the Empire sees.

Two pages for the privacy service in [abutlabs/jam-privacy-service](https://github.com/abutlabs/jam-privacy-service),
against a local JAM tiny testnet. That repo's `client/wallet.py` serves them; the indexer
relays what they submit and serves what the chain records.

- **The wallet** (`index.html`): public and private balances, and five moves: mint from the
  faucet, pay publicly, shield, send privately, unshield. It proves each transfer in the
  browser with noir_js and bb.js, finds its notes by scanning the chain's sealed notes with its
  own key, and says beside each move what anyone can read of it on chain. `?user=alice` (or
  bob, carol, david, eve, fergie) opens a JAM dev account, whose secret is its public JIP-5
  seed; any other name is a wallet whose secret never leaves this browser.
- **The explorer** (`explorer.html`): everything the chain records, public payments with names
  and amounts beside private transfers with only nullifiers, commitments and sealed notes.
  Search an address; read with a dev account's keys, a wallet in this browser, or a viewing
  key, to see what each can open.

It lives in this fork of Aztec's demo-wallet, in the demo-wallet's colours, but does not
use the demo-wallet's React app or the Aztec PXE: the service's circuit is not Aztec's
kernel circuit yet (jam-privacy-service #18, #19). Plain HTML, CSS and JavaScript; only the
provers are bundled (`npm run build`).

    cd jam-privacy-service && nets/demo.sh up
    open "http://localhost:19710/?user=alice"     # and ?user=bob in a second window
    open http://localhost:19710/explorer.html
