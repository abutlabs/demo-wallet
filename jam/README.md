# JAM privacy wallet

A page for the privacy service in [abutlabs/jam-privacy-service](https://github.com/abutlabs/jam-privacy-service):
public and private balances, and three moves (shield, send, unshield) against a local JAM
tiny testnet. Served by that repo's `client/wallet.py`, which proves each transfer with
Noir and Barretenberg on the machine and submits it through the indexer.

It lives in this fork of Aztec's demo-wallet, in the demo-wallet's colours, but does not
use the demo-wallet's React app or the Aztec PXE: the service's circuit is not Aztec's
kernel circuit yet (jam-privacy-service #18, #19). Plain HTML, CSS and JavaScript, no build.

    cd jam-privacy-service && nets/demo.sh up && nets/demo.sh wallet
    open http://localhost:19710/?user=A      # and ?user=B in a second browser
