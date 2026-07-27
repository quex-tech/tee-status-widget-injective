# On-chain TEE status checker

A small script that fetches TEE status - through REST or websocket RPC - to be shown in web dashboards (since there is not much use for it beyond that).

See index.html for usage example. Just take the `attestation.js` file to use.

To enable measurements check, populate `expected-measurements.json` file to be deposited alongside with the script; remember to update it when the chain updates, naturally.

tested with commit injectived-core `8e955ee427b1990277dec88810d9beb735b164b9`
