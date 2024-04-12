# Trust DID Web - Python

This repository includes Python libraries for working with `did:tdw` (Trust DID Web) DID documents and the underlying log format. Methods are provided for provisioning and updating DID documents as well as a resolving existing `did:tdw` DIDs.

## Prerequisites

This library requires Python 3.9 or newer. Dependencies are listed in requirements.txt and can be installed via:

```sh
pip3 install -r requirements.txt
```

## Testing

The test resolver script may be invoked via the command line:

```sh
python3 -m did_tdw.resolver "did:tdw:domain.example:26nkkrdjqpcfc5zgw6lgsgsgscrg"
```

This script also accepts the path to the local DID history file:

```sh
python3 -m did_tdw.resolver -f did.jsonl "did:tdw:domain.example:26nkkrdjqpcfc5zgw6lgsgsgscrg"
```

## Demo

For testing purposes, a new DID can be minted along with a couple test updates using the included demo script:

```sh
python3 demo.py domain.example
```
