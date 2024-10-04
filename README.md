# Trust DID Web - Python

This repository includes Python libraries for working with `did:tdw` (Trust DID Web) DID documents and the underlying log format. Methods are provided for provisioning and updating DID documents as well as a resolving existing `did:tdw` DIDs. Currently, version 0.4 of [the specification](https://bcgov.github.io/trustdidweb/) is implemented.

## Prerequisites

This library requires Python 3.10 or later. Dependencies are listed in pyproject.toml and can be installed via:

```sh
poetry install
```

## Usage

A new `did:tdw` DID can be minted using the provision command. This will create a new Askar keystore for handling the signing key.

```sh
python3 -m did_tdw.provision --auto "domain.example"
```

This will output a new directory named after the new DID, containing `did.jsonl` (the DID log) and `did.json` (the current state of the document).

To automatically update the DID, edit `did.json` and execute the update command (use the identifier output from the provision command):

```sh
python3 -m did_tdw.update --auto "did:tdw:QmRwq46VkGuCEx4dyYxxexmig7Fwbqbm9AB73iKUAHjMZH:domain.example"
```

## DID Resolution

The resolver script may be invoked via the command line, and supports dereferencing of fragments and paths:

```sh
python3 -m did_tdw.resolver "did:tdw:QmRwq46VkGuCEx4dyYxxexmig7Fwbqbm9AB73iKUAHjMZH:domain.example"
```

```sh
python3 -m did_tdw.resolver "did:tdw:QmRwq46VkGuCEx4dyYxxexmig7Fwbqbm9AB73iKUAHjMZH:domain.example#key-1"
```

```sh
python3 -m did_tdw.resolver "did:tdw:QmRwq46VkGuCEx4dyYxxexmig7Fwbqbm9AB73iKUAHjMZH:domain.example/whois.vc"
```

For testing, this script also accepts the path to the local DID history file:

```sh
python3 -m did_tdw.resolver -f did.jsonl "did:tdw:QmRwq46VkGuCEx4dyYxxexmig7Fwbqbm9AB73iKUAHjMZH:domain.example"
```

## Demo

For demo purposes, a new DID can be minted along with a series of test updates applied using the included demo script:

```sh
python3 demo.py domain.example
```

## Contributing

Pull requests are welcome! Please read our [contributions guide](./CONTRIBUTING.md) and submit your PRs. We enforce [developer certificate of origin](https://developercertificate.org/) (DCO) commit signing — [guidance](https://github.com/apps/dco) on this is available. We also welcome issues submitted about problems you encounter in using Trust DID Web - Python.

## License

[Apache License Version 2.0](LICENSE)
