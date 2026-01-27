# pg-cli

This is the CLI tool for interacting with Postguard.

## Usage
Run these commands in a UNIX shell (Linux, MacOS, WSL, etc). from the root of the repository.
### Encrypting
To encrypt a file and have the recipient (recipient@example.com) prove their email attribute
using IRMA, run the following command:
```shell
cargo run --bin pg-cli --release enc -i '{"recipient@example.com": [{"t": "pbdf.sidn-pbdf.email.email", "v": "recipient@example.com"}]}' <filename>
```

This will prompt the recipient to complete an IRMA session to prove their email attribute via a QR code (make sure you use terminal that renders it well, [Wezterm](https://wezterm.org/index.html) and [Terminus](https://termius.com/index.html) worked.)

If you wish to use an an API key instead use `--api-key` argument.

If you wish to use a different PKG server use the `--pkg` argument.

### Decrypting
To decrypt a file, run the following command:
```shell
cargo run --bin pg-cli --release dec <filename>
```
Make sure the file ends with .enc and ofcourse make sure you use the same PKG server as the one used to encrypt.

You can do so by adding the `--pkg` argument.