# JWT Debug Tool Configuration

JWT Debug Tool supports configuration files to persist your preferred settings across multiple runs.

## Configuration File

The configuration file is a JSON file with the following structure:

```json
{
  "defaultFormat": "json",
  "colorEnabled": true,
  "defaultKeyFile": "/path/to/key.pem",
  "showHeader": false,
  "showClaims": true,
  "showSignature": false,
  "showExpiration": false,
  "decodeSignature": false,
  "ignoreExpiration": false
}
```

## Configuration File Locations

The tool loads configuration from exactly one file, chosen in this order:

1. Path specified with `-config` flag.
2. `~/.jwtdebug.json` (user home directory).
3. `~/.config/jwtdebug.json`.
4. `~/.config/jwtdebug/config.json`.

For safety, the current working directory is not considered. This avoids accidentally
loading untrusted configuration when running the tool in arbitrary folders.

## Creating a Configuration File

You can create a configuration file in two ways:

### 1. Using the `-save-config` Flag

Run the tool with your preferred options and add the `-save-config` flag:

```bash
jwtdebug -format json -color=false -header -save-config
```

This saves your current settings to `~/.jwtdebug.json` in your home directory.
The `-config` flag controls loading, not where `-save-config` writes.

### 2. Manually Creating the File

You can also create the configuration file manually by creating a JSON file with the structure shown above and saving it to one of the supported locations.

## Configuration Priority

Settings are applied in the following order of precedence (highest to lowest):

1. Command-line flags that were explicitly set by the user.
2. Settings loaded from the configuration file (picked using the search order above).
3. Built‑in defaults.

Only flags you explicitly set on the command line override config values; otherwise
the config file fills in those options.

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `defaultFormat` | Default output format (pretty, json, or raw) | pretty |
| `colorEnabled` | Enable colored output | true |
| `defaultKeyFile` | Default key file for signature verification | "" |
| `showHeader` | Show token header by default | false |
| `showClaims` | Show token claims by default | true |
| `showSignature` | Show token signature by default | false |
| `showExpiration` | Check token expiration by default | false |
| `decodeSignature` | Decode base64 signature by default | false |
| `ignoreExpiration` | Ignore token expiration when verifying | false |
