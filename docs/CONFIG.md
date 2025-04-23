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

The tool looks for configuration files in the following locations, in order of precedence:

1. Path specified with `-config` flag
2. `.jwtdebug.json` in the current directory
3. `.jwtdebug.json` in the user's home directory
4. `.config/jwtdebug.json` in the user's home directory

## Creating a Configuration File

You can create a configuration file in two ways:

### 1. Using the `-save-config` Flag

Run the tool with your preferred options and add the `-save-config` flag:

```bash
jwtdebug -format yaml -color=false -header -save-config
```

This will save your current settings to a configuration file in your home directory.

### 2. Manually Creating the File

You can also create the configuration file manually by creating a JSON file with the structure shown above and saving it to one of the supported locations.

## Configuration Priority

Settings are applied in the following order of precedence (highest to lowest):

1. Command-line flags explicitly set by the user
2. Settings from the configuration file
3. Default values

This means that command-line flags will always override settings from the configuration file, allowing you to temporarily override your saved preferences.

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `defaultFormat` | Default output format (pretty, json, yaml, raw) | pretty |
| `colorEnabled` | Enable colored output | true |
| `defaultKeyFile` | Default key file for signature verification | "" |
| `showHeader` | Show token header by default | false |
| `showClaims` | Show token claims by default | true |
| `showSignature` | Show token signature by default | false |
| `showExpiration` | Check token expiration by default | false |
| `decodeSignature` | Decode base64 signature by default | false |
| `ignoreExpiration` | Ignore token expiration when verifying | false |
