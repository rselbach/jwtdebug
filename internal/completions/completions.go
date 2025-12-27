package completions

import (
	"fmt"
)

// Bash returns the bash completion script
func Bash() string {
	return `# jwtdebug bash completion
_jwtdebug() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Main options
    opts="--all -a --header -H --claims -c --signature -s --expiration -e
          --decode-signature --raw-claims --verify -V --key-file -k
          --ignore-expiration --output -o --color --no-color
          --config --save-config --help -h --version --quiet -q --verbose -v
          --strict"

    # Handle option arguments
    case "${prev}" in
        --key-file|-k|--config)
            # Complete with files
            COMPREPLY=( $(compgen -f -- "${cur}") )
            return 0
            ;;
        --output|-o)
            # Complete with format options
            COMPREPLY=( $(compgen -W "pretty json raw" -- "${cur}") )
            return 0
            ;;
    esac

    # Complete options
    if [[ "${cur}" == -* ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
        return 0
    fi

    # Default to file completion for tokens
    COMPREPLY=( $(compgen -f -- "${cur}") )
}

complete -F _jwtdebug jwtdebug
`
}

// Zsh returns the zsh completion script
func Zsh() string {
	return `#compdef jwtdebug

_jwtdebug() {
    local -a opts
    opts=(
        '(-a --all)'{-a,--all}'[Show all token parts and info]'
        '(-H --header)'{-H,--header}'[Show token header]'
        '(-c --claims)'{-c,--claims}'[Show token claims/payload]'
        '(-s --signature)'{-s,--signature}'[Show token signature]'
        '(-e --expiration)'{-e,--expiration}'[Check token expiration status]'
        '--decode-signature[Decode signature from base64 to hex]'
        '--raw-claims[Output only raw claims JSON]'
        '(-V --verify)'{-V,--verify}'[Verify token signature]'
        '(-k --key-file)'{-k,--key-file}'[Key file for signature verification]:file:_files'
        '--ignore-expiration[Ignore token expiration when verifying]'
        '(-o --output)'{-o,--output}'[Output format]:format:(pretty json raw)'
        '--color[Colorize output]'
        '--no-color[Disable colored output]'
        '--config[Path to config file]:file:_files'
        '--save-config[Save current settings to config file]'
        '(-h --help)'{-h,--help}'[Show help message]'
        '--version[Show version information]'
        '(-q --quiet)'{-q,--quiet}'[Suppress informational notices]'
        '(-v --verbose)'{-v,--verbose}'[Enable verbose output]'
        '--strict[Disable smart token extraction]'
        '*:token:_files'
    )

    _arguments -s $opts
}

_jwtdebug "$@"
`
}

// Fish returns the fish completion script
func Fish() string {
	return `# jwtdebug fish completion

# Disable file completion by default
complete -c jwtdebug -f

# Display options
complete -c jwtdebug -s a -l all -d 'Show all token parts and info'
complete -c jwtdebug -s H -l header -d 'Show token header'
complete -c jwtdebug -s c -l claims -d 'Show token claims/payload'
complete -c jwtdebug -s s -l signature -d 'Show token signature'
complete -c jwtdebug -s e -l expiration -d 'Check token expiration status'
complete -c jwtdebug -l decode-signature -d 'Decode signature from base64 to hex'
complete -c jwtdebug -l raw-claims -d 'Output only raw claims JSON'

# Verification options
complete -c jwtdebug -s V -l verify -d 'Verify token signature'
complete -c jwtdebug -s k -l key-file -r -F -d 'Key file for signature verification'
complete -c jwtdebug -l ignore-expiration -d 'Ignore token expiration when verifying'

# Output options
complete -c jwtdebug -s o -l output -r -a 'pretty json raw' -d 'Output format'
complete -c jwtdebug -l color -d 'Colorize output'
complete -c jwtdebug -l no-color -d 'Disable colored output'

# Config options
complete -c jwtdebug -l config -r -F -d 'Path to config file'
complete -c jwtdebug -l save-config -d 'Save current settings to config file'

# Other options
complete -c jwtdebug -s h -l help -d 'Show help message'
complete -c jwtdebug -l version -d 'Show version information'
complete -c jwtdebug -s q -l quiet -d 'Suppress informational notices'
complete -c jwtdebug -s v -l verbose -d 'Enable verbose output'
complete -c jwtdebug -l strict -d 'Disable smart token extraction'
`
}

// PrintBash prints the bash completion script to stdout
func PrintBash() {
	fmt.Print(Bash())
}

// PrintZsh prints the zsh completion script to stdout
func PrintZsh() {
	fmt.Print(Zsh())
}

// PrintFish prints the fish completion script to stdout
func PrintFish() {
	fmt.Print(Fish())
}
