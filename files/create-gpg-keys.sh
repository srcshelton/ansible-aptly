#! /bin/bash

declare pass=''
declare dir='/etc/aptly'
declare email='repo-signing-key@localdomain'

[[ -n "${1:-}" ]] && pass="${1}"
[[ -n "${2:-}" ]] && dir="${2}"
[[ -n "${3:-}" ]] && email="${3}"

[[ -n "${pass:-}" ]] || exit 1
mkdir -p "${dir}" || exit 1

gpg --batch --gen-key <<-EOF
	%echo Generating OpenGPG key for Aptly repo signing
	Key-Type: RSA
	Key-Length: 2048
	Subkey-Type: RSA
	Subkey-Length: 2048
	Name-Real: Aptly
	Name-Comment: Repo signing key
	Name-Email: ${email}
	Expire-Date: 0
	Passphrase: ${pass}
	%pubring ${dir}/pubring.gpg
	%secring ${dir}/secring.gpg
	# Do a commit here, so that we can later print "done" :-)
	%commit
	%echo done
EOF

exit ${?}

# vi: set syntax=sh:
