#! /bin/bash

set -eu

# shellcheck disable=SC2034
debug="${DEBUG:-0}"
# shellcheck disable=SC2034
trace="${TRACE:-1}"

declare NAME="${NAME:-$( basename "${0}" )}"
declare CFGDIR="${APTLY_CONFIG_DIR:-/etc/aptly}"

declare DISTRO=''
declare RELEASE=''
declare MIRROR=''
declare -a PPA=()

declare -a __STDLIB_OWNED_FILES

declare DATE
declare -i DELAY=5

DATE="$( date +'%Y%m%d' )"

# Imported from stdlib.sh [github.com/srcshelton/stdlib.sh]
#
function cleanup() { # {{{
	# N.B.: 'rc' initially contains ${?}, not ${1}
	local -i rc=${?}
	local file

	if [[ -n "${1:-}" ]]; then
		if [[ "${1}" == '0' ]]; then
			rc=${1}; shift
		elif (( ${1} )); then
			rc=${1}; shift
		fi
	fi

	# Remove any STDLIB-generated temporary files and exit.

	for file in "${__STDLIB_OWNED_FILES[@]:-}"; do
		if [[ -n "${file:-}" && -e "${file}" ]]; then

			# TODO: It would be nice to run stdlib.sh functions as
			#       a dedicated unprivileged user by default, so
			#       that cleanup couldn't be maliciously or even
			#       accidentally used to cause system damage if
			#       run by UID 0...

			# XXX: Use std::readlink for cross-platform support...
			if [[ "$( readlink -e "${file}" )" == '/' ]]; then
				die "Attempt made to cleanup/remove '/' - serious bug or malicious code suspected"
			fi

			if rmdir "${file}" >/dev/null 2>&1; then
				(( debug & 2 )) && echo >&2 -e "${FUNCNAME[0]##*_} succeeded removing empty directory '${file}'"
			elif rm -f "${file}" >/dev/null 2>&1; then
				(( debug & 2 )) && echo >&2 -e "${FUNCNAME[0]##*_} succeeded removing file '${file}'"
			elif rm -rf "${file}" >/dev/null 2>&1; then
				(( debug & 2 )) && echo >&2 -e "${FUNCNAME[0]##*_} succeeded removing non-empty file or directory '${file}'"
			else
				echo >&2 -e "${FUNCNAME[0]##*_} unable to remove filesystem object '${file}': ${?}"

				# We'd expect this to fail again, but tell us
				# what happened.  This is arguably less correct
				# than capturing the output in the first place,
				# but the distinction is likely marginal...
				echo >&2 -e "$( rm -rv "${file}" 2>&1 )"
				(( rc )) || (( rc++ ))
			fi
		else
			(( debug & 2 )) && [[ -n "${file:-}" ]] && echo >&2 -e "${FUNCNAME[0]##*_} unable to remove missing object '${file}'"
		fi
	done
	unset file

	trap - EXIT INT QUIT TERM

	# 'rc' is numeric, and therefore not subject to word-splitting
	# shellcheck disable=SC2086
	exit ${rc}
} # cleanup # }}}

function die() { # {{{
	echo >&2 -e "FATAL: ${*:-Unknown error}"
	cleanup 1

	# Unreachable
	exit 255
} # die # }}}

# Imported from stdlib.sh [github.com/srcshelton/stdlib.sh]
#
function garbagecollect() { # {{{
	local file="" rc=0

	# Add an additional file to the list of files to be removed when
	# cleanup is invoked.

	#std_ERRNO=0 # instead use 'std_ERRNO=$( errsymbol ENOERROR )'
	for file in "${@:-}"; do
		if [[ -e "${file}" ]]; then
			__STDLIB_OWNED_FILES+=( "${file}" )
			rc=${rc:-0}
		else
			#std_ERRNO=$( errsymbol ENOTFOUND )
			rc=1
		fi
	done

	if (( debug & 2 )); then
		if ! [[ -n "${__STDLIB_OWNED_FILES[*]:-}" ]]; then
			echo >&2 -e "${FUNCNAME[0]##*_} is not tracking any files after being invoked with filenames '${*:-}'"
		else
			echo >&2 -e "${FUNCNAME[0]##*_} now tracking ${#__STDLIB_OWNED_FILES[@]} files:"
			for file in "${__STDLIB_OWNED_FILES[@]}"; do
				echo >&2 -e "\t${file}"
			done
		fi
	fi

	# std_ERRNO set above
	return ${rc:-1}
} # garbagecollect # }}}

function lock() { # {{{
	local lockfile="${1:-/var/lock/${NAME}.lock}"

	mkdir -p "$( dirname "${lockfile}" )" 2>/dev/null || exit 1

	if ( set -o noclobber ; echo "${$}" >"${lockfile}" ) 2>/dev/null; then
		garbagecollect "${lockfile}"
		return ${?}
	else
		return 1
	fi

	# Unreachable
	return 128
} # lock # }}}


# Parameter-injection and error-checking wrapper
#
function run() { # {{{
	local cmd="${1:-}" ; shift
	local -a args=( "${@:-}" )
	local -i rc=0 retry=1
	local delay="1.0"

	[[ -n "${cmd:-}" ]] || return 126
	[[ -e "${cmd}" ]] || type -pf "${cmd}" >/dev/null 2>&1 || return 127

	# Inject updated configuration directory, if relevant...
	if [[ "$( basename "${cmd}" )" == "aptly" && -n "${CFGDIR:-}" ]]; then
		args=( "-config=${CFGDIR}/aptly.conf" "${args[@]:-}" )
	fi

	# Running:
	#   aptly -config /etc/aptly/aptly.conf (mirror|snapshot|publish) list -raw=true
	# ... often appears to fail with return code 141 (but never when run
	# interactively...) :(
	#
	if [[ "${args[*]:-}" =~ \ list\  ]]; then
		retry=5
	fi
	while (( retry )); do
		(( retry-- ))

		(( debug )) && echo >&2 "DEBUG: About to run command '${cmd}${args[*]:+ ${args[*]}}'"

		# We need to 'eval' this to correctly pass quoted arguments...
		eval "${cmd}" "${args[@]:-}" 2>&1
		rc=${?}

		if (( retry )); then
			if (( 141 == rc )); then
				sleep "${delay}"
				(( debug )) && echo >&2 "DEBUG: Retrying failed command"
			else
				retry=0
			fi
		fi
	done

	(( rc )) && echo >&2 "Command '${cmd}${args[*]:+ ${args[*]}}' failed: ${rc}"

	return ${rc}
} # run # }}}


# aptly repo management functions
#
function createorupdatemirrors() { # {{{
	local x y list
	local -i rc=0
	#extern DISTRO RELEASE MIRROR PPA

	list="$( run aptly mirror list -raw=true )"
	(( debug )) && echo -e >&2 "DEBUG: aptly mirror list:\n${list}"

	# Iterate through {main,universer,multiverse}(y) for each of the
	# current Ubuntu/Debian release, the security component, and the
	# updates component (x)... noting that we're not currently retrieving
	# the 'restricted' component.
	#
	for x in "${DISTRO}" "${DISTRO}-security" "${DISTRO}-updates"; do
		for y in main universe multiverse; do
			if ! grep -Fq "${x}-${y}-${RELEASE}" <<<"${list:-}" ; then
				run aptly mirror create "${x}-${y}-${RELEASE}" "${MIRROR}" "${x}" "${y}"
				rc+=${?}
			fi

			# Mirrors must be updated after they are first created...
			run aptly mirror update "${x}-${y}-${RELEASE}"
			rc+=${?}
		done
	done
	for x in "${PPA[@]:-}"; do
		if [[ -n "${x:-}" ]]; then
			if grep -Fq "${DISTRO}-ppa-${x}" <<<"${list:-}" ; then
				run aptly mirror update "${DISTRO}-ppa-${x}"
				rc+=${?}
			else
				# We don't have all of the details to create PPA
				# mirrors, so we leave this to ansible, or as a
				# manual task.
				#
				# Potentially, the PPA list could be converted to an
				# associative array of configuration data...
				#
				echo >&2 "No aptly mirror exists for PPA '${DISTRO}-ppa-${x}'"
				rc+=1
			fi
		fi
	done

	return ${rc}
} # createorupdatemirrors # }}}

function updatesnapshots() { # {{{
	local -i doublefetch=${1:-0}
	local -i rc=0 changed=0
	local x y list
	#extern DISTRO RELEASE PPA DATE

	list="$( run aptly snapshot list -raw=true )"
	(( debug )) && echo -e >&2 "DEBUG: aptly snapshot list:\n${list}"

	# "${DISTRO}" mirror should only change on release update,
	# e.g. 14.04.3 -> 14.04.4
	#
	# As above, we're consistently using (y) for sub-components and (x),
	# where relevant, for components...
	#
	for y in main universe multiverse; do
		grep -Fq "${DISTRO}-${y}-${RELEASE}-current" <<<"${list:-}" && run aptly snapshot drop -force "${DISTRO}-${y}-${RELEASE}-current"

		if ! grep -Fq "${DISTRO}-${y}-${RELEASE}" <<<"${list:-}" ; then
			run aptly snapshot create "${DISTRO}-${y}-${RELEASE}" from mirror "${DISTRO}-${y}-${RELEASE}"
			rc+=${?}
		else
			run aptly snapshot create "${DISTRO}-${y}-${RELEASE}-current" from mirror "${DISTRO}-${y}-${RELEASE}"
			if (( $( run aptly snapshot diff "${DISTRO}-${y}-${RELEASE}" "${DISTRO}-${y}-${RELEASE}-current" 2>/dev/null | wc -l ) > 1 )); then
				echo >&2 "Mirror '${DISTRO}-${y}-${RELEASE}' has changed, indicating a release update"
				echo >&2 "Please resolve this situation manually (by bumping the release version to match"
				echo >&2 "and updating the relevant snapshots).  It would be nice to do this"
				echo >&2 "automatically, but the repo doesn't actually expose the release version :("
				rc=1
			fi
			run aptly snapshot drop -force "${DISTRO}-${y}-${RELEASE}-current"

			(( rc )) && return 1
		fi
	done

	for x in "${DISTRO}-security" "${DISTRO}-updates"; do
		for y in main universe multiverse; do
			grep -Fq "${x}-${y}-${DATE}-check" <<<"${list:-}" && run aptly snapshot drop -force "${x}-${y}-${DATE}-check"
			grep -Fq "${x}-${y}-${DATE}" <<<"${list:-}" && run aptly snapshot drop -force "${x}-${y}-${DATE}"
			run aptly snapshot create "${x}-${y}-${DATE}" from mirror "${x}-${y}-${RELEASE}"
			rc+=${?}

			if (( doublefetch )); then
				changed=1
				while (( changed )); do
					run aptly mirror update "${x}-${y}-${RELEASE}"
					run aptly snapshot create "${x}-${y}-${DATE}-check" from mirror "${x}-${y}-${RELEASE}"
					if (( $( run aptly snapshot diff "${x}-${y}-${DATE}" "${x}-${y}-${DATE}-check" 2>/dev/null | wc -l ) > 1 )); then
						echo >&2 "Warning: Mirror '${x}-${y}-${RELEASE}' changed during snapshot process - regenerating..."
						sleep ${DELAY:-5}

						run aptly snapshot drop -force "${x}-${y}-${DATE}"
						run aptly snapshot rename "${x}-${y}-${DATE}-check" "${x}-${y}-${DATE}"
					else
						run aptly snapshot drop -force "${x}-${y}-${DATE}-check"
						changed=0
					fi
				done
			fi
		done
	done
	for x in "${PPA[@]:-}"; do
		if [[ -n "${x:-}" ]]; then
			grep -Fq "${DISTRO}-ppa-${x}-${DATE}-check" <<<"${list:-}" && run aptly snapshot drop -force "${DISTRO}-ppa-${x}-${DATE}-check"
			grep -Fq "${DISTRO}-ppa-${x}-${DATE}" <<<"${list:-}" && run aptly snapshot drop -force "${DISTRO}-ppa-${x}-${DATE}"
			run aptly snapshot create "${DISTRO}-ppa-${x}-${DATE}" from mirror "${DISTRO}-ppa-${x}"
			rc+=${?}

			if (( doublefetch )); then
				changed=1
				while (( changed )); do
					run aptly mirror update "${DISTRO}-ppa-${x}"
					run aptly snapshot create "${DISTRO}-ppa-${x}-${DATE}-check" from mirror "${DISTRO}-ppa-${x}"
					if (( $( run aptly snapshot diff "${DISTRO}-ppa-${x}-${DATE}" "${DISTRO}-ppa-${x}-${DATE}-check" 2>/dev/null | wc -l ) > 1 )); then
						echo >&2 "Warning: Mirror '${DISTRO}-ppa-${x}' changed during snapshot process - regenerating..."
						sleep ${DELAY:-5}

						run aptly snapshot drop -force "${DISTRO}-ppa-${x}-${DATE}"
						run aptly snapshot rename "${DISTRO}-ppa-${x}-${DATE}-check" "${DISTRO}-ppa-${x}-${DATE}"
					else
						run aptly snapshot drop -force "${DISTRO}-ppa-${x}-${DATE}-check"
						changed=0
					fi
				done
			fi
		fi
	done

	for y in main universe multiverse; do
		grep -Fq "${DISTRO}-all-${y}-${DATE}" <<<"${list:-}" && run aptly snapshot drop -force "${DISTRO}-all-${y}-${DATE}"
		run aptly snapshot merge -latest "${DISTRO}-all-${y}-${DATE}" "${DISTRO}-${y}-${RELEASE}" "${DISTRO}-updates-${y}-${DATE}" "${DISTRO}-security-${y}-${DATE}"
		rc+=${?}
	done

	if (( ${#PPA[@]:-} )); then
		grep -Fq "${DISTRO}-all-ppa-${DATE}" <<<"${list:-}" && run aptly snapshot drop -force "${DISTRO}-all-ppa-${DATE}"
		# shellcheck disable=SC2046
		run aptly snapshot merge -latest "${DISTRO}-all-ppa-${DATE}" $( for x in "${PPA[@]}"; do echo "${DISTRO}-ppa-${x}-${DATE}"; done )
		rc+=${?}

		grep -Fq "${DISTRO}-all-all-${DATE}" <<<"${list:-}" && run aptly snapshot drop -force "${DISTRO}-all-all-${DATE}"
		run aptly snapshot merge -latest "${DISTRO}-all-all-${DATE}" "${DISTRO}-all-main-${DATE}" "${DISTRO}-all-universe-${DATE}" "${DISTRO}-all-multiverse-${DATE}" "${DISTRO}-all-ppa-${DATE}"
		rc+=${?}
	else
		grep -Fq "${DISTRO}-all-all-${DATE}" <<<"${list:-}" && run aptly snapshot drop -force "${DISTRO}-all-all-${DATE}"
		run aptly snapshot merge -latest "${DISTRO}-all-all-${DATE}" "${DISTRO}-all-main-${DATE}" "${DISTRO}-all-universe-${DATE}" "${DISTRO}-all-multiverse-${DATE}"
		rc+=${?}
	fi

	return ${rc}
} # updatesnapshots # }}}

function publishrepo() { # {{{
	local stablesnapshot="${1:-}" ; shift
	local testingsnapshot="${1:-}" ; shift
	local repo snapshot slist plist root
	local -i rc=0
	#extern DISTRO DATE APTLY_OPTS

	if [[ -z "${APTLY_OPTS:-}" && -z "${*:-}" ]]; then
		echo >&2 "No aptly GPG options provided - cannot publish" \
		         "updated repo"
		return 1
	fi

	slist="$( run aptly snapshot list -raw=true )"
	plist="$( run aptly publish list -raw=true )"
	(( debug )) && echo -e >&2 "DEBUG: aptly snapshot list:\n${slist}"
	(( debug )) && echo -e >&2 "DEBUG: aptly publish list:\n${plist}"

	# String-parsing JSON data is *bad*!
	# (... but we're very reliant on the consistency of aptly's output in
	# any case, and this saves relying on json_pp or similar)
	root="$( run aptly config show | grep -F 'rootDir' | cut -d'"' -f 4 )"
	(( debug )) && echo >&2 "DEBUG: aptly rootDir is '${root}'"

	# Publishing the latest update requires interactive input of the repo
	# GPG key, or specific configuration in the form of:
	#   -passphrase 'gpg_passphrase'
	#   -keyring '/etc/aptly/pubring.gpg'
	#   -secret-keyring '/etc/aptly/secring.gpg'
	#   -gpg-key 'email_address_of_key'
	# ... which are aptly options (e.g. the single hyphen is intentional)
	# that are passed through to aptly directly.
	#
	for repo in "stable" "testing"; do
		snapshot="$( eval echo "\${${repo:-}snapshot:-}" )"
		if [[ -n "${snapshot:-}" && "${snapshot}" != "none" ]]; then
			if ! grep -Fq "${DISTRO}-all-all-${snapshot}" <<<"${slist:-}" ; then
				echo >&2 "WARN: Could not locate combined snapshot for date '${snapshot}' - not creating/updating '${DISTRO}-${repo}' repo"
				(( rc++ ))
			else
				if grep -Fq "${DISTRO}-${repo}" <<<"${plist:-}" && [[ -d "${root:-}"/public/"${repo}" ]]; then
					# aptly publish switch <distribution name> [prefix] <new snapshot>
					# shellcheck disable=SC2086
					run aptly publish switch -batch ${APTLY_OPTS:-} "${@}" "${DISTRO}" "${repo}" "${DISTRO}-all-all-${snapshot}"
					rc+=${?}
				else
					# aptly publish [-distribution="<distribution name>"] <snapshot name> [prefix]
					# shellcheck disable=SC2086
					run aptly publish snapshot -batch ${APTLY_OPTS:-} "${@}" -distribution="${DISTRO}" "${DISTRO}-all-all-${snapshot}" "${repo}"
					rc+=${?}
				fi
			fi
		fi
	done

	if ! grep -Fq "${DISTRO}-all-all-${DATE}" <<<"${slist:-}" ; then
		echo >&2 "ERROR: Could not locate combined snapshot for date '${DATE}' - not creating/updating 'latest/${DISTRO}' document root"
		(( rc++ ))

	elif grep -Fq "${DISTRO}" <<<"${plist:-}" && [[ -d "${root:-}"/public/latest ]]; then
		# aptly publish switch <distribution name> [prefix] <new snapshot>
		# shellcheck disable=SC2086
		run aptly publish switch -batch ${APTLY_OPTS:-} "${@}" "${DISTRO}" 'latest' "${DISTRO}-all-all-${DATE}"
		rc+=${?}
	else
		# aptly publish [-distribution="<distribution name>"] <snapshot name> [prefix]
		# shellcheck disable=SC2086
		run aptly publish snapshot -batch ${APTLY_OPTS:-} "${@}" -distribution="${DISTRO}" "${DISTRO}-all-all-${DATE}" 'latest'
		rc+=${?}
	fi

	return ${rc}
} # publishrepo # }}}


function main() { # {{{
	local -i doublefetch=0 rc=0
	local stablesnapshot='none' testingsnapshot='none' email='' domain=''
	local x='' fqdn=''

	local lockfile="/var/lock/${NAME}.lock"
	[[ -w /var/lock ]] || lockfile="${TMPDIR:-/tmp}/${NAME}.lock"

	local usage
	usage="Usage: ${NAME} [--config=<directory>] [--stable=<iso_date>] [--testing=<iso_date>] [--double-fetch] [--notify=<email>] -passphrase <key_passphrase> -keyring <path_to_keyring> -secret-keyring <path_to_secret_keyring> [-gpg-key <key_id>]"

	if \
		[[ "${*:-}" =~ \ --config=[^\ ]+\  ]] ||
		[[ "${*:-}" =~ \ --double-?fetch(=[^ ]+)?\  ]] ||
		[[ "${*:-}" =~ \ --notify=[^\ ]+\  ]] ||
		[[ "${*:-}" =~ \ --stable=[^\ ]+\  ]] ||
		[[ "${*:-}" =~ \ --testing=[^\ ]+\  ]]
	then
		local -a args
		while [[ -n "${1:-}" ]]; do
			if [[ "${1:0:9}" == '--config=' ]]; then
				CFGDIR="${1:9}"
			elif [[ "${1:0:8}" == '--double' ]]; then
				# We'll assume that if this is specified, it's
				# wanted...
				#
				doublefetch=1
			elif [[ "${1:0:9}" == '--notify=' ]]; then
				email="${1:9}"
			elif [[ "${1:0:9}" == '--stable=' ]]; then
				stablesnapshot="${1:9}"
			elif [[ "${1:0:10}" == '--testing=' ]]; then
				testingsnapshot="${1:10}"
			else
				args+=( "${1}" )
			fi
			shift
		done
		set -- "${args[@]:-}"
	fi

	if grep -Eq ' -(h|-help) ' <<<" ${*:-} "; then
		echo >&2 "${usage}"
		exit 0
	fi

	if ! [[ -s "${CFGDIR}"/aptly-update.conf ]]; then
		echo >&2 "FATAL: Cannot read configuration file '${CFGDIR}/aptly-update.conf'"
		exit 1
	fi

	# shellcheck disable=SC1090,SC1091
	if ! source "${CFGDIR}"/aptly-update.conf; then
		echo >&2 "FATAL: Cannot parse configuration file '${CFGDIR}/aptly-update.conf'"
		exit 1
	fi

	if [[ -z "${DISTRO:-}" || -z "${RELEASE:-}" || -z "${MIRROR:-}" ]]; then
		echo >&2 "FATAL: Could not read full configuration from file '${CFGDIR}/aptly-update.conf'"
		exit 1
	fi

	if [[ -z "${APTLY_OPTS:-}" && -z "${*:-}" ]]; then
		echo >&2 "${usage}"
		exit 1
	fi

	[[ "${stablesnapshot}" == 'none' ]] && stablesnapshot="${STABLE:-none}"
	[[ "${testingsnapshot}" == 'none' ]] && testingsnapshot="${TESTING:-none}"

	echo >&2 'Establishing lock ...'

	if [[ -s "${lockfile}" ]]; then
		local -i blockingpid
		blockingpid="$( <"${lockfile}" )"
		if (( blockingpid > 1 )); then
			# shellcheck disable=SC2086
			if kill -0 ${blockingpid} >/dev/null 2>&1; then
				local processname
				processname="$( pgrep -lF "${lockfile}" | cut -d' ' -f 2- )"
				die "Lock file '${lockfile}' (belonging to process '${processname}', PID '${blockingpid}') exists - aborting"
			else
				echo >&2 -e "Lock file '${lockfile}' (belonging to obsolete PID '${blockingpid}') exists - removing stale lock"
				rm -f "${lockfile}" || die "Lock file removal failed: ${?}"
			fi
		else
			echo >&2 -e "Lock file '${lockfile}' exists with invalid content '$( head -n 1 "${lockfile}" )' - removing broken lock"
			rm -f "${lockfile}" || die "Lock file removal failed: ${?}"
		fi
	fi

	if [[ -e "${lockfile}" ]]; then
		echo >&2 -e "Lock file '${lockfile}' exists, but is empty - removing broken lock"
		rm -f "${lockfile}" || die "Lock file removal failed: ${?}"
	fi

	lock "${lockfile}" || die "Creating lock file '${lockfile}' failed - aborting"
	sleep 0.1

	local lockpid
	lockpid="$( <"${lockfile}" )"
	if [[ -e "${lockfile}" && -n "${lockpid:-}" && "${lockpid}" == "${$}" ]]; then
		:
	elif [[ -e "${lockfile}" && -n "${lockpid:-}" ]]; then
		die "Lock file '${lockfile}' is for process ${lockpid}, not our PID ${$} - aborting"
	elif [[ -e "${lockfile}" ]]; then
		die "Lock file '${lockfile}' exists but is empty - aborting"
	else
		die "Lock file '${lockfile}' does not exist - aborting"
	fi
	unset lockpid

	# We have a lock...

	if ! createorupdatemirrors; then
		echo >&2 "WARN: Mirror update returned ${?} errors"
		rc+=1
	fi
	if ! updatesnapshots ${doublefetch}; then
		echo >&2 "WARN: Snapshot update returned ${?} errors"
		rc+=1
	fi
	if ! publishrepo "${stablesnapshot}" "${testingsnapshot}" "${@:-}"; then
		echo >&2 "WARN: Repo update returned ${?} errors"
		rc+=1
	fi

	if [[ -n "${email:-}" ]]; then
		if type -pf mailx >/dev/null 2>&1; then
			# `hostname -f` often gives only the hostname
			# of the current node, whereas `hostname -A`
			# gives the full domain name... but in several
			# forms :(
			if [[ "$( hostname -f )" =~ \. ]]; then
				domain="$( hostname -f | cut -d'.' -f 2- )"
			else
				for x in $( hostname -A ); do
					if [[ "${x:-}" =~ \.(co(m|\.uk)|net|org)$ ]]; then
						domain="$( cut -d'.' -f 2- <<<"${x}" )"
						break
					fi
				done
			fi
			fqdn="$( hostname ).${domain:-local}"

			mailx -r "aptly@${fqdn:-localhost.localdomain}" -s "aptly refresh completed on host ${fqdn:-localhost.localdomain}" <<-EOF

				aptly on host ${fqdn:-localhost.localdomain} has $( (( rc )) && echo 'completed but failed :(' || echo 'finished successfully!' )

				aptly was invoked with the following options:
				$( [[ -n "${stablesnapshot:-}" ]]	&& echo "	* stablesnapshot=${stablesnapshot}" )
				$( [[ -n "${testingsnapshot:-}" ]]	&& echo "	* testingsnapshot=${testingsnapshot}" )
				$( [[ -n "${doublefetch:-}" ]]		&& echo "	* doublefetch=${doublefetch}" )
				$( [[ -n "${email:-}" ]]		&& echo "	* email=${email}" )
				$(
					if ! (( rc )); then
						echo "If this is a fresh environment, it is now safe to start kicking other VMs"
					fi
				)
			EOF
		fi
	fi

	return ${rc}
} # main # }}}

export LC_ALL='C'
set -o pipefail

trap cleanup EXIT INT QUIT TERM

main "${@:-}"

exit ${?}

# vi: set filetype=sh syntax=sh commentstring=#%s foldmarker=\ {{{,\ }}} foldmethod=marker colorcolumn=80 nowrap:
