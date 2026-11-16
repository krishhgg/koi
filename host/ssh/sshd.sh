# The sshd configuration for the account the CLI connects as, and the checks
# that it is the configuration sshd applies: what install.sh writes to the
# box and what the CLI's integration test (packages/cli/test/
# ssh.integration.test.ts) writes for a throwaway sshd, from one source.
# Sourced by bash, never run. Every function prints its reason to stderr and
# returns 1 when the check fails.
#
# How sshd settles the keywords the account's block sets, for a client
# (OpenSSH 9.6, servconf.c): it reads the global section when it starts;
# once the client is known it reads the Match blocks in order, and for each
# of those keywords the first value obtained wins, a value from a Match
# block over the global one. So a keyword the first matching block sets is
# settled: no later block and no global line changes it. AcceptEnv is the
# one of them that works otherwise: every matching block's list is
# appended, and the sum stands in for the global list. That is the rule for
# the keywords listed below, each tried with sshd -T; other keywords have
# rules of their own, and nothing here depends on them.
#
# The account's block (koi_match_block) depends on that rule. It must be the
# first Match sshd reads, and it sets every keyword that decides who gets
# in, what runs, where, and with what, so that nothing else in the
# configuration decides them for the account. What the rule leaves open is
# checked another way: the walker (koi_check_match_blocks) refuses an
# AcceptEnv in any other Match block, and koi_check_global reads the one
# keyword sshd does not take inside a Match block.
#
# Which of those keywords sshd takes inside a Match block, each tried with
# sshd -t (OpenSSH 9.6p1):
#   taken: ForceCommand, ChrootDirectory, TrustedUserCAKeys,
#     AuthorizedKeysFile, AuthorizedKeysCommand, AuthorizedPrincipalsFile,
#     AuthorizedPrincipalsCommand, AuthenticationMethods,
#     PubkeyAuthentication, PasswordAuthentication,
#     KbdInteractiveAuthentication, HostbasedAuthentication, PermitUserRC,
#     PermitTTY, DisableForwarding, AllowAgentForwarding,
#     AllowTcpForwarding, AllowStreamLocalForwarding, X11Forwarding,
#     PermitTunnel, GatewayPorts, PermitOpen, PermitListen, SetEnv,
#     AcceptEnv.
#   refused ("not allowed within a Match block"): PermitUserEnvironment.
#     The global value is read with sshd -T instead (koi_check_global).
# What `none` does inside the block. For ForceCommand and ChrootDirectory
# it is a switch: sshd clears both to nothing once the block is applied.
# For TrustedUserCAKeys, AuthorizedPrincipalsFile, AuthorizedKeysCommand
# and AuthorizedPrincipalsCommand it is not a switch but a literal name,
# kept as the value: a file sshd cannot open and a command it cannot run,
# which comes to the same. A certificate is refused (the integration test
# logs in with one), and AuthorizedKeysCommand none is refused as a path
# that is not absolute, which sshd logs on an attempt the keys file has
# already refused. sshd -T prints none for an unset keyword and for the
# word alike.
#
# What the block does not settle: ExposeAuthInfo. sshd takes it inside a
# Match block, and with it on, in the global section or in a later block,
# sshd adds SSH_USER_AUTH, the path of a file listing how the client
# authenticated, to the gateway's environment. The AcceptEnv and SetEnv
# placeholders do not stop that; nothing of koi's reads the variable.
#
# How sshd reads its files, which the walker follows:
#   - It opens each file with fopen, whatever the name is: a named pipe
#     feeds it lines, a directory reads as nothing, a link to nothing
#     stops it. Each line is copied up to its first NUL byte, newline
#     included, so the rest of such a line and the line after it join
#     what came before the NUL. The walker reads regular files alone and
#     refuses anything else, and refuses a file with a NUL in it, since
#     bash drops the byte and reads on.
#   - A line is a keyword, then its arguments after blanks or one `=`.
#     Include arguments are split as argv_split does: on spaces and tabs,
#     with double or single quotes grouping, `\"`, `\'` and `\\` standing
#     for the character inside quotes or out, `\ ` for a space outside
#     quotes, any other backslash kept, and a word that starts with `#`
#     ending the line.
#   - Include names files by pattern (glob(3): `*`, `?`, `[...]`, `\`), a
#     relative pattern under /etc/ssh, each matching file in byte order,
#     read in place of the line. A file included from inside a Match block
#     belongs to that block, a Match in the included file starts a new
#     block, and when the included file ends the including file goes on
#     in the block it was in. A Match block otherwise runs to the next
#     Match in its file.

# The names the Match block gives AcceptEnv and SetEnv. sshd cannot take
# either back to nothing inside a Match block: a bare keyword is a syntax
# error. A list given in the block replaces the global list for the account
# (sshd -T -C user=... shows it; OpenSSH 9.6), so these stand in for
# nothing: no program reads them, and with them in place the account takes
# no variable the client sends (LD_PRELOAD, say, which the loader would act
# on before the gateway runs) and none from the configuration, whatever the
# global AcceptEnv (Ubuntu's default is LANG LC_*) or SetEnv says.
KOI_SSHD_ACCEPT_ENV=KOI_NO_CLIENT_ENV
KOI_SSHD_SET_ENV=KOI_NO_SERVER_ENV=

# The Match block for the account. Every keyword that decides who gets in
# (keys from the one root-owned file: no password, keyboard prompt, host
# key, certificate or key command), what runs (the gateway, whatever the
# client asked for, with no PTY and no ~/.ssh/rc), where (no chroot) and
# what the session may open (nothing) has a value here, so that the first
# value obtained is the block's. PermitUserEnvironment cannot be set here;
# the installer reads the global value (koi_check_global).
#
#   koi_match_block USER GATEWAY KEYS
koi_match_block() {
	local user=$1 gateway=$2 keys=$3
	cat <<CONF
# koi: the account the CLI connects as (host/ssh/install.sh). Do not edit;
# the installer rewrites this file. It must be the first Match block sshd
# reads: for each keyword below the first value sshd obtains wins, except
# AcceptEnv, to which every matching block adds, so this block settles
# each for the account, whatever the global section or a later block says.
# PermitUserEnvironment cannot be set in a Match block; the installer
# checks that the global value is no.
Match User $user
    # Who gets in: keys from the one root-owned file, and nothing else.
    AuthenticationMethods publickey
    PubkeyAuthentication yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    HostbasedAuthentication no
    AuthorizedKeysFile $keys
    AuthorizedKeysCommand none
    AuthorizedPrincipalsFile none
    AuthorizedPrincipalsCommand none
    TrustedUserCAKeys none
    # What runs, and where.
    ForceCommand $gateway
    ChrootDirectory none
    PermitTTY no
    PermitUserRC no
    # What the session may open: nothing.
    DisableForwarding yes
    AllowAgentForwarding no
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    PermitTunnel no
    GatewayPorts no
    PermitOpen none
    PermitListen none
    # Its environment: names nothing reads, in place of an empty list,
    # which sshd does not take. They replace the global AcceptEnv and
    # SetEnv for this account.
    AcceptEnv $KOI_SSHD_ACCEPT_ENV
    SetEnv $KOI_SSHD_SET_ENV
CONF
}

# The lines sshd -T must print for a client of the account, as sshd prints
# them: the block's keywords in lower case, each with the block's value.
# ForceCommand and the keys file come first, so that a block that does not
# reach a client is reported by the keyword that says the most.
#
#   koi_effective_lines GATEWAY KEYS
koi_effective_lines() {
	local gateway=$1 keys=$2
	cat <<LINES
forcecommand $gateway
authorizedkeysfile $keys
authenticationmethods publickey
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
hostbasedauthentication no
authorizedkeyscommand none
authorizedprincipalsfile none
authorizedprincipalscommand none
trustedusercakeys none
chrootdirectory none
permittty no
permituserrc no
disableforwarding yes
allowagentforwarding no
allowtcpforwarding no
allowstreamlocalforwarding no
x11forwarding no
permittunnel no
gatewayports no
permitopen none
permitlisten none
acceptenv $KOI_SSHD_ACCEPT_ENV
setenv $KOI_SSHD_SET_ENV
LINES
}

# Splits ARGS into KOI_WORDS as sshd's argv_split does (see the top of this
# file). Returns 1 for a quote never closed, which sshd refuses too.
#
#   koi_split_words ARGS
koi_split_words() {
	local s=$1 n=${#1} i=0 c next quote word
	KOI_WORDS=()
	while [ "$i" -lt "$n" ]; do
		c=${s:i:1}
		if [ "$c" = ' ' ] || [ "$c" = $'\t' ]; then
			i=$((i + 1))
			continue
		fi
		[ "$c" = '#' ] && return 0
		quote='' word=''
		while [ "$i" -lt "$n" ]; do
			c=${s:i:1}
			if [ "$c" = '\' ]; then
				next=${s:i+1:1}
				if [ "$next" = '"' ] || [ "$next" = "'" ] || [ "$next" = '\' ] ||
					{ [ -z "$quote" ] && [ "$next" = ' ' ]; }; then
					word+=$next
					i=$((i + 2))
				else
					word+='\'
					i=$((i + 1))
				fi
				continue
			fi
			if [ -z "$quote" ]; then
				if [ "$c" = ' ' ] || [ "$c" = $'\t' ]; then
					break
				fi
				if [ "$c" = '"' ] || [ "$c" = "'" ]; then
					quote=$c
					i=$((i + 1))
					continue
				fi
			elif [ "$c" = "$quote" ]; then
				quote=''
				i=$((i + 1))
				continue
			fi
			word+=$c
			i=$((i + 1))
		done
		[ -n "$quote" ] && return 1
		KOI_WORDS+=("$word")
	done
	return 0
}

# What PATH is, in words for a message, when it is not a regular file. The
# tests follow a symbolic link, as sshd's fopen does; a link to nothing is
# the one thing fopen refuses.
#
#   koi_file_kind PATH
koi_file_kind() {
	local path=$1
	if [ -d "$path" ]; then
		echo directory
	elif [ -p "$path" ]; then
		echo 'named pipe'
	elif [ -S "$path" ]; then
		echo socket
	elif [ -b "$path" ] || [ -c "$path" ]; then
		echo device
	elif [ -L "$path" ]; then
		echo 'symbolic link to nothing'
	else
		echo 'file of another kind'
	fi
}

# Prints the number of the line with the first NUL byte in FILE and
# returns 0; returns 1 when the file has none. read -d '' reads up to a
# NUL and returns 1 at the end of the file without one, so no byte of the
# file is interpreted. LC_ALL=C so that the count is by byte.
#
#   koi_nul_line FILE
koi_nul_line() {
	local LC_ALL=C before
	IFS= read -r -d '' before < "$1" || return 1
	before=${before//[!$'\n']/}
	echo $((${#before} + 1))
}

# Walks the sshd configuration from FILE as sshd reads it (see the top of
# this file) and prints a record for each thing the checks need, in sshd's
# order:
#
#   match <tab> FILE:LINE
#       a Match block starts at FILE:LINE
#   acceptenv <tab> BLOCK <tab> FILE:LINE
#       AcceptEnv set at FILE:LINE inside the Match block BLOCK
#
# Whom a block is for is not read: the checks need no more than where each
# block starts. Returns 1, naming the file and line, for anything it
# cannot read as sshd would: a file it cannot open, a file that is not a
# regular file or has a NUL byte in it, a line that is not a keyword and
# its arguments, or an Include it cannot follow. Nothing on stdout is then
# to be used. BLOCK is the enclosing Match block (`-` at the top level);
# the caller leaves DEPTH and BLOCK to their defaults.
#
#   koi_walk_sshd FILE SSHDIR [DEPTH BLOCK]
koi_walk_sshd() {
	local file=$1 sshdir=$2 depth=${3:-0} block=${4:--}
	# Globs sort as sshd's do, by byte; and match as glob(3) does with no
	# flags: no file under a leading dot, no case folding, nothing extra.
	local LC_ALL=C IFS=
	local -
	set +f
	shopt -u nullglob failglob dotglob nocaseglob extglob globstar
	unset GLOBIGNORE
	local line n=0 nul keyword rest pattern path
	if [ "$depth" -gt 16 ]; then
		echo "koi: Include nested deeper than 16 files at $file" >&2
		return 1
	fi
	# Only a regular file is read: the Include that named anything else
	# was refused below, and a named pipe is never opened, which would
	# wait for a writer.
	if [ ! -f "$file" ] || [ ! -r "$file" ]; then
		echo "koi: cannot read $file as a regular file" >&2
		return 1
	fi
	# sshd copies each line up to its first NUL byte, newline included,
	# while bash's read drops the byte and keeps the rest of the line: the
	# two read different files from here on. Refused before any line is
	# read, since the line could be an Include.
	if nul=$(koi_nul_line "$file"); then
		echo "koi: $file:$nul has a NUL byte, at which sshd cuts the line; remove it" >&2
		return 1
	fi
	while IFS= read -r line || [ -n "$line" ]; do
		n=$((n + 1))
		# sshd drops blanks and a carriage return at the start of a line,
		# and whitespace at its end.
		line=${line#"${line%%[! $'\t\r']*}"}
		while [[ $line == *[\ $'\t\r\f'] ]]; do line=${line%?}; done
		[ -z "$line" ] && continue
		[ "${line:0:1}" = '#' ] && continue
		# A keyword, then its arguments after blanks, one `=`, or both.
		# A keyword that starts with a quote or an `=`, which sshd would
		# read around, is refused rather than read wrong.
		if ! [[ $line =~ ^([A-Za-z0-9]+)([[:blank:]]*=?[[:blank:]]*)(.*)$ ]] ||
			{ [ -z "${BASH_REMATCH[2]}" ] && [ -n "${BASH_REMATCH[3]}" ]; }; then
			echo "koi: $file:$n cannot be read as a keyword and its arguments; write it as sshd_config(5) shows it" >&2
			return 1
		fi
		keyword=${BASH_REMATCH[1],,}
		rest=${BASH_REMATCH[3]}
		case $keyword in
		match)
			block=$file:$n
			printf 'match\t%s\n' "$block"
			continue
			;;
		acceptenv)
			if [ "$block" != - ]; then
				printf 'acceptenv\t%s\t%s\n' "$block" "$file:$n"
			fi
			continue
			;;
		include) ;;
		*) continue ;;
		esac
		# An Include decides what the walker reads next, so it must be read
		# exactly: no control character sshd would keep in a word (a NUL,
		# which read would have dropped, was refused with the file), and
		# quotes that close.
		if [[ ${rest//$'\t'/} == *[[:cntrl:]]* ]]; then
			echo "koi: $file:$n has a control character in its arguments" >&2
			return 1
		fi
		if ! koi_split_words "$rest"; then
			echo "koi: $file:$n has a quote that is never closed" >&2
			return 1
		fi
		if [ ${#KOI_WORDS[@]} -eq 0 ]; then
			echo "koi: $file:$n is an Include without a file" >&2
			return 1
		fi
		for pattern in "${KOI_WORDS[@]}"; do
			case $pattern in
			'' | [Nn][Oo][Nn][Ee])
				echo "koi: $file:$n is an Include with an empty file name" >&2
				return 1
				;;
			'~'*)
				# sshd reads it from its working directory, which the walker
				# does not know.
				echo "koi: $file:$n includes $(printf %q "$pattern"), a path from sshd's working directory; write it in full" >&2
				return 1
				;;
			*[\[\\]*)
				echo "koi: $file:$n includes $(printf %q "$pattern"); the walker follows * and ? in an Include pattern, not [ or \\" >&2
				return 1
				;;
			/*) ;;
			*) pattern=$sshdir/$pattern ;;
			esac
			# Pathname expansion alone, with IFS empty: a space in the
			# pattern is part of it. A pattern that matches nothing stays as
			# it is, and names no file.
			# shellcheck disable=SC2206
			local -a paths=($pattern)
			for path in "${paths[@]}"; do
				# A literal pattern that names nothing stays as it is, and
				# sshd skips it too. Anything that is there, sshd opens and
				# reads, whatever it is (see the top of this file), so it
				# is refused by name and kind unless it is a regular file,
				# never skipped. A link to nothing is there for glob(3) and
				# stops sshd.
				if [ ! -e "$path" ] && [ ! -L "$path" ]; then
					continue
				fi
				if [ ! -f "$path" ]; then
					echo "koi: $file:$n includes $(printf %q "$path"), a $(koi_file_kind "$path") and not a regular file, which is all the installer reads" >&2
					return 1
				fi
				case $path in
				*[$'\t\n']*)
					echo "koi: $file:$n includes $(printf %q "$path"), whose name the walker cannot carry; rename it" >&2
					return 1
					;;
				esac
				# The included file starts in this block; this file goes on
				# in it after.
				koi_walk_sshd "$path" "$sshdir" $((depth + 1)) "$block" || return 1
			done
		done
	done < "$file"
	return 0
}

# Every check of the sshd configuration, in the one order that is safe on
# files the installer has not read yet: the walker first, then sshd -t,
# then the two checks that run sshd -T. sshd opens whatever an Include
# names, with -t and -T alike, and on a named pipe with no writer it waits
# for one and never returns; the walker refuses an Include of anything but
# a regular file by name and kind, without opening it, so it must see the
# files before sshd does. Prints the reason to stderr and returns 1 on the
# first check that fails.
#
#   koi_check_sshd SSHD CONFIG OURS SSHDIR USER GATEWAY KEYS
koi_check_sshd() {
	local sshd=$1 config=$2 ours=$3 sshdir=$4 user=$5 gateway=$6 keys=$7 syntax
	koi_check_match_blocks "$config" "$ours" "$sshdir" || return 1
	if ! syntax=$("$sshd" -t -f "$config" 2>&1); then
		echo "koi: sshd refuses its configuration with $ours in place: ${syntax:-no reason given}. Not reloaded." >&2
		return 1
	fi
	koi_check_global "$sshd" "$config" || return 1
	koi_check_effective "$sshd" "$config" "$user" "$gateway" "$keys" || return 1
}

# Checks the Match blocks sshd reads from CONFIG against OURS, the file
# with the account's block, which CONFIG must include. Two things. The
# first Match sshd meets is the one in OURS: for the keywords the block
# sets, all but AcceptEnv, the first matching block's value wins, and a
# Match before the Include would also swallow the Include into itself.
# And no other Match block, whoever it is for, sets AcceptEnv: sshd
# appends every matching block's list to the account's, and the walker
# does not read whom a block is for. sshd reads a block's criteria by
# rules of its own (strdelim, not the quoting of other keywords), under
# which `User *,!'koi-connect'` keeps its quotes and excludes nobody;
# following those rules is not the installer's job, and on a host
# dedicated to koi no other account needs a variable from its client.
# sshd -T answers for one client at a time and cannot show either for
# every client; only reading the files in sshd's order can
# (koi_walk_sshd).
#
#   koi_check_match_blocks CONFIG OURS [SSHDIR]
koi_check_match_blocks() {
	local config=$1 ours=$2 sshdir=${3:-/etc/ssh}
	local records record kind block where first=''
	records=$(koi_walk_sshd "$config" "$sshdir") || return 1
	while IFS= read -r record; do
		[ -n "$record" ] || continue
		IFS=$'\t' read -r kind block where <<< "$record"
		if [ "$kind" = match ]; then
			if [ -z "$first" ]; then
				first=$block
				case $first in
				"$ours":*) ;;
				*)
					echo "koi: sshd reads a Match block at $first before the one in $ours, and the first block that matches a client decides its ForceCommand and keys. Move it after the Include of $ours, or into a file that sorts after it. Not reloaded." >&2
					return 1
					;;
				esac
			fi
			continue
		fi
		if [ "$block" = "$first" ]; then
			continue
		fi
		echo "koi: the Match block at $block sets AcceptEnv at $where; sshd adds every matching block's AcceptEnv to the account's, and the installer does not read whom a block is for. Set AcceptEnv in the global section instead, which the account's block replaces, or remove it. Not reloaded." >&2
		return 1
	done <<< "$records"
	if [ -z "$first" ]; then
		echo "koi: sshd reading $config never meets the Match block in $ours; $config must include it (Include $(dirname "$ours")/*.conf) before any Match block" >&2
		return 1
	fi
	return 0
}

# The keyword the block needs that sshd does not take inside a Match
# block, so only the global section can set it: PermitUserEnvironment,
# which would let an environment= option on a key, or ~/.ssh/environment,
# into the account's environment. sshd -T without a client shows the
# global value.
#
#   koi_check_global SSHD CONFIG
koi_check_global() {
	local sshd=$1 config=$2 effective value
	if ! effective=$("$sshd" -T -f "$config" 2>&1); then
		echo "koi: sshd -T failed: $effective" >&2
		return 1
	fi
	value=$(grep -i '^permituserenvironment ' <<< "$effective" | tr '\n' ' ' | sed 's/ $//')
	if [ "$value" != 'permituserenvironment no' ]; then
		echo "koi: sshd's global PermitUserEnvironment is '${value#permituserenvironment }'; sshd does not take the keyword inside a Match block, so the global section must set PermitUserEnvironment no. Not reloaded." >&2
		return 1
	fi
}

# A sanity check on the account's block, after koi_check_match_blocks has
# read the files: sshd -T -C for a client of the account at each of a few
# addresses shows every keyword of the block with the block's value, and
# AcceptEnv and SetEnv with the placeholder names and nothing else. It
# shows that sshd loads the block as written and that the block is the
# one that settles those keywords for these clients; the proof that no
# other block adds to AcceptEnv is the walker's, since a few addresses
# cannot stand for every Match criterion. sshd -T prints keywords in lower
# case.
#
#   koi_check_effective SSHD CONFIG USER GATEWAY KEYS
koi_check_effective() {
	local sshd=$1 config=$2 user=$3 gateway=$4 keys=$5 addr effective line keyword value
	for addr in 127.0.0.1 203.0.113.10 2001:db8::1; do
		if ! effective=$("$sshd" -T -f "$config" -C "user=$user,host=$addr,addr=$addr" 2>&1); then
			echo "koi: sshd -T -C user=$user,addr=$addr failed: $effective" >&2
			return 1
		fi
		while IFS= read -r line; do
			keyword=${line%% *}
			value=${line#* }
			case $keyword in
			acceptenv | setenv) koi_want_only "$addr" "$effective" "$keyword" "$value" || return 1 ;;
			*) koi_want "$addr" "$effective" "$keyword" "$value" || return 1 ;;
			esac
		done < <(koi_effective_lines "$gateway" "$keys")
	done
}

# The keyword's effective line is exactly "KEYWORD VALUE".
koi_want() {
	local addr=$1 effective=$2 keyword=$3 value=$4
	if ! grep -Fqix "$keyword $value" <<< "$effective"; then
		echo "koi: for a client at $addr, sshd would apply '$(grep -i "^$keyword " <<< "$effective" | tr '\n' ' ' | sed 's/ $//')', not '$keyword $value'; the account's block does not reach this client, or sshd reads another file. Not reloaded." >&2
		return 1
	fi
}

# The keyword's effective lines are "KEYWORD VALUE" and no other.
koi_want_only() {
	local addr=$1 effective=$2 keyword=$3 value=$4 lines
	lines=$(grep -i "^$keyword " <<< "$effective" || true)
	if [ "$lines" != "$keyword $value" ]; then
		echo "koi: for a client at $addr, sshd would apply '$(tr '\n' ' ' <<< "$lines" | sed 's/ $//')', not '$keyword $value' alone; another part of the sshd configuration adds to $keyword for this account. Not reloaded." >&2
		return 1
	fi
}
