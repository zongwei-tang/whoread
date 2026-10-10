#!/bin/bash
# Resolves build settings from an Xcode .xcconfig file the way Xcode does, for building without
# Xcode (scripts/dev/sc-build.sh app).
#
# Usage:
#   xcconfig.sh [-D NAME=VALUE]... FILE get NAME...    print each setting, one per line
#   xcconfig.sh [-D NAME=VALUE]... FILE expand [--xml] < TEMPLATE > OUT
#                                    replace every $(NAME) / ${NAME} in TEMPLATE; with --xml the
#                                    substituted values are escaped for XML text (Info.plist)
#
# Xcode's rules: later assignments win; `#include "f"` and `#include? "f"` (optional) are read in
# place, relative to the including file; `//` starts a comment; references are resolved when a
# value is used, not when it is assigned, so a BUNDLE_ID_PREFIX set in an included Local.xcconfig
# changes every setting that refers to it. -D settings override the files, like build settings on
# the xcodebuild command line or a project's own settings over its configuration file.
# Stricter than Xcode on purpose: a reference to a setting defined nowhere is an error (Xcode
# silently expands it to nothing), as is any line this parser does not understand (conditional
# settings such as NAME[sdk=...], $(inherited), operators such as $(NAME:lower)).
set -euo pipefail
# bash 5.2 reads & in a ${s//x/y} replacement as the matched text; /bin/bash 3.2 never does.
shopt -u patsub_replacement 2>/dev/null || true

die() { echo "xcconfig.sh: $*" >&2; exit 1; }

NAMES=()
VALUES=()

# assign NAME VALUE
assign() {
  local i
  for ((i = 0; i < ${#NAMES[@]}; i++)); do
    if [ "${NAMES[$i]}" = "$1" ]; then VALUES[i]="$2"; return 0; fi
  done
  NAMES+=("$1")
  VALUES+=("$2")
}

# lookup NAME : raw value in REPLY; status 1 when the setting is not defined.
lookup() {
  local i
  for ((i = 0; i < ${#NAMES[@]}; i++)); do
    if [ "${NAMES[$i]}" = "$1" ]; then REPLY="${VALUES[$i]}"; return 0; fi
  done
  return 1
}

# trim STRING : REPLY without leading and trailing white space.
trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  REPLY="$s"
}

ASSIGN_RE='^([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$'
INCLUDE_RE='^#include(\??)[[:space:]]*"([^"]+)"$'

# read_file FILE DEPTH
read_file() {
  local file="$1" depth="$2" line n=0 inc optional
  [ "$depth" -le 16 ] || die "$file: #include nested too deeply"
  [ -f "$file" ] || die "$file: not found"
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    line="${line%%//*}"
    trim "$line"; line="$REPLY"
    [ -n "$line" ] || continue
    if [[ "$line" =~ $INCLUDE_RE ]]; then
      optional="${BASH_REMATCH[1]}"
      inc="${BASH_REMATCH[2]}"
      case "$inc" in /*) ;; *) inc="$(dirname "$file")/$inc" ;; esac
      if [ -f "$inc" ]; then
        read_file "$inc" $((depth + 1))
      elif [ -z "$optional" ]; then
        die "$file:$n: included file $inc not found"
      fi
    elif [[ "$line" =~ $ASSIGN_RE ]]; then
      local name="${BASH_REMATCH[1]}"
      trim "${BASH_REMATCH[2]}"
      assign "$name" "$REPLY"
    else
      die "$file:$n: unsupported line: $line"
    fi
  done < "$file"
}

REF_RE='\$\(([A-Za-z_][A-Za-z0-9_]*)\)|\$\{([A-Za-z_][A-Za-z0-9_]*)\}'

# literal TEXT CONTEXT : TEXT is copied unchanged, so it must not hold a reference REF_RE did not
# match (operators such as $(NAME:lower), nested references such as $(A_$(B))). Checked on every
# piece between matches, not only the tail: `$(A:lower)$(B)` must not pass `$(A:lower)` through.
literal() {
  if [[ "$1" == *'$('* || "$1" == *'${'* ]]; then die "unsupported reference in: $2"; fi
}

# expand STRING DEPTH : STRING with every reference replaced (recursively), in REPLY.
expand() {
  local s="$1" depth="$2" out="" ref name pre
  [ "$depth" -le 32 ] || die "reference cycle while expanding: $1"
  while [[ "$s" =~ $REF_RE ]]; do
    ref="${BASH_REMATCH[0]}"
    name="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
    # The first literal occurrence of the matched text is where the leftmost match starts.
    pre="${s%%"$ref"*}"
    literal "$pre" "$1"
    out+="$pre"
    s="${s#*"$ref"}"
    lookup "$name" || die "\$($name) is not defined"
    expand "$REPLY" $((depth + 1))
    out+="$REPLY"
  done
  literal "$s" "$1"
  REPLY="$out$s"
}

xml_escape() {
  local s="$1"
  s="${s//&/&amp;}"
  s="${s//</&lt;}"
  s="${s//>/&gt;}"
  REPLY="$s"
}

DEFINES=()
while [ $# -gt 0 ]; do
  case "$1" in
    -D) [ $# -ge 2 ] || die "-D needs NAME=VALUE"; DEFINES+=("$2"); shift 2 ;;
    -D*) DEFINES+=("${1#-D}"); shift ;;
    *) break ;;
  esac
done
[ $# -ge 2 ] || die "usage: xcconfig.sh [-D NAME=VALUE]... FILE get NAME... | FILE expand [--xml]"
FILE="$1"
CMD="$2"
shift 2

read_file "$FILE" 0
for d in ${DEFINES[@]+"${DEFINES[@]}"}; do
  [[ "$d" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || die "bad -D $d"
  assign "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
done

case "$CMD" in
  get)
    [ $# -ge 1 ] || die "get needs at least one NAME"
    for name in "$@"; do
      lookup "$name" || die "$name is not defined"
      expand "$REPLY" 0
      printf '%s\n' "$REPLY"
    done
    ;;
  expand)
    XML=0
    if [ "${1:-}" = "--xml" ]; then XML=1; shift; fi
    [ $# -eq 0 ] || die "expand takes no further arguments"
    while IFS= read -r line || [ -n "$line" ]; do
      out=""
      whole="$line"
      while [[ "$line" =~ $REF_RE ]]; do
        ref="${BASH_REMATCH[0]}"
        name="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
        pre="${line%%"$ref"*}"
        literal "$pre" "$whole"
        out+="$pre"
        line="${line#*"$ref"}"
        lookup "$name" || die "\$($name) is not defined"
        expand "$REPLY" 0
        if [ "$XML" = 1 ]; then xml_escape "$REPLY"; fi
        out+="$REPLY"
      done
      literal "$line" "$whole"
      printf '%s\n' "$out$line"
    done
    ;;
  *) die "unknown command $CMD" ;;
esac
