#!/bin/bash
#
# Solana Vanity Mnemonic Grinder
# Generates all leet variants and runs solana-keygen grind.
# Edit the word banks and name lists below to customize.
#
# Usage: ./grind.sh [cpu_percent]
#   cpu_percent: percentage of CPU cores to use (default: 50)
#

set -euo pipefail

# ============================================================
# CONFIG
# ============================================================
WORD_COUNT=24
NICE_LEVEL=10
DEFAULT_CPU_PERCENT=50
MATCH_COUNT=100

# ============================================================
# WORD BANK
# base58 safe: use lowercase o (not O), lowercase i (not I),
#              uppercase L (not l). No zeros.
# ============================================================
POSITIVE="
    BEST GoLD FAST FiRE KiNG CASH CooL DEEP LoRD RiCH VoiD RARE
    EViL PURE BoLD BoSS SoLo WiSE HERo PUNK DUKE NUKE BooM SAGE
    FUNK HACK EPiC DUDE RAGE FLEX GoAT DANK DoPE HoDL SWAG ViBE
    YEET YoLo STUD LoVE PEAK WiNS HiGH HoLY LoUD HARD DEAD CoDE
    NERD GEEK GoLF RUNS GURU JERK RUST DEVS RooT SUDo TALL
"
ROAST="
    ANAL FUCK CoCK DiCK SUCK DiLF SLUT BoNE BANG SEXY KiLL HATE
    DAMN WANG FooL CRAP NUDE PoRN TiTS DoRK PAiN HELL BUTT SHiT
    ooPS BoMB BooB NUTS DUMB BoNK BRUH LMAo BRRR DoNG
"
TEAM_WORDS="FUSE ETHR TEAM"
ALL_WORDS="$POSITIVE $ROAST $TEAM_WORDS"

# ============================================================
# DEV NAMES
# p_ = prefix forms, s_ = suffix forms (space separated)
# ============================================================
p_Erik="ERiK"                   ; s_Erik="ERiK"
p_Landon="LAND"                 ; s_Landon="LAND"
p_Jordan="JoRD"                 ; s_Jordan="JoRD"
p_Jonathan="JoN1 JoN2 JoN3 JoN4 JoN5 JoN6 JoN7 JoN8 JoN9 JoNS"
s_Jonathan="1JoN 2JoN 3JoN 4JoN 5JoN 6JoN 7JoN 8JoN 9JoN JoNS"
p_AJ="AJAY"                    ; s_AJ="AJAY"

ALL_FIRST_NAMES="Erik Landon Jordan Jonathan AJ"

# Last names
p_Donohoo="DoNo"   ; s_Donohoo="DoNo"
p_Hooo="Hooo"      ; s_Hooo="Hooo"
p_Poch="PoCH"      ; s_Poch="PoCH"
p_Gates="GATE"     ; s_Gates="GATE"
p_Gawrych="GAWR"   ; s_Gawrych="GAWR"
p_Taylor="TAYL"    ; s_Taylor="TAYL"
p_Taylor2="TLoR"   ; s_Taylor2="TLoR"

LAST_NAMES_WITH_WORDS="Donohoo Poch Gates Gawrych Taylor Taylor2"

# Name pairs: "first:last" (generates both directions)
NAME_PAIRS="
    Erik:Donohoo  Erik:Hooo
    Landon:Poch   Jordan:Gates
    Jonathan:Gawrych
    AJ:Taylor     AJ:Taylor2
    Donohoo:Hooo
"

SELF_REPEATS="ERiK PoCH LAND GATE GAWR AJAY TAYL DoNo Hooo JoRD TLoR"
LANDON_SPECIALS="LoRD MiNE MARK FiLL MASS FALL LoCK oooo"

# ============================================================
# HOLLOW KNIGHT 4+4 PAIRS (prefix:suffix)
# ============================================================
HK_PAIRS="
    DEEP:NEST CiTY:TEAR GREY:ZoTE GRAY:ZoTE GRiM:KiNG DREM:NAiL
    BELL:HART GoDS:HoME GREY:MooR GRAY:MooR DUNG:DFND GRiM:GRiM
    DUNG:DUNG SiLK:SoNG PALE:KiNG KiNG:GRiM PATH:PAiN KiNG:SoUL
    VoiD:LACE LoST:LACE NiTE:GRiM MoTH:WiNG LAST:STAG KiNG:EDGE
    SiLK:VoiD VoiD:SiLK SoNG:SiLK WoRM:WAYS MooR:WiNG SiLK:SoAR
    PALE:WYRM PURE:VESS WYRM:KiNG SHAW:DASH VoiD:HERT SiLK:BiND
    LACE:VoiD SiLK:SiLK VoiD:VoiD LACE:LACE SHAW:SHAW NoSK:NoSK
    ZoTE:ZoTE WYRM:WYRM NAiL:NAiL STAG:STAG
"
HK_BUG_DIGITS="1 2 3 4 5 6 7 8 9"

# ============================================================
# LEET ENGINE (uses awk for speed)
# ============================================================
CACHE_DIR=$(mktemp -d)
trap 'rm -rf "$CACHE_DIR"' EXIT

# Generate all leet variants of a word via awk.
# $1=word, $2=mode (prefix: lock first char, suffix: all can leet)
leet_expand() {
    echo "$1" | awk -v mode="$2" '{
        split("A,4 B,8 E,3 G,6 i,1 S,5 T,7 Z,2", pairs, " ")
        for (k in pairs) { split(pairs[k], kv, ","); leet[kv[1]] = kv[2] }
        n = 1; variants[1] = ""
        for (i = 1; i <= length($0); i++) {
            ch = substr($0, i, 1)
            has_sub = (ch in leet) && (i > 1 || mode != "prefix")
            nn = 0
            for (j = 1; j <= n; j++) {
                nn++; nv[nn] = variants[j] ch
                if (has_sub) { nn++; nv[nn] = variants[j] leet[ch] }
            }
            n = nn; for (j = 1; j <= n; j++) variants[j] = nv[j]
        }
        for (j = 1; j <= n; j++) print variants[j]
    }'
}

# Cached leet expansion
cached_expand() {
    local word="$1" mode="$2"
    local safe=$(echo "$word" | sed 's/O/o/g; s/I/i/g; s/l/L/g')
    local f="$CACHE_DIR/${safe}_${mode}"
    [[ -f "$f" ]] || leet_expand "$safe" "$mode" > "$f"
    cat "$f"
}

# Cross-product two files of variants into prefix:suffix flags
cross_product() {
    awk 'NR==FNR{s[NR]=$0; ns=NR; next} {for(i=1;i<=ns;i++) print $0 ":" s[i]}' "$2" "$1"
}

# ============================================================
# BUILD FLAGS
# ============================================================
echo "Building flags..." >&2
FLAGS_FILE="$CACHE_DIR/flags"
> "$FLAGS_FILE"

echo "  HK pairs..." >&2
for pair in $HK_PAIRS; do
    IFS=':' read -r p s <<< "$pair"
    pf=$(mktemp -p "$CACHE_DIR"); sf=$(mktemp -p "$CACHE_DIR")
    cached_expand "$p" prefix > "$pf"
    cached_expand "$s" suffix > "$sf"
    cross_product "$pf" "$sf" >> "$FLAGS_FILE"
done

echo "  BUG...NiTE..." >&2
sf=$(mktemp -p "$CACHE_DIR")
cached_expand "NiTE" suffix > "$sf"
for d in $HK_BUG_DIGITS; do
    sed "s/^/BUG${d}:/" "$sf" >> "$FLAGS_FILE"
done

echo "  Name pairs..." >&2
for pair in $NAME_PAIRS; do
    [[ -z "$pair" ]] && continue
    IFS=':' read -r fk lk <<< "$pair"
    eval "fp=\"\$p_${fk}\""; eval "fs=\"\$s_${fk}\""
    eval "lp=\"\$p_${lk}\""; eval "ls=\"\$s_${lk}\""
    for f in $fp; do for l in $ls; do
        pf=$(mktemp -p "$CACHE_DIR"); sf2=$(mktemp -p "$CACHE_DIR")
        cached_expand "$f" prefix > "$pf"
        cached_expand "$l" suffix > "$sf2"
        cross_product "$pf" "$sf2" >> "$FLAGS_FILE"
    done; done
    for l in $lp; do for f in $fs; do
        pf=$(mktemp -p "$CACHE_DIR"); sf2=$(mktemp -p "$CACHE_DIR")
        cached_expand "$l" prefix > "$pf"
        cached_expand "$f" suffix > "$sf2"
        cross_product "$pf" "$sf2" >> "$FLAGS_FILE"
    done; done
done

echo "  Self-repeats..." >&2
for w in $SELF_REPEATS; do
    pf=$(mktemp -p "$CACHE_DIR"); sf=$(mktemp -p "$CACHE_DIR")
    cached_expand "$w" prefix > "$pf"
    cached_expand "$w" suffix > "$sf"
    cross_product "$pf" "$sf" >> "$FLAGS_FILE"
done

echo "  Landon specials..." >&2
pf=$(mktemp -p "$CACHE_DIR")
cached_expand "LAND" prefix > "$pf"
for s in $LANDON_SPECIALS; do
    sf=$(mktemp -p "$CACHE_DIR")
    cached_expand "$s" suffix > "$sf"
    cross_product "$pf" "$sf" >> "$FLAGS_FILE"
done

echo "  Word list variants..." >&2
ALL_P="$CACHE_DIR/all_words_prefix"
ALL_S="$CACHE_DIR/all_words_suffix"
> "$ALL_P"; > "$ALL_S"
for w in $ALL_WORDS; do
    cached_expand "$w" prefix >> "$ALL_P"
    cached_expand "$w" suffix >> "$ALL_S"
done

echo "  First name + words..." >&2
for name in $ALL_FIRST_NAMES; do
    eval "prefixes=\"\$p_${name}\""
    eval "suffixes=\"\$s_${name}\""
    for form in $prefixes; do
        nf=$(mktemp -p "$CACHE_DIR")
        cached_expand "$form" prefix > "$nf"
        cross_product "$nf" "$ALL_S" >> "$FLAGS_FILE"
    done
    for form in $suffixes; do
        nf=$(mktemp -p "$CACHE_DIR")
        cached_expand "$form" suffix > "$nf"
        cross_product "$ALL_P" "$nf" >> "$FLAGS_FILE"
    done
done

echo "  Last name + words..." >&2
for name in $LAST_NAMES_WITH_WORDS; do
    eval "prefixes=\"\$p_${name}\""
    eval "suffixes=\"\$s_${name}\""
    for form in $prefixes; do
        nf=$(mktemp -p "$CACHE_DIR")
        cached_expand "$form" prefix > "$nf"
        cross_product "$nf" "$ALL_S" >> "$FLAGS_FILE"
    done
    for form in $suffixes; do
        nf=$(mktemp -p "$CACHE_DIR")
        cached_expand "$form" suffix > "$nf"
        cross_product "$ALL_P" "$nf" >> "$FLAGS_FILE"
    done
done

echo "  Deduplicating..." >&2
sort -u -o "$FLAGS_FILE" "$FLAGS_FILE"
FLAG_COUNT=$(wc -l < "$FLAGS_FILE")
echo "${FLAG_COUNT} unique flags" >&2

# ============================================================
# DETECT CORES
# ============================================================
PERCENT="${1:-$DEFAULT_CPU_PERCENT}"
TOTAL_CORES=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo "")
if [ -z "$TOTAL_CORES" ]; then
    echo "Error: Could not detect CPU core count." >&2
    exit 1
fi
THREADS=$(( TOTAL_CORES * PERCENT / 100 ))
THREADS=$(( THREADS < 1 ? 1 : THREADS ))
echo "Detected $TOTAL_CORES cores, using $THREADS threads ($PERCENT%)" >&2

# ============================================================
# LAUNCH
# ============================================================
ARGS=(
    solana-keygen grind
    --num-threads "$THREADS"
    --use-mnemonic
    --word-count "$WORD_COUNT"
    --derivation-path
    --ignore-case
    --no-bip39-passphrase
    --no-outfile
)
while IFS= read -r flag; do
    ARGS+=(--starts-and-ends-with "${flag}:${MATCH_COUNT}")
done < "$FLAGS_FILE"

ARG_SIZE=0
for a in "${ARGS[@]}"; do ARG_SIZE=$(( ARG_SIZE + ${#a} + 1 )); done
echo "Arg size: ${ARG_SIZE} bytes" >&2
if [ "$ARG_SIZE" -gt 900000 ]; then
    echo "WARNING: close to macOS 1MB ARG_MAX limit" >&2
fi

echo "" >&2
echo "Launching (nice $NICE_LEVEL, caffeinated)..." >&2
echo "Ctrl+Z to pause, fg to resume, Ctrl+C to stop" >&2
echo "" >&2

renice -n "$NICE_LEVEL" $$ >/dev/null 2>&1 || true

exec caffeinate -i "${ARGS[@]}" 2>&1 | \
    sed -Eu 's/([A-Za-z0-9]{4})([A-Za-z0-9]{35,36})([A-Za-z0-9]{4})/\1...\3 (\1\2\3)/g'
