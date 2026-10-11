#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  install.sh  —  SCAN CLI installer for Linux / macOS
#
#  What this does:
#    1. Checks Python 3.10+
#    2. Installs pip if missing
#    3. Installs Python deps (requests, rich)
#    4. Copies the tool into ~/.local/share/scan-cli/
#    5. Creates a `scan` wrapper in ~/.local/bin/
#    6. Checks PATH and prints advice if needed
#    7. Checks for the optional subfinder binary
#
#  Usage:
#    chmod +x install.sh
#    ./install.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
BOLD="\033[1m"
GRN="\033[1;32m"
CYN="\033[1;36m"
YLW="\033[1;33m"
RED="\033[1;31m"
RST="\033[0m"

ok()   { echo -e "${GRN}  ✔  $*${RST}"; }
info() { echo -e "${CYN}  ➜  $*${RST}"; }
warn() { echo -e "${YLW}  ⚠  $*${RST}"; }
die()  { echo -e "${RED}  ✘  $*${RST}"; exit 1; }

# ── Dirs ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/.local/share/scan-cli"
BIN_DIR="${HOME}/.local/bin"
BIN_PATH="${BIN_DIR}/scan"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYN}  ╔══════════════════════════════════════╗"
echo -e "  ║       SCAN CLI  —  Installer  v1.0   ║"
echo -e "  ╚══════════════════════════════════════╝${RST}"
echo ""

# ── 1. Python 3.10+ ──────────────────────────────────────────────────────────
info "Checking Python 3 (3.10+ required)…"
if ! command -v python3 &>/dev/null; then
    die "python3 not found.  Install it:  sudo apt install python3"
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJ=$(python3 -c "import sys; print(sys.version_info.major)")
PY_MIN=$(python3 -c "import sys; print(sys.version_info.minor)")

if [[ "$PY_MAJ" -lt 3 ]] || [[ "$PY_MAJ" -eq 3 && "$PY_MIN" -lt 10 ]]; then
    die "Python 3.10+ required, found ${PY_VER}.  Please upgrade."
fi
ok "Python ${PY_VER}"

# ── 2. pip ───────────────────────────────────────────────────────────────────
info "Checking pip…"
if ! python3 -m pip --version &>/dev/null; then
    warn "pip not found — attempting to install…"
    python3 -m ensurepip --upgrade 2>/dev/null \
      || sudo apt-get install -y python3-pip 2>/dev/null \
      || die "Could not install pip.  Run: sudo apt install python3-pip"
fi
ok "pip $(python3 -m pip --version | awk '{print $2}')"

# ── 3. Python packages ───────────────────────────────────────────────────────
info "Installing Python dependencies…"
python3 -m pip install --quiet --user -r "${SCRIPT_DIR}/requirements.txt"
ok "requests + rich installed"

# ── 4. Copy tool files ───────────────────────────────────────────────────────
info "Copying tool files to ${INSTALL_DIR}…"
mkdir -p "${INSTALL_DIR}/lib"

cp "${SCRIPT_DIR}/scan.py"        "${INSTALL_DIR}/scan.py"
cp "${SCRIPT_DIR}/lib/__init__.py"     "${INSTALL_DIR}/lib/__init__.py"
cp "${SCRIPT_DIR}/lib/subfinder.py"    "${INSTALL_DIR}/lib/subfinder.py"
cp "${SCRIPT_DIR}/lib/api_discovery.py" "${INSTALL_DIR}/lib/api_discovery.py"
cp "${SCRIPT_DIR}/lib/crawler.py"      "${INSTALL_DIR}/lib/crawler.py"

chmod +x "${INSTALL_DIR}/scan.py"
ok "Files installed"

# ── 5. Create the `scan` wrapper ─────────────────────────────────────────────
info "Creating 'scan' command in ${BIN_DIR}…"
mkdir -p "${BIN_DIR}"

cat > "${BIN_PATH}" <<WRAPPER
#!/usr/bin/env bash
exec python3 "${INSTALL_DIR}/scan.py" "\$@"
WRAPPER

chmod +x "${BIN_PATH}"
ok "Wrapper created → ${BIN_PATH}"

# ── 6. PATH check ────────────────────────────────────────────────────────────
if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
    warn "${BIN_DIR} is not in your PATH."
    echo ""
    echo -e "  Add this line to your ${BOLD}~/.bashrc${RST} or ${BOLD}~/.zshrc${RST}:"
    echo -e "    ${CYN}export PATH=\"\${HOME}/.local/bin:\${PATH}\"${RST}"
    echo ""
    echo -e "  Then reload:  ${CYN}source ~/.bashrc${RST}"
    echo ""
else
    ok "PATH already includes ${BIN_DIR}"
fi

# ── 7. Optional: subfinder binary ────────────────────────────────────────────
info "Checking for subfinder binary (optional but recommended)…"
if command -v subfinder &>/dev/null; then
    ok "subfinder found → $(command -v subfinder)"
else
    warn "subfinder not found — will fall back to crt.sh + HackerTarget."
    echo ""
    echo -e "  To install subfinder (requires Go):"
    echo -e "    ${CYN}go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest${RST}"
    echo ""
    echo -e "  Pre-built binaries:"
    echo -e "    ${CYN}https://github.com/projectdiscovery/subfinder/releases${RST}"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GRN}  ✅  Installation complete!${RST}"
echo ""
echo -e "  ${BOLD}Quick start:${RST}"
echo -e "    ${CYN}scan subs -d example.com${RST}"
echo -e "    ${CYN}scan endpoints -u https://api.example.com${RST}"
echo -e "    ${CYN}scan full -d example.com --max-hosts 5 -o out.json${RST}"
echo -e "    ${CYN}scan --help${RST}"
echo ""
