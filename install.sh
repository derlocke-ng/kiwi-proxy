#!/usr/bin/env bash
# install.sh — kiwi-proxy, installed by `kiwi` (see kiwi.manifest)
#
# User scope only: rootless podman needs no root, so a plain user install is
# fully functional and nothing outside $HOME is ever written.
#
#   KIWI_SCOPE  user        KIWI_PREFIX  ~/.local
#   KIWI_ACTION install|update|uninstall
#   KIWI_GUI    0 on a headless machine
#   KIWI_PURGE  1 only when the user asked for --purge
#
# Consumers (kiwi-fox, kiwi-pentesting) import the package from
# $KIWI_PREFIX/lib/kiwi-proxy, or call the kiwi-proxy command.
set -euo pipefail

KIWI_SCOPE="${KIWI_SCOPE:-user}"
KIWI_PREFIX="${KIWI_PREFIX:-$HOME/.local}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP=kiwi-proxy
LIBDIR="$KIWI_PREFIX/lib/$APP"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}/$APP"
CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/$APP"
UNITDIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
# kiwi-fox kept its DNS data here before the split.
FOX_DATA="${XDG_DATA_HOME:-$HOME/.local/share}/kiwi-fox"

if [[ "$KIWI_SCOPE" != user ]]; then
    echo "install.sh: $APP is user-scope only; nothing to do for scope '$KIWI_SCOPE'"
    exit 0
fi

# The launcher's icon is replaced on update (it comes from kiwi-icons), and an
# icon-theme.cache that predates it keeps the old one in the app grid until the
# cache is rebuilt — the same refresh kiwi-updater does for its own icon.
refresh_desktop_caches() {
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -qtf "$KIWI_PREFIX/share/icons/hicolor" 2>/dev/null || true
    fi
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q "$KIWI_PREFIX/share/applications" 2>/dev/null || true
    fi
}

do_install() {
    mkdir -p "$LIBDIR" "$KIWI_PREFIX/bin"
    rm -rf "$LIBDIR/kiwi_proxy" "$LIBDIR/containers" "$LIBDIR/server-module"
    cp -r "$SRC/src/kiwi_proxy" "$LIBDIR/kiwi_proxy"
    cp -r "$SRC/containers" "$LIBDIR/containers"
    cp -r "$SRC/server-module" "$LIBDIR/server-module"

    cat > "$KIWI_PREFIX/bin/$APP" <<EOW
#!/usr/bin/env bash
export PYTHONPATH="$LIBDIR\${PYTHONPATH:+:\$PYTHONPATH}"
exec python3 -m kiwi_proxy "\$@"
EOW
    chmod +x "$KIWI_PREFIX/bin/$APP"

    if [[ "${KIWI_GUI:-1}" == 1 ]]; then
        cat > "$KIWI_PREFIX/bin/$APP-gui" <<EOW
#!/usr/bin/env bash
export PYTHONPATH="$LIBDIR\${PYTHONPATH:+:\$PYTHONPATH}"
exec python3 -m kiwi_proxy.ui "\$@"
EOW
        chmod +x "$KIWI_PREFIX/bin/$APP-gui"
        install -Dm644 "$SRC/data/$APP.desktop" \
            "$KIWI_PREFIX/share/applications/$APP.desktop" 2>/dev/null || true
        install -Dm644 "$SRC/data/$APP.svg" \
            "$KIWI_PREFIX/share/icons/hicolor/scalable/apps/$APP.svg" 2>/dev/null || true
        refresh_desktop_caches
    fi

    # Resolver stamps and blocklists kiwi-fox downloaded before the split are the
    # same files; take them rather than fetching them again.
    if [[ -d "$FOX_DATA/blocklists" && ! -e "$DATA/blocklists" ]]; then
        mkdir -p "$DATA"
        cp -r "$FOX_DATA/blocklists" "$DATA/blocklists"
        echo "took the DNS stamps and blocklists kiwi-fox had downloaded"
    fi

    mkdir -p "$UNITDIR"
    cat > "$UNITDIR/$APP-blocklists.service" <<EOW
[Unit]
Description=Refresh kiwi-proxy DNS blocklists
[Service]
Type=oneshot
ExecStart=$KIWI_PREFIX/bin/$APP dns update
EOW
    cat > "$UNITDIR/$APP-blocklists.timer" <<EOW
[Unit]
Description=Refresh kiwi-proxy DNS blocklists daily
[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=2h
[Install]
WantedBy=timers.target
EOW
    # One exit kept up for as long as you are logged in (or always, with
    # `loginctl enable-linger`): systemctl --user enable --now kiwi-proxy@NAME
    cat > "$UNITDIR/$APP@.service" <<EOW
[Unit]
Description=kiwi-proxy exit %i
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$KIWI_PREFIX/bin/$APP up --no-measure %i
ExecStop=$KIWI_PREFIX/bin/$APP down %i
[Install]
WantedBy=default.target
EOW
    systemctl --user daemon-reload 2>/dev/null || true
    systemctl --user enable --now "$APP-blocklists.timer" 2>/dev/null || true

    echo "installed $APP to $KIWI_PREFIX"
    echo
    echo "First run needs one command — it builds the gateway image and fetches the"
    echo "DNS data (kiwi-fox's setup runs it for you):"
    echo
    echo "    $APP setup"
    echo
    echo "Then:  $APP add work socks5://host:port --expose 1081   &&   $APP up work"
    echo "   or: $APP-gui   (\"Kiwi-Proxy\" in your app grid)"
}

do_update() { do_install; }

do_uninstall() {
    systemctl --user disable --now "$APP-blocklists.timer" 2>/dev/null || true
    rm -f "$UNITDIR/$APP-blocklists."{service,timer} "$UNITDIR/$APP@.service"
    systemctl --user daemon-reload 2>/dev/null || true
    rm -f "$KIWI_PREFIX/bin/$APP" "$KIWI_PREFIX/bin/$APP-gui"
    rm -f "$KIWI_PREFIX/share/applications/$APP.desktop"
    rm -f "$KIWI_PREFIX/share/icons/hicolor/scalable/apps/$APP.svg"
    refresh_desktop_caches
    rm -rf "$LIBDIR"

    # An ordinary uninstall leaves exits, module state and secrets alone, so
    # reinstalling resumes where you left off. --purge deletes them.
    if [[ "${KIWI_PURGE:-0}" == 1 || "${2:-}" == --purge ]]; then
        echo "purging $DATA and $CONFIG — exits and their stored passwords are being deleted"
        rm -rf "$DATA" "$CONFIG"
    else
        echo "kept $DATA (pass --purge to remove exits and module state)"
    fi
    echo "uninstalled $APP"
}

case "${KIWI_ACTION:-${1:-install}}" in
    install)   do_install ;;
    update)    do_update ;;
    uninstall) do_uninstall "$@" ;;
    *) echo "usage: $0 install|update|uninstall [--purge]" >&2; exit 1 ;;
esac
