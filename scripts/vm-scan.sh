s(){ echo; echo "########## $1"; }
s OS; . /etc/os-release; echo $PRETTY_NAME; uname -r; uptime
s HW; nproc; free -h; df -hT -x tmpfs -x devtmpfs -x overlay -x squashfs -x efivarfs
s NET; ip -br a; ip r | head -5
s LISTEN; ss -tlnpu
s FIREWALL; ufw status 2>/dev/null
s SERVICES; systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'
s USER_SERVICES; for u in $(ls /home); do echo "-- $u"; sudo -u $u XDG_RUNTIME_DIR=/run/user/$(id -u $u) systemctl --user list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}'; done
s TIMERS; systemctl list-timers --no-legend | awk '{print $NF}' | head -30
s DOCKER; command -v docker && docker version --format '{{.Server.Version}}' && docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
s DOCKER_COMPOSE_PROJECTS; docker compose ls -a 2>/dev/null
s DOCKER_VOLUMES; docker volume ls 2>/dev/null; docker network ls 2>/dev/null
s DOCKER_DF; docker system df 2>/dev/null
s COMPOSE_FILES
for f in $(find /home /opt /srv /root -maxdepth 5 \( -name "docker-compose*.y*ml" -o -name "compose.y*ml" \) -not -path "*/node_modules/*" 2>/dev/null); do echo "--- $f"; sed -E 's/((PASSWORD|SECRET|TOKEN|_KEY|PASS)[A-Za-z_]*["]?[:=] *).*/\1***/I' "$f"; done
s TAILSCALE; tailscale status 2>/dev/null | head -30; tailscale serve status 2>/dev/null
s NETBIRD; netbird status 2>/dev/null | head -20
s DESKTOP; systemctl get-default; ls /usr/share/xsessions /usr/share/wayland-sessions 2>/dev/null; dpkg -l | awk '/^ii/{print $2}' | grep -E "^(xrdp|x11vnc|tigervnc|ubuntu-desktop|gnome-shell|xfce4|kde-plasma|sunshine|rustdesk|nomachine)" 
s NOTABLE_PKGS; dpkg -l | awk '/^ii/{print $2" "$3}' | grep -E "^(docker-ce|nginx|caddy|postgresql-[0-9]+|mariadb-server|redis-server|nodejs|tailscale|netbird|code|google-chrome|firefox|cloudflared|qemu-guest-agent|python3 )" 
s SNAP; snap list 2>/dev/null
s DEV_TOOLS; for u in $(ls /home); do echo "-- $u"; ls -la /home/$u | awk '{print $NF}' | grep -vE "^\.$|^\.\.$|^\.(bash|profile|cache|sudo)"; for t in node bun deno go cargo python3 uv pnpm claude codex gh; do p=$(sudo -iu $u bash -lc "command -v $t" 2>/dev/null) && echo "$t: $p"; done; done
s HOME_PROJECTS; for u in $(ls /home); do find /home/$u -maxdepth 3 -name .git -type d 2>/dev/null | sed 's|/.git||'; done
s OPT_SRV; ls -la /opt /srv
s CRON; for u in root $(ls /home); do echo "-- $u"; crontab -u $u -l 2>/dev/null | grep -v "^#"; done; ls /etc/cron.d
s SSH; grep -hvE "^#|^$" /etc/ssh/sshd_config.d/* 2>/dev/null; for u in /root /home/*; do echo "-- $u"; awk '{print $NF}' $u/.ssh/authorized_keys 2>/dev/null; done
s UPDATES; apt list --upgradable 2>/dev/null | tail -n +2 | wc -l; cat /var/run/reboot-required 2>/dev/null
