#!/usr/bin/env bash
set -euo pipefail

# ============================================
# WireGuard Installer + Client Manager (Andrés)
# - Soporta tipos de cliente:
#   [1] Normal (full-tunnel)
#   [2] Intranet-only (AllowedIPs acotados)
#   [3] Gateway de LAN (anuncia LAN_CIDR detrás del peer)
# - Red por defecto del servidor: 10.7.0.0/24
# - Puerto por defecto: 51820/udp
# - Guarda clientes en /root/<nombre>.conf
# ============================================

WG_IFACE="wg0"
WG_NET="10.7.0.0/24"
WG_NET_BASE="10.7.0"
WG_PORT_DEFAULT="51820"
DNS_DEFAULT="1.1.1.1, 1.0.0.1"
WG_DIR="/etc/wireguard"
WG_CONF="${WG_DIR}/${WG_IFACE}.conf"
BACKUP_DIR="/root/wg-backups"
QR_CMD="$(command -v qrencode || true)"

detect_iface() {
  # Detectra interfaz de salida principal (para NAT)
  # Si no encuentra, usa "eth0" como fallback
  local iface
  iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}') || true
  if [[ -z "${iface:-}" ]]; then
    iface="eth0"
  fi
  echo "$iface"
}

is_ipv4_cidr() {
  # Validación básica IPv4 CIDR (ej: 10.76.0.0/24)
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$ ]] || return 1
  IFS=/ read -r ip mask <<< "$1"
  IFS=. read -r o1 o2 o3 o4 <<< "$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [[ "$o" -ge 0 && "$o" -le 255 ]] || return 1
  done
  return 0
}

ip_in_use() {
  local ip="$1"
  grep -qE "AllowedIPs *= *${ip}/32" "$WG_CONF" 2>/dev/null && return 0 || return 1
}

next_free_ip() {
  # Busca próxima IP libre del rango 10.7.0.X
  local i
  for i in $(seq 2 254); do
    local ip="${WG_NET_BASE}.${i}"
    if ! ip_in_use "$ip"; then
      echo "$ip"
      return 0
    fi
  done
  return 1
}

ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Ejecutá como root." >&2
    exit 1
  fi
}

ensure_apt() {
  if ! command -v apt >/dev/null 2>&1; then
    echo "Este instalador está pensado para Debian/Ubuntu (apt)." >&2
    exit 1
  fi
}

backup_conf() {
  mkdir -p "$BACKUP_DIR"
  if [[ -f "$WG_CONF" ]]; then
    cp -a "$WG_CONF" "$BACKUP_DIR/wg0.conf.$(date +%Y%m%d-%H%M%S).bak"
  fi
}

restart_wg() {
  systemctl daemon-reload || true
  if systemctl is-enabled --quiet "wg-quick@${WG_IFACE}"; then
    systemctl restart "wg-quick@${WG_IFACE}"
  else
    wg-quick down "${WG_IFACE}" 2>/dev/null || true
    wg-quick up "${WG_IFACE}"
    systemctl enable "wg-quick@${WG_IFACE}"
  fi
}

print_qr() {
  local file="$1"
  if [[ -n "$QR_CMD" ]]; then
    echo
    echo "===== QR ====="
    "$QR_CMD" -t ansiutf8 < "$file" || true
    echo "=============="
  fi
}

install_server() {
  ensure_apt
  apt update
  apt install -y wireguard wireguard-tools jq iproute2 iptables qrencode || apt install -y wireguard wireguard-tools jq iproute2 iptables

  mkdir -p "$WG_DIR"
  chmod 700 "$WG_DIR"

  # Si ya existe, no sobreescribir:
  if [[ -f "$WG_CONF" ]]; then
    echo "Ya existe ${WG_CONF}. ¿Querés reinstalar el servidor desde cero? (y/n)"
    read -r ans
    if [[ "$ans" != "y" ]]; then
      echo "OK, no reinstalo. Volviendo al menú."
      return
    fi
    backup_conf
  fi

  echo "IP pública detectada (o ingresá manualmente):"
  PUB_IPS=()
  # Intento detectar IP pública
  DETECTED_IP=$(curl -4s https://ifconfig.me || true)
  [[ -n "$DETECTED_IP" ]] && PUB_IPS+=("$DETECTED_IP")
  # También IP asignada a la NIC de salida
  DEF_IFACE=$(detect_iface)
  IFACE_IP=$(ip -4 addr show "$DEF_IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)
  [[ -n "$IFACE_IP" ]] && PUB_IPS+=("$IFACE_IP")
  PUB_IPS=($(printf "%s\n" "${PUB_IPS[@]}" | awk '!x[$0]++'))

  local server_ip=""
  if ((${#PUB_IPS[@]})); then
    echo "0) Ingresar manualmente"
    local idx=1
    for ip in "${PUB_IPS[@]}"; do
      echo "$idx) $ip"
      idx=$((idx+1))
    done
    echo -n "Seleccioná opción: "
    read -r opt
    if [[ "$opt" == "0" ]]; then
      echo -n "IP/Dominio público del servidor: "
      read -r server_ip
    else
      sel=$((opt-1))
      server_ip="${PUB_IPS[$sel]:-}"
    fi
  fi
  while [[ -z "${server_ip:-}" ]]; do
    echo -n "IP/Dominio público del servidor: "
    read -r server_ip
  done

  echo -n "Puerto UDP para WireGuard [${WG_PORT_DEFAULT}]: "
  read -r wg_port
  [[ -z "${wg_port:-}" ]] && wg_port="$WG_PORT_DEFAULT"

  echo -n "DNS para clientes [${DNS_DEFAULT}]: "
  read -r dns_cli
  [[ -z "${dns_cli:-}" ]] && dns_cli="$DNS_DEFAULT"

  # Claves servidor
  umask 077
  SERVER_PRIV=$(wg genkey)
  SERVER_PUB=$(printf "%s" "$SERVER_PRIV" | wg pubkey)

  # IP del servidor en la red:
  SERVER_IP="${WG_NET_BASE}.1"

  # Detectar interfaz de salida para NAT:
  OUT_IFACE=$(detect_iface)

  cat > "$WG_CONF" <<EOF
[Interface]
Address = ${SERVER_IP}/24
ListenPort = ${wg_port}
PrivateKey = ${SERVER_PRIV}
SaveConfig = false

# Habilitar NAT al exterior
PostUp   = iptables -t nat -A POSTROUTING -o ${OUT_IFACE} -s ${WG_NET} -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o ${OUT_IFACE} -s ${WG_NET} -j MASQUERADE
EOF

  # Habilitar forwarding
  if ! sysctl -q net.ipv4.ip_forward | grep -q " = 1"; then
    sed -i 's/^#\?net\.ipv4\.ip_forward.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    sysctl -p >/dev/null || true
  fi

  # Levantar
  wg-quick up "${WG_IFACE}" || { echo "Error al levantar ${WG_IFACE}"; exit 1; }
  systemctl enable "wg-quick@${WG_IFACE}"

  # Guardar metadata
  echo "$server_ip" > "${WG_DIR}/.server_public_endpoint"
  echo "$wg_port"   > "${WG_DIR}/.server_port"
  echo "$dns_cli"   > "${WG_DIR}/.dns_for_clients"

  echo
  echo "Servidor listo en ${server_ip}:${wg_port}"
  echo "Red interna: ${WG_NET} (servidor ${SERVER_IP})"
  echo
}

list_clients() {
  grep -n "^\[Peer\]" -n "$WG_CONF" 2>/dev/null | sed 's/:.*//g' | while read -r ln; do
    name=$(sed -n "$((ln-1))p" "$WG_CONF" | sed 's/^# *Client: *//')
    [[ -n "$name" ]] && echo "$name"
  done
}

add_client() {
  if [[ ! -f "$WG_CONF" ]]; then
    echo "No existe ${WG_CONF}. Instalá primero el servidor."
    return
  fi

  echo -n "Nombre del cliente (sin espacios): "
  read -r CLIENT
  [[ -z "${CLIENT:-}" ]] && { echo "Nombre inválido"; return; }
  if list_clients | grep -qx "$CLIENT"; then
    echo "Ya existe un cliente llamado '$CLIENT'."
    return
  fi

  # Tipo de cliente
  echo "Tipo de cliente:"
  echo "  [1] Normal (full-tunnel: 0.0.0.0/0, ::/0)"
  echo "  [2] Intranet-only (pedir CIDR(s), p.ej. 10.7.0.0/24,10.76.0.0/24)"
  echo "  [3] Gateway de LAN (anunciar LAN detrás de este peer en el servidor)"
  echo -n "Elegí [1/2/3]: "
  read -r TYPE
  [[ -z "${TYPE:-}" ]] && TYPE="1"

  # Asignar IP al cliente
  CLIENT_IP=$(next_free_ip) || { echo "No hay IPs libres en ${WG_NET}"; return; }

  # Claves cliente
  umask 077
  CLIENT_PRIV=$(wg genkey)
  CLIENT_PUB=$(printf "%s" "$CLIENT_PRIV" | wg pubkey)
  CLIENT_PSK=$(wg genpsk)

  SERVER_PUB=$(wg show "${WG_IFACE}" public-key)
  SERVER_ENDPOINT=$(cat "${WG_DIR}/.server_public_endpoint")
  SERVER_PORT=$(cat "${WG_DIR}/.server_port")
  DNS_CLI=$(cat "${WG_DIR}/.dns_for_clients")

  # AllowedIPs del CLIENTE
  ALLOWED_CLIENT="0.0.0.0/0, ::/0"
  LAN_CIDR=""
  if [[ "$TYPE" == "2" ]]; then
    echo "Ingresá CIDR(s) separados por coma, ej: 10.7.0.0/24,10.76.0.0/24"
    echo -n "AllowedIPs específicos: "
    read -r CIDRS
    # Normalizar y validar
    CIDRS=$(echo "$CIDRS" | tr -d ' ' )
    IFS=',' read -r -a arr <<< "$CIDRS"
    ok="yes"
    for c in "${arr[@]}"; do
      if ! is_ipv4_cidr "$c"; then ok="no"; fi
    done
    if [[ "$ok" != "yes" ]]; then
      echo "CIDR inválido. Cancelado."
      return
    fi
    ALLOWED_CLIENT="$CIDRS"
  elif [[ "$TYPE" == "3" ]]; then
    echo -n "LAN CIDR detrás de este gateway (ej: 10.76.0.0/24): "
    read -r LAN_CIDR
    if ! is_ipv4_cidr "$LAN_CIDR"; then
      echo "LAN_CIDR inválido. Cancelado."
      return
    fi
    # Para el cliente gateway, puede bastar con ver la red WG + su LAN si querés split
    ALLOWED_CLIENT="${WG_NET},${LAN_CIDR}"
  fi

  # Crear archivo de cliente
  CLIENT_FILE="/root/${CLIENT}.conf"
  cat > "$CLIENT_FILE" <<EOF
[Interface]
Address = ${CLIENT_IP}/24
DNS = ${DNS_CLI}
PrivateKey = ${CLIENT_PRIV}

[Peer]
PublicKey = ${SERVER_PUB}
PresharedKey = ${CLIENT_PSK}
AllowedIPs = ${ALLOWED_CLIENT}
Endpoint = ${SERVER_ENDPOINT}:${SERVER_PORT}
PersistentKeepalive = 25
EOF

  # Agregar peer al servidor
  backup_conf
  {
    echo "# Client: ${CLIENT}"
    echo "[Peer]"
    echo "PublicKey = ${CLIENT_PUB}"
    echo "PresharedKey = ${CLIENT_PSK}"
    # AllowedIPs del lado SERVIDOR SIEMPRE /32 del cliente
    if [[ "$TYPE" == "3" ]]; then
      # Gateway: anunciar también la LAN detrás de este peer
      echo "AllowedIPs = ${CLIENT_IP}/32, ${LAN_CIDR}"
    else
      echo "AllowedIPs = ${CLIENT_IP}/32"
    fi
    echo
  } >> "$WG_CONF"

  restart_wg

  echo
  echo "Cliente creado: ${CLIENT} (${CLIENT_IP})"
  echo "Archivo: ${CLIENT_FILE}"
  print_qr "$CLIENT_FILE"
  echo
  echo "TIPOS:"
  echo "  - Normal: el cliente sale a Internet por la VPN (full-tunnel) o por su red local (si cambiaste AllowedIPs)."
  echo "  - Intranet-only: alcanza solo las redes que pusiste en AllowedIPs."
  echo "  - Gateway de LAN: este peer anuncia ${LAN_CIDR} al servidor; recordá habilitar forwarding/NAT en esa máquina."
  echo
}

remove_client() {
  if [[ ! -f "$WG_CONF" ]]; then
    echo "No existe ${WG_CONF}."
    return
  fi
  echo "Clientes disponibles:"
  mapfile -t clients < <(list_clients)
  if ((${#clients[@]}==0)); then
    echo "No hay clientes."
    return
  fi
  local i=1
  for c in "${clients[@]}"; do
    echo "  $i) $c"
    i=$((i+1))
  done
  echo -n "Elegí cliente a borrar [número]: "
  read -r idx
  if ! [[ "$idx" =~ ^[0-9]+$ ]] || (( idx<1 || idx>${#clients[@]} )); then
    echo "Opción inválida."
    return
  fi
  target="${clients[$((idx-1))]}"

  backup_conf
  # Quitar bloque del peer y comentario "# Client: <name>"
  awk -v name="$target" '
    BEGIN{skip=0}
    {
      if ($0 ~ "^# Client: "name"$") {skip=1; next}
      if (skip==1 && $0 ~ /^\[Peer\]/) {skip=2; next}
      if (skip==2) {
        if ($0 ~ /^\[/) {skip=0; print $0}
        else next
      } else {
        print $0
      }
    }' "$WG_CONF" > "${WG_CONF}.tmp"

  mv "${WG_CONF}.tmp" "$WG_CONF"
  restart_wg
  rm -f "/root/${target}.conf"

  echo "Cliente '${target}' eliminado."
}

uninstall_all() {
  echo "Esto va a DESINSTALAR WireGuard del sistema. ¿Continuar? (y/n)"
  read -r ans
  [[ "$ans" != "y" ]] && { echo "Cancelado."; return; }

  systemctl disable --now "wg-quick@${WG_IFACE}" 2>/dev/null || true
  wg-quick down "${WG_IFACE}" 2>/dev/null || true

  # Backup final
  backup_conf

  rm -rf "$WG_DIR"
  apt purge -y wireguard wireguard-tools 2>/dev/null || true
  apt autoremove -y 2>/dev/null || true
  echo "Desinstalado. Backups en ${BACKUP_DIR}"
}

menu() {
  echo "========= WireGuard Manager ========="
  echo "1) Instalar/Configurar servidor"
  echo "2) Agregar cliente"
  echo "3) Eliminar cliente"
  echo "4) Mostrar estado (wg show)"
  echo "5) Reiniciar servicio"
  echo "6) Desinstalar todo"
  echo "0) Salir"
  echo "===================================="
  echo -n "Elegí: "
}

main() {
  ensure_root
  mkdir -p "$BACKUP_DIR"

  while true; do
    menu
    read -r opt
    case "$opt" in
      1) install_server ;;
      2) add_client ;;
      3) remove_client ;;
      4) wg show || echo "wg no está levantado" ;;
      5) restart_wg ;;
      6) uninstall_all ;;
      0) exit 0 ;;
      *) echo "Opción inválida" ;;
    esac
  done
}

main
