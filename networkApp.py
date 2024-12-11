import scapy.all as scapy
from scapy.layers.inet import TCP, IP
import logging
import subprocess

# Налаштування логування
logging.basicConfig(
    filename="alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Правила для різних типів сканувань
SCAN_RULES = {
    "SYN": {
        "flag": 0x02,
        "message": "Виявлено SYN-сканування",
    },
    "Stealth": {
        "flag": 0x04,
        "message": "Виявлено приховане сканування",
    },
    "FIN": {
        "flag": 0x01,
        "message": "Виявлено FIN-сканування",
    },
    "NULL": {
        "flag": 0x00,
        "message": "Виявлено NULL-сканування",
    },
    "XMAS": {
        "flag": 0x29,
        "message": "Виявлено XMAS-сканування",
    },
}

# Функція для перевірки наявності правила для конкретного IP
def is_ip_blocked(ip):
    try:
        result = subprocess.run(
            ["sudo", "ufw", "status", "verbose"],
            capture_output=True,
            text=True
        )
        return f"from {ip}" in result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Помилка при перевірці заблокованого IP: {e}")
        return False

# Функція для перевірки наявності правила для конкретного порту
def is_port_blocked(port):
    try:
        result = subprocess.run(
            ["sudo", "ufw", "status", "verbose"],
            capture_output=True,
            text=True
        )
        return f"to any port {port}" in result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Помилка при перевірці заблокованого порту: {e}")
        return False


processed_scans = set()

# Функція для налаштування брандмауера на основі виявлених сканувань
def setup_firewall_on_scan(ip, port):
    # Створення унікального ідентифікатора для кожного IP і порту
    scan_id = f"{ip}:{port}"

    # Перевірка, чи було вже оброблене це сканування
    if scan_id in processed_scans:
        return  # Якщо сканування вже оброблено, нічого не робимо

    # Якщо сканування нове, додаємо його до набору оброблених
    processed_scans.add(scan_id)

    try:
        # Перевірка, чи IP вже заблокований
        if not is_ip_blocked(ip):
            print(f"[INFO] Блокування IP {ip} через виявлення сканування")
            subprocess.run(["sudo", "ufw", "deny", "from", ip],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            print(f"[INFO] IP {ip} вже заблоковано")

        # Перевірка, чи порт вже заблокований
        if not is_port_blocked(port):
            print(f"[INFO] Блокування порту {port} через виявлення сканування")
            subprocess.run(["sudo", "ufw", "deny", "to", "any", "port", str(port)],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            print(f"[INFO] Порт {port} вже заблоковано")

        # Додаткові блокування: заборонити вхідний трафік з певних IP
        blocked_ips = ["192.168.159.133", "192.168.159.134"]
        for blocked_ip in blocked_ips:
            if not is_ip_blocked(blocked_ip):
                print(f"[INFO] Блокування вхідного трафіку з IP {blocked_ip}")
                subprocess.run(["sudo", "ufw", "deny", "from", blocked_ip],
                               check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Обмежити доступ до певних портів
        blocked_ports = [80, 443]
        for blocked_port in blocked_ports:
            if not is_port_blocked(blocked_port):
                print(f"[INFO] Блокування доступу до порту {blocked_port}")
                subprocess.run(["sudo", "ufw", "deny", "to", "any", "port", str(blocked_port)],
                               check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Дозволити трафік лише з довірених IP
        trusted_ips = ["192.168.159.132"]
        for trusted_ip in trusted_ips:
            print(f"[INFO] Дозвіл трафіку з довіреного IP {trusted_ip}")
            subprocess.run(["sudo", "ufw", "allow", "from", trusted_ip],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Помилка при налаштуванні брандмауера: {e}")


# Функція для обробки сканувань
def detect_scan(packet):
    try:
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            ip_layer = packet.getlayer(IP)

            # Перевірка TCP сканувань згідно з правилами
            for scan_type, rule in SCAN_RULES.items():
                if tcp_layer.flags == rule["flag"]:
                    logging.info(f"[ALERT] {rule['message']} з {ip_layer.src} до порту {tcp_layer.dport}")
                    print(f"[ALERT] {rule['message']} з {ip_layer.src} до порту {tcp_layer.dport}")

                    # Налаштування брандмауера на основі виявленого сканування
                    setup_firewall_on_scan(ip_layer.src, tcp_layer.dport)
    except Exception as e:
        logging.error(f"[ERROR] Помилка при обробці пакета: {e}")

# Функція для початкового налаштування брандмауера
def setup_initial_firewall():
    try:
        # Вимкнення UFW (якщо вже увімкнений)
        subprocess.run(["sudo", "ufw", "disable"], check=True)

        # Очищення існуючих правил
        subprocess.run(["sudo", "ufw", "reset"], check=True)

        # За умовчанням дозволити всі вихідні з'єднання та блокувати всі вхідні
        subprocess.run(["sudo", "ufw", "default", "deny", "incoming"], check=True)
        subprocess.run(["sudo", "ufw", "default", "allow", "outgoing"], check=True)

        # Увімкнути UFW без попередніх блокувань
        subprocess.run(["sudo", "ufw", "enable"], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Помилка при налаштуванні брандмауера: {e}")

# Функція для початку захоплення пакетів
def start_sniffing():
    try:
        print(f"[INFO] Початок захоплення пакетів на інтерфейсі eth0...\n")
        scapy.sniff(iface="eth0", filter="tcp or icmp", prn=detect_scan)
    except Exception as e:
        logging.error(f"[ERROR] Помилка при захопленні пакетів: {e}")

if __name__ == "__main__":

    setup_initial_firewall()

    start_sniffing()


