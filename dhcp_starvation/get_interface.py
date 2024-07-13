import psutil
import ipaddress

def get_interface_for_target(target_ip, interface_guids):
    target_net = ipaddress.ip_network(target_ip + '/24', strict=False)  # Assuming a /24 subnet mask
    for iface in psutil.net_if_addrs():
        if iface in interface_guids:
            for addr in psutil.net_if_addrs()[iface]:
                if addr.family == psutil.AF_INET:
                    iface_ip = addr.address
                    iface_net = ipaddress.ip_network(iface_ip + '/24', strict=False)  # Assuming a /24 subnet mask
                    if target_net.overlaps(iface_net):
                        return iface
    return None

if __name__ == "__main__":
    target_ip = "192.168.1.1"
    interface_guids = [
        '{1AC9029D-DDDE-4497-917A-361BEA98596A}', '{9E1CF21C-E926-46B0-AA70-9DC1D38E0CB9}',
        '{93BF4183-8E82-4320-A967-E2B8504F25C9}', '{4B705380-B3D2-47CC-87BC-2917B746109D}',
        '{25C9C8D6-376B-4DE4-92A3-F2F1380158C8}', '{343CE8C0-716A-466D-AEA7-121E90F036F1}',
        '{BBC5E071-F520-482A-8EBE-C344707405BA}', '{D2CF99A7-71F6-4572-A2B5-6B78335D9ACC}',
        '{A8F204F3-DC59-45EC-9DC4-8211BBC4294C}', '\\Device\\NPF_Loopback',
        '{EAB62EB0-6CC2-45BA-AF0C-05712192B957}'
    ]
    interface = get_interface_for_target(target_ip, interface_guids)
    if interface:
        print(f"The interface to use for target IP {target_ip} is: {interface}")
    else:
        print(f"No suitable interface found for target IP {target_ip}")
