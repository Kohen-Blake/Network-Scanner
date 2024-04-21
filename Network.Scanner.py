import scapy.all as scapy
import socket
import tkinter as tk
from tkinter import scrolledtext

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    # Using conf.L3socket to access layer 3
    answered_list, _ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False, iface="Ethernet")
    
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def scan_ports(ip, timeout=1):
    open_ports = []
    for port in range(1 , 65535):  # Scan ports 1 to 1023
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                open_ports.append(port)
        except:
            pass
    return open_ports

def print_results(clients_list, open_ports):
    result_text = "IP Address\t\tMAC Address\n"
    result_text += "-----------------------------------------\n"
    for client in clients_list:
        result_text += client["ip"] + "\t\t" + client["mac"] + "\n"
    result_text += "\nOpen Ports:\n"
    result_text += str(open_ports)
    return result_text

def on_scan_button_click():
    target_ip = "/24"  # Scan entire network
    
    clients = scan(target_ip)
    open_ports = scan_ports(target_ip)
    
    result = print_results(clients, open_ports)
    result_display.config(state=tk.NORMAL)  # Enable text modification
    result_display.delete(1.0, tk.END)  # Clear previous result
    result_display.insert(tk.END, result)
    result_display.config(state=tk.DISABLED)  # Disable text modification

# Create Tkinter window
window = tk.Tk()
window.title("Network Scanner")
window.configure(bg="#2e2e2e")

# Create widgets
scan_button = tk.Button(window, text="Scan", command=on_scan_button_click)
scan_button.pack(pady=10)
result_display = scrolledtext.ScrolledText(window, width=50, height=20, state=tk.DISABLED, bg="#404040", fg="white")  # Set foreground color to white
result_display.pack(padx=10, pady=5)

# Run Tkinter event loop
window.mainloop()
