import sys
from spiffy_x import (
    HColor, ChatServer, ChatClient, clear, print_matrix_header,
    print_status, animate_intro
)

# --- MAIN MENU ---
def show_main_menu():
    animate_intro()
    print()
    print(f"{HColor.BRIGHT_GREEN}  ╔════════════════════════════════════╗{HColor.ENDC}")
    print(f"{HColor.BRIGHT_GREEN}  ║ {HColor.WHITE}[1]{HColor.GREEN} INITIALIZE SERVER NODE         {HColor.BRIGHT_GREEN}║{HColor.ENDC}")
    print(f"{HColor.BRIGHT_GREEN}  ║ {HColor.WHITE}[2]{HColor.GREEN} CONNECT TO UPLINK              {HColor.BRIGHT_GREEN}║{HColor.ENDC}")
    print(f"{HColor.BRIGHT_GREEN}  ╚════════════════════════════════════╝{HColor.ENDC}")
    print()
    return input(f"{HColor.BRIGHT_GREEN}  SELECT OPTION > {HColor.ENDC}").strip()

def main():
    choice = show_main_menu()
    
    if choice == '1':
        clear()
        server = ChatServer(port=5555) 
        server.start()
    
    elif choice == '2':
        clear()
        print_matrix_header()
        print()
        host = input(f"{HColor.CYAN}  TARGET IP [localhost]: {HColor.ENDC}").strip() or 'localhost'
        port_input = input(f"{HColor.CYAN}  TARGET PORT [5555]: {HColor.ENDC}").strip()
        port = int(port_input) if port_input else 5555
        
        key = input(f"{HColor.YELLOW}  ACCESS KEY: {HColor.ENDC}").strip()
        username = input(f"{HColor.CYAN}  CALLSIGN: {HColor.ENDC}").strip()
        
        if not key or not username:
            print_status("ERROR", "Key and Callsign required", "error")
            return
        
        # Pure CLI Client
        ChatClient(host, port, key, username).connect()
    
    else:
        print_status("ERROR", "Invalid Option", "error")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{HColor.RED}  [!] TERMINATED{HColor.ENDC}")
        sys.exit()