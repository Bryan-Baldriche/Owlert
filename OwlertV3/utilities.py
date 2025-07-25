# Imports
import os
import platform

# Clear Screen - For when the Terminal is just too damn much to look at
def clear_screen():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

# User Input "if/else"
def user_input(prompt="🦉: "):
    while True:
        response = input(prompt).strip().lower()
        if response == "clear":
            clear_screen()
        elif response == "help":
            help_menu()
        elif response == "home":
            home_menu()
        elif response == "version":
            version = "Version 1.3"
            print(version)
        else:
            return response

# Help Menu / List of Commands
def help_menu():
    print("\n 🦉 Owlert Global Commands 🦉\n")
    print("Remember you can all upon these at any time!\n")
    print(">    [help]     > brings up Global Commands Menu ")
    print(">    [clear]    > wipes the terminal screen")
    print(">    [home]     > Bring up the home menu")
    print(">    [version]  > Bring up the current program version number")
    print(">    [exit]     > exit the program")

def home_menu():
    print("\n📡 Owlert Network Recon 📡\n")
    print("1. Host Subnet Discovery")
    print("2. Specific Port Host Discovery")
    print("3. Scan All Ports for Hosts (Incredibly Slow!)")
    print("4. Fast Subnet-Wide Scan (Common Ports Scan)")
    print("5. Service Enumeration")
    print("6. exit")
    print("\n type 'help' at anytime for a list of additional commands")
