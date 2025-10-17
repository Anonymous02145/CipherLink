import os
import sys

def __init__():
    mode = str(input("Mode : "))
    modes = ["public", "user", "anonymous"]
    if mode.lower() not in modes:
        raise ValueError("Invalid mode")

    if mode == "public":
        if hasattr(sys, 'base_prefix'):
            if sys.prefix != sys.base_prefix:
                if 'VIRTUAL_ENV' in os.environ:
                    os.system("python -m client")
                else:
                    print("Virtual Env Not Detected")
                    print("Do you want to continue without virtual environment? (y/n) : ")
                    option = str(input("> "))
                    if option.lower() == "y":
                        os.system("python -m client")
                    elif option.lower() == "n":
                        print("Exiting...")
                        sys.exit()
                    else:
                        print("Invalid option")
                        sys.exit()
            else:
                print("Virtual Env Not Detected")
                print("Do you want to continue without virtual environment? (y/n) : ")
                option = str(input("> "))
                if option.lower() == "y":
                    os.system("python -m client")
                elif option.lower() == "n":
                    print("Exiting...")
                    sys.exit()
                else:
                    print("Invalid option")
                    sys.exit()

    elif mode == "user":
        print("User mode not implemented yet")
        print("Starting in Public Mode")
        if hasattr(sys, 'base_prefix'):
            if sys.prefix != sys.base_prefix:
                if 'VIRTUAL_ENV' in os.environ:
                    os.system("python -m client")
                else:
                    print("Virtual Env Not Detected")
                    print("Do you want to continue without virtual environment? (y/n) : ")
                    option = str(input("> "))
                    if option.lower() == "y":
                        os.system("python -m client")
                    elif option.lower() == "n":
                        print("Exiting...")
                        sys.exit()
                    else:
                        print("Invalid option")
                        sys.exit()
            else:
                print("Virtual Env Not Detected")
                print("Do you want to continue without virtual environment? (y/n) : ")
                option = str(input("> "))
                if option.lower() == "y":
                    os.system("python -m client")
                elif option.lower() == "n":
                    print("Exiting...")
                    sys.exit()
                else:
                    print("Invalid option")
                    sys.exit()

    elif mode == "anonymous":
        if hasattr(sys, 'base_prefix'):
            if sys.prefix != sys.base_prefix:
                if 'VIRTUAL_ENV' in os.environ:
                    os.system("python -m Anonymous")
                else:
                    print("Virtual Env Not Detected")
                    print("Do you want to continue without virtual environment? (y/n) : ")
                    option = str(input("> "))
                    if option.lower() == "y":
                        os.system("python -m Anonymous")
                    elif option.lower() == "n":
                        print("Exiting...")
                        sys.exit()
                    else:
                        print("Invalid option")
                        sys.exit()
            else:
                print("Virtual Env Not Detected")
                print("Do you want to continue without virtual environment? (y/n) : ")
                option = str(input("> "))
                if option.lower() == "y":
                    os.system("python -m Anonymous")
                elif option.lower() == "n":
                    print("Exiting...")
                    sys.exit()
                else:
                    print("Invalid option")
                    sys.exit()


if __name__ == "__main__":
    __init__()
