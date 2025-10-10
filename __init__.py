import os
import sys

def __init__():
    mode = str(input("Mode : "))
    modes = ["Public", "User", "Anonymous"]
    if mode not in modes:
        raise ValueError("Invalid mode")

    if mode == "Public":
        if hasattr(sys, 'base_prefix'):
            if sys.prefix != sys.base_prefix:
                if 'VIRTUAL_ENV' in os.environ:
                    os.system("python -m client")
                else:
                    print("Virtual Env Not Detected")
            else:
                print("Virtual Env Not Detected")

    elif mode == "User":
        print("User mode not implemented yet")
    elif mode == "Anonymous":
        if hasattr(sys, 'base_prefix'):
            if sys.prefix != sys.base_prefix:
                if 'VIRTUAL_ENV' in os.environ:
                    os.system("python -m Anonymous")
                else:
                    print("Virtual Env Not Detected")
            else:
                print("Virtual Env Not Detected")


if __name__ == "__main__":
    __init__()
