# main.py
import sys
from engine import encrypt, decrypt

def main():
    if len(sys.argv) < 5:
        print("Usage:")
        print("  python main.py <encrypt|decrypt> <cipher> <input_file> <output_file> [key] [--iv IV]")
        sys.exit(1)

    mode = sys.argv[1].lower()
    cipher_name = sys.argv[2].lower()
    input_file = sys.argv[3]
    output_file = sys.argv[4]
    key = sys.argv[5].encode() if len(sys.argv) > 5 else b""
    
    # Optional IV argument for AES-CBC
    iv = None
    if "--iv" in sys.argv:
        iv_index = sys.argv.index("--iv") + 1
        if iv_index < len(sys.argv):
            iv = sys.argv[iv_index].encode()

    # Read input file
    with open(input_file, "rb") as f:
        data = f.read()

    try:
        if mode == "encrypt":
            result = encrypt(data, cipher_name, key, iv=iv)
        elif mode == "decrypt":
            result = decrypt(data, cipher_name, key, iv=iv)
        else:
            print("Mode must be 'encrypt' or 'decrypt'")
            sys.exit(1)

        # Write output file
        with open(output_file, "wb") as f:
            f.write(result)

        print(f"{mode.capitalize()}ion complete. Output written to {output_file}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()