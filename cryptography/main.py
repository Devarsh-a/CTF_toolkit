# main.py

import sys
from engine import encrypt, decrypt, analyze


def print_usage():
    print("Usage:")
    print("  python main.py encrypt <cipher> <input_file> <output_file> [key] [--iv IV]")
    print("  python main.py decrypt <cipher> <input_file> <output_file> [key] [--iv IV]")
    print("  python main.py analyze <input_file> <output_file>")
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print_usage()

    mode = sys.argv[1].lower()

    # ENCRYPT / DECRYPT MODE
    
    if mode in ("encrypt", "decrypt"):

        if len(sys.argv) < 5:
            print_usage()

        cipher_name = sys.argv[2].lower()
        input_file = sys.argv[3]
        output_file = sys.argv[4]
        key = sys.argv[5].encode() if len(sys.argv) > 5 else b""

        iv = None
        if "--iv" in sys.argv:
            iv_index = sys.argv.index("--iv") + 1
            if iv_index < len(sys.argv):
                iv = sys.argv[iv_index].encode()

        with open(input_file, "rb") as f:
            data = f.read()

        try:
            if mode == "encrypt":
                result = encrypt(data, cipher_name, key, iv=iv)
            else:
                result = decrypt(data, cipher_name, key, iv=iv)

            with open(output_file, "wb") as f:
                f.write(result)

            print(f"{mode.capitalize()}ion complete. Output written to {output_file}")

        except Exception as e:
            print(f"Error: {e}")

   
    # ANALYZE MODE (ML + Recursive)

    elif mode == "analyze":

        if len(sys.argv) < 4:
            print_usage()

        input_file = sys.argv[2]
        output_file = sys.argv[3]

        with open(input_file, "rb") as f:
            data = f.read()

        try:
            results = analyze(data)

            if not results:
                print("No decoding candidates found.")
                return

            best = results[0]

            decoded_text = best.decoded.decode(errors="ignore")
            chain = " -> ".join(best.chain())

            with open(output_file, "w", encoding="utf-8") as f:
                f.write("=== BEST CANDIDATE ===\n\n")
                f.write(decoded_text)
                f.write("\n\n=== DECODE CHAIN ===\n")
                f.write(chain)

            print(f"Analysis complete. Best result written to {output_file}")

        except Exception as e:
            print(f"Error during analysis: {e}")

    else:
        print_usage()


if __name__ == "__main__":
    main()