import os

def generate_report(results, output_path):
    with open(output_path, "w") as report:
        report.write("==== STEGANOGRAPHY FORENSIC REPORT ====\n\n")
        for file, findings in results.items():
            report.write(f"File: {file}\n")
            if findings:
                for finding in findings:
                    report.write(f"  - {finding}\n")
            else:
                report.write("  - No suspicious indicators found.\n")
            report.write("\n")