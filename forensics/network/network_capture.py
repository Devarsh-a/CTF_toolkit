import os
import pyshark

# ===== CONFIGURATION =====
PCAP_FILE = "capture.pcap"
TLS_KEY_FILE = "sslkeys.log"  # Needed for HTTPS decryption
OUTPUT_DIR = "forensic_output"

# ===== HELPER FUNCTIONS =====
def ensure_dirs(*dirs):
    for d in dirs:
        os.makedirs(d, exist_ok=True)

def save_file(data, directory, prefix, ext):
    idx = len(os.listdir(directory)) + 1
    path = os.path.join(directory, f"{prefix}_{idx}.{ext}")
    with open(path, "wb") as f:
        f.write(data)

def save_text(data, directory, prefix="text"):
    save_file(data.encode("utf-8", errors="ignore"), directory, prefix, "txt")


# ===== BASE PROTOCOL CLASS =====
class ProtocolAnalyzer:
    def __init__(self, pcap_file, output_dir):
        self.pcap_file = pcap_file
        self.output_dir = output_dir
        ensure_dirs(output_dir)

    def analyze(self):
        raise NotImplementedError("Must implement analyze method for protocol analyzer.")


# ===== HTTP ANALYZER =====
class HTTPAnalyzer(ProtocolAnalyzer):
    def __init__(self, pcap_file, output_dir):
        super().__init__(pcap_file, os.path.join(output_dir, "http"))
        ensure_dirs(os.path.join(self.output_dir, "texts"),
                    os.path.join(self.output_dir, "images"),
                    os.path.join(self.output_dir, "pdfs"))

    def extract_urls(self, pkt):
        urls = []
        try:
            if hasattr(pkt, 'http'):
                host = getattr(pkt.http, 'host', None)
                uri = getattr(pkt.http, 'request_uri', None)
                if host and uri:
                    urls.append(f"http://{host}{uri}")
        except Exception:
            pass
        return urls

    def extract_payload(self, pkt):
        try:
            if hasattr(pkt.http, 'file_data'):
                return bytes.fromhex(pkt.http.file_data.replace(":", ""))
        except Exception:
            return None

    def analyze(self):
        print("[HTTP] Analyzing HTTP traffic...")
        cap = pyshark.FileCapture(self.pcap_file, display_filter="http")
        urls_found = set()
        text_count = 0
        image_count = 0
        pdf_count = 0
        for pkt in cap:
            urls_found.update(self.extract_urls(pkt))
            data = self.extract_payload(pkt)
            if data:
                try:
                    content_type = getattr(pkt.http, 'content_type', '').lower()
                    if "text" in content_type:
                        text_count += 1
                        save_text(data.decode("utf-8", errors="ignore"),
                                  os.path.join(self.output_dir, "texts"))
                    elif "image/jpeg" in content_type:
                        image_count += 1
                        save_file(data, os.path.join(self.output_dir, "images"), "image", "jpg")
                    elif "image/png" in content_type:
                        image_count += 1
                        save_file(data, os.path.join(self.output_dir, "images"), "image", "png")
                    elif "image/gif" in content_type:
                        image_count += 1
                        save_file(data, os.path.join(self.output_dir, "images"), "image", "gif")
                    elif "application/pdf" in content_type:
                        pdf_count += 1
                        save_file(data, os.path.join(self.output_dir, "pdfs"), "document", "pdf")
                except Exception:
                    continue
        # Save URLs
        with open(os.path.join(self.output_dir, "urls.txt"), "w") as f:
            for url in urls_found:
                f.write(url + "\n")
        print(f"[HTTP] URLs: {len(urls_found)}, Text: {text_count}, Images: {image_count}, PDFs: {pdf_count}")


# ===== HTTPS ANALYZER =====
class HTTPSAnalyzer(HTTPAnalyzer):
    def __init__(self, pcap_file, output_dir, tls_key_file):
        super().__init__(pcap_file, os.path.join(output_dir, "https"))
        self.tls_key_file = tls_key_file

    def analyze(self):
        if not os.path.exists(self.tls_key_file):
            print("[HTTPS] TLS key file not found, skipping HTTPS analysis.")
            return
        print("[HTTPS] Analyzing HTTPS traffic...")
        cap = pyshark.FileCapture(self.pcap_file, override_prefs={'tls.keylog_file': self.tls_key_file})
        urls_found = set()
        text_count = 0
        image_count = 0
        pdf_count = 0
        for pkt in cap:
            urls = self.extract_urls(pkt)
            urls_found.update([u.replace("http://", "https://") for u in urls])
            data = self.extract_payload(pkt)
            if data:
                try:
                    content_type = getattr(pkt.http, 'content_type', '').lower()
                    if "text" in content_type:
                        text_count += 1
                        save_text(data.decode("utf-8", errors="ignore"),
                                  os.path.join(self.output_dir, "texts"))
                    elif "image/jpeg" in content_type:
                        image_count += 1
                        save_file(data, os.path.join(self.output_dir, "images"), "image", "jpg")
                    elif "image/png" in content_type:
                        image_count += 1
                        save_file(data, os.path.join(self.output_dir, "images"), "image", "png")
                    elif "image/gif" in content_type:
                        image_count += 1
                        save_file(data, os.path.join(self.output_dir, "images"), "image", "gif")
                    elif "application/pdf" in content_type:
                        pdf_count += 1
                        save_file(data, os.path.join(self.output_dir, "pdfs"), "document", "pdf")
                except Exception:
                    continue
        with open(os.path.join(self.output_dir, "urls.txt"), "w") as f:
            for url in urls_found:
                f.write(url + "\n")
        print(f"[HTTPS] URLs: {len(urls_found)}, Text: {text_count}, Images: {image_count}, PDFs: {pdf_count}")


# ===== DNS ANALYZER =====
class DNSAnalyzer(ProtocolAnalyzer):
    def __init__(self, pcap_file, output_dir):
        super().__init__(pcap_file, os.path.join(output_dir, "dns"))

    def analyze(self):
        print("[DNS] Analyzing DNS traffic...")
        cap = pyshark.FileCapture(self.pcap_file, display_filter="dns")
        queries = set()
        for pkt in cap:
            try:
                if hasattr(pkt.dns, 'qry_name'):
                    queries.add(pkt.dns.qry_name)
            except Exception:
                continue
        with open(os.path.join(self.output_dir, "dns_queries.txt"), "w") as f:
            for q in queries:
                f.write(q + "\n")
        print(f"[DNS] Queries found: {len(queries)}")


# ===== FTP ANALYZER =====
class FTPAnalyzer(ProtocolAnalyzer):
    def __init__(self, pcap_file, output_dir):
        super().__init__(pcap_file, os.path.join(output_dir, "ftp"))

    def analyze(self):
        print("[FTP] Analyzing FTP traffic...")
        cap = pyshark.FileCapture(self.pcap_file, display_filter="ftp")
        commands = []
        for pkt in cap:
            try:
                if hasattr(pkt.ftp, 'request_command'):
                    arg = getattr(pkt.ftp, 'request_arg', '')
                    commands.append(f"{pkt.ftp.request_command} {arg}")
            except Exception:
                continue
        with open(os.path.join(self.output_dir, "ftp_commands.txt"), "w") as f:
            for cmd in commands:
                f.write(cmd + "\n")
        print(f"[FTP] Commands extracted: {len(commands)}")


# ===== SMTP ANALYZER =====
class SMTPAnalyzer(ProtocolAnalyzer):
    def __init__(self, pcap_file, output_dir):
        super().__init__(pcap_file, os.path.join(output_dir, "smtp"))

    def analyze(self):
        print("[SMTP] Analyzing SMTP traffic...")
        cap = pyshark.FileCapture(self.pcap_file, display_filter="smtp")
        email_count = 0
        for pkt in cap:
            try:
                if hasattr(pkt.smtp, 'req_command'):
                    email_count += 1
            except Exception:
                continue
        print(f"[SMTP] Emails/commands observed: {email_count}")


# ===== IMAP ANALYZER =====
class IMAPAnalyzer(ProtocolAnalyzer):
    def __init__(self, pcap_file, output_dir):
        super().__init__(pcap_file, os.path.join(output_dir, "imap"))

    def analyze(self):
        print("[IMAP] Analyzing IMAP traffic...")
        cap = pyshark.FileCapture(self.pcap_file, display_filter="imap")
        email_count = 0
        for pkt in cap:
            try:
                if hasattr(pkt.imap, 'request_line'):
                    email_count += 1
            except Exception:
                continue
        print(f"[IMAP] Emails/commands observed: {email_count}")


# ===== MAIN WORKFLOW =====
if __name__ == "__main__":
    analyzers = [
        HTTPAnalyzer(PCAP_FILE, OUTPUT_DIR),
        HTTPSAnalyzer(PCAP_FILE, OUTPUT_DIR, TLS_KEY_FILE),
        DNSAnalyzer(PCAP_FILE, OUTPUT_DIR),
        FTPAnalyzer(PCAP_FILE, OUTPUT_DIR),
        SMTPAnalyzer(PCAP_FILE, OUTPUT_DIR),
        IMAPAnalyzer(PCAP_FILE, OUTPUT_DIR)
    ]

    for analyzer in analyzers:
        analyzer.analyze()

    print("[*] Multi-protocol forensic extraction completed. All results are in 'forensic_output'.")