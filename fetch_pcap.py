import paramiko
import os
import time

server_ip = "192.168.0.38"
username = "zainab"
password = "zainab123"
remote_folder = "/var/pcap"
local_folder = "resources/pcap"

os.makedirs(local_folder, exist_ok=True)

# filename -> size at time of successful download
downloaded_files = {}  # changed from set to dict: {filename: size_when_downloaded}

# filename -> (last_seen_size, stable_count)
size_tracker = {}

STABLE_CHECKS_REQUIRED = 2
CHECK_INTERVAL = 5


def connect_ssh():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=server_ip, username=username, password=password, timeout=10)
    print("[INFO] Connected to SSH server")
    return ssh


def list_pcap_files_with_mtime_size(ssh):
    cmd = (
        f'echo "{password}" | sudo -S bash -c '
        f'"stat -c \'%Y %s %n\' {remote_folder}/*.pcap 2>/dev/null"'
    )
    stdin, stdout, stderr = ssh.exec_command(cmd)
    exit_code = stdout.channel.recv_exit_status()
    output = stdout.read().decode().strip()
    err = stderr.read().decode().strip()

    if exit_code != 0 and not output:
        print("[ERROR listing]")
        print(err)
        return []

    entries = []
    for line in output.splitlines():
        try:
            mtime_str, size_str, path = line.split(" ", 2)
            fname = os.path.basename(path.strip())
            if fname.endswith(".pcap"):
                entries.append((int(mtime_str), int(size_str), fname))
        except ValueError:
            continue

    entries.sort(key=lambda x: x[0])
    return entries


def download_file(ssh, file):
    remote_path = f"{remote_folder}/{file}"
    local_path = os.path.join(local_folder, file)
    print(f"\n[INFO] Downloading {file}")
    cmd = f'echo "{password}" | sudo -S cat "{remote_path}"'
    stdin, stdout, stderr = ssh.exec_command(cmd)
    stdout.channel.settimeout(60)
    try:
        with open(local_path, "wb") as f:
            while True:
                data = stdout.channel.recv(32768)
                if not data:
                    break
                f.write(data)
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            error = stderr.read().decode().strip()
            print(f"[ERROR] Failed to download {file}")
            print(error)
            if os.path.exists(local_path):
                os.remove(local_path)
            return False
        print(f"[SUCCESS] {file}")
        return True
    except Exception as e:
        print(f"[ERROR] {e}")
        if os.path.exists(local_path):
            os.remove(local_path)
        return False


def main():
    ssh = None
    while True:
        try:
            if ssh is None:
                ssh = connect_ssh()
                print("*****************")

            entries = list_pcap_files_with_mtime_size(ssh)

            if not entries:
                time.sleep(CHECK_INTERVAL)
                continue

            newest_mtime, newest_size, newest_file = entries[-1]
            candidate_files = [fname for _, _, fname in entries[:-1]]  # older ones, always safe

            # ---- stability check for newest file ----
            prev_size, stable_count = size_tracker.get(newest_file, (None, 0))
            if prev_size is not None and prev_size == newest_size:
                stable_count += 1
            else:
                stable_count = 0
            size_tracker[newest_file] = (newest_size, stable_count)

            if stable_count >= STABLE_CHECKS_REQUIRED:
                candidate_files.append(newest_file)

            # cleanup tracker for files that no longer exist
            current_sizes = {fname: size for _, size, fname in entries}
            for old_name in list(size_tracker.keys()):
                if old_name not in current_sizes:
                    size_tracker.pop(old_name, None)

            # ---- KEY FIX: re-check already-downloaded files too ----
            # agar kisi purani downloaded file ka size ab remote pe barh gaya
            # (matlab dobara likha gaya), tou usay re-download list mein daalo
            for fname, remote_size in current_sizes.items():
                if fname in downloaded_files and downloaded_files[fname] != remote_size:
                    print(f"[WARN] {fname} ka size change ho gaya hai "
                          f"({downloaded_files[fname]} -> {remote_size}). "
                          f"File dobara likhi gayi — re-downloading.")
                    downloaded_files.pop(fname, None)
                    # size_tracker bhi reset karo taake stability dobara verify ho
                    size_tracker.pop(fname, None)
                    if fname not in candidate_files:
                        candidate_files.append(fname)

            # ---- download loop ----
            for file in candidate_files:
                remote_size = current_sizes.get(file)
                if file not in downloaded_files:
                    if download_file(ssh, file):
                        downloaded_files[file] = remote_size
                time.sleep(2)

            time.sleep(CHECK_INTERVAL)

        except Exception as e:
            print(f"[LOOP ERROR] {e}")
            try:
                if ssh:
                    ssh.close()
            except:
                pass
            ssh = None
            size_tracker.clear()
            time.sleep(0)


if __name__ == "__main__":
    main()