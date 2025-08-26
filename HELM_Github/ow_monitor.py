#!/usr/bin/env python3
import subprocess
import time
import os

THRIFT_PORT = 9090
POLL_INTERVAL = 0.2  # 每秒輪詢一次
PREV_OW = -1

# 建立資料夾
os.makedirs("result", exist_ok=True)

def read_ow_counter():
    try:
        cmd = f"register_read ow_counter 0"
        output = subprocess.check_output(
            ["simple_switch_CLI", "--thrift-port", str(THRIFT_PORT)],
            input=cmd.encode(),
            stderr=subprocess.DEVNULL
        ).decode()
        for line in output.splitlines():
            if "ow_counter[0]" in line:
                return int(line.split('=')[1].strip(), 0)
    except Exception:
        return None

def read_and_save_register(ow):
    try:
        cmd = "register_read dr_state 0"
        output = subprocess.check_output(
            ["simple_switch_CLI", "--thrift-port", str(THRIFT_PORT)],
            input=cmd.encode(),
            stderr=subprocess.DEVNULL
        ).decode()
        with open(f"result/{ow}.txt", "w") as f:
            f.write(output)
    except Exception as e:
        print(f"❌ 無法讀取 dr_state: {e}")

def launch_in_host(host, command):
    pid_output = subprocess.check_output(["pgrep", "-f", f"mininet:{host}"]).decode().strip()
    pid = pid_output.splitlines()[0]
    full_cmd = ["mnexec", "-a", pid, "bash", "-c", command]
    print(f"🚀 在 {host} 執行：{command}")
    return subprocess.Popen(full_cmd)

def kill_process_in_host(host, must_include_1, must_include_2):
    try:
        pid_output = subprocess.check_output(["pgrep", "-f", f"mininet:{host}"])
        host_pid = pid_output.decode().strip().splitlines()[0]

        all_lines = subprocess.check_output([
            "mnexec", "-a", host_pid, "pgrep", "-af", must_include_1
        ]).decode().strip().splitlines()

        for line in all_lines:
            pid, cmdline = line.split(' ', 1)
            if must_include_2 in cmdline and "bash" not in cmdline:
                subprocess.run(["mnexec", "-a", host_pid, "kill", pid], check=True)
                print(f"🛑 成功 kill {host} 中 PID={pid} 的行程")

    except subprocess.CalledProcessError:
        print(f"⚠️ 找不到或無法 kill {host} 中的目標行程")

def handle_window(ow):
    if ow == 0:
        launch_in_host("h1", "tcpreplay --intf1=eth0 --mbps=1 --loop=50 /pcap/mixed")
    elif ow >= 102:
        kill_process_in_host("h1", "tcpreplay", "mixed")
'''
    elif ow == 5:
        launch_in_host("h3", "tcpreplay --intf1=eth0 --mbps=5 --loop=9999999 /pcap/FE")
        launch_in_host("h2", "tcpreplay --intf1=eth0 --mbps=50 --loop=9999999 /pcap/ddos")
    elif 20 <= ow < 50:
        kill_process_in_host("h2", "tcpreplay", "ddos")
        kill_process_in_host("h3", "tcpreplay", "FE")
    elif ow == 50:
        launch_in_host("h2", "tcpreplay --intf1=eth0 --mbps=50 --loop=9999999 /pcap/ddos")
    elif 65 <= ow < 80:
        kill_process_in_host("h2", "tcpreplay", "ddos")
    elif ow == 80:
        launch_in_host("h3", "tcpreplay --intf1=eth0 --mbps=5 --loop=9999999 /pcap/FE")
    elif ow >= 95:
        kill_process_in_host("h3", "tcpreplay", "FE")
'''
def main():
    global PREV_OW
    while True:
        value = read_ow_counter()
        if value is not None and value != PREV_OW:
            print(f"✅ 觀察視窗切換：OW = {value}")
            handle_window(value)
            read_and_save_register(value)
            PREV_OW = value
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()

