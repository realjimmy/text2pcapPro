#!/usr/bin/env python3
import sys
import argparse
import os
import configparser
import subprocess
from datetime import datetime
import re

"""
@Description: Tools for converting debugging information output from gdb, tcpdump into pcap packets (Python version)
@Author: realjimmy
"""

CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'settings.ini')
CONFIG_SECTION = 'text2pcap'
CONFIG_KEY = 'path'
OUTPUT_BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output')

# Global variable to control debug output
DEBUG_MODE = False

def print_logo():
    logo = """
 _            _   ____                          ___           
| |_ _____  _| |_|___ \ _ __   ___ __ _ _ __   / _ \_ __ ___  
| __/ _ \ \/ / __| __) | '_ \ / __/ _` | '_ \ / /_)/ '__/ _ \ 
| ||  __/>  <| |_ / __/| |_) | (_| (_| | |_) / ___/| | | (_) |
 \__\___/_/\_\\__|_____| .__/ \___\__,_| .__/\/    |_|  \___/ 
                       |_|             |_|                    
Author: realjimmy
"""
    print(logo)

def print_error(msg):
    print(f"❌ {msg}")

def print_info(msg):
    print(f"💡 {msg}")

def print_debug(msg):
    if DEBUG_MODE:
        print(f"🐛 {msg}")

def print_pass(msg):
    print(f"✅ {msg}")

def print_warn(msg):
    print(f"⚠️ {msg}")

def print_intput(msg):
    print(f"✏️ {msg}")

def ensure_config():
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)
    if not os.path.exists(CONFIG_FILE):
        config = configparser.ConfigParser()
        config[CONFIG_SECTION] = {CONFIG_KEY: ''}
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)

def get_text2pcap_path():
    ensure_config()
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    path = ''
    if config.has_section(CONFIG_SECTION):
        path = config[CONFIG_SECTION].get(CONFIG_KEY, '')
    # Check if current path is available
    if path and check_text2pcap_interactive(path):
        print_debug('Dependency program text2pcap path verification passed')
        return path
    # Try to use text2pcap directly from system PATH
    if check_text2pcap_interactive('text2pcap'):
        print_debug('Automatically updated dependency program text2pcap path')
        config[CONFIG_SECTION][CONFIG_KEY] = 'text2pcap'
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)
        return 'text2pcap'
    # Need user input
    while True:
        user_path = input('Please enter the directory containing text2pcap, or the full path to text2pcap: ').strip()
        if os.path.isdir(user_path):
            candidate_path = os.path.join(user_path, 'text2pcap')
        else:
            candidate_path = user_path
        if check_text2pcap_interactive(candidate_path):
            print_pass('Dependency program text2pcap path verification passed')
            config[CONFIG_SECTION][CONFIG_KEY] = candidate_path
            with open(CONFIG_FILE, 'w') as f:
                config.write(f)
            print_pass(f'Updated text2pcap path to: {candidate_path}')
            return candidate_path
        else:
            print_error('Invalid path or cannot execute, please re-enter.')

def check_text2pcap_interactive(path):
    """
    Check if text2pcap -v is available and determine if the output contains Text2pcap or Wireshark.
    If not included, give a warning and let the user choose whether to continue.
    """
    try:
        result = subprocess.run([path, '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        output = result.stdout.decode(errors='ignore') + result.stderr.decode(errors='ignore')
        if result.returncode != 0:
            return False
        if ('text2pcap' in output.lower()) or ('wireshark' in output.lower()):
            return True
        else:
            print_warn('Warning: The execution result of this path does not contain Text2pcap or Wireshark, may not be the correct text2pcap path.')
            while True:
                choice = input('Continue using this path? (y/n): ').strip().lower()
                if choice == 'y':
                    return True
                elif choice == 'n':
                    return False
    except Exception:
        return False

def get_output_file():
    """Generate output/date/ directory and unique filename, return full path"""
    today = datetime.now().strftime('%Y_%m_%d')
    out_dir = os.path.join(OUTPUT_BASE, today)
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    
    # Find existing sequence numbers, check all format files
    exist_files = os.listdir(out_dir)
    nums = []
    # Match files starting with numbers, support .txt and .pcap formats
    pattern = re.compile(r'^(\d+)_')
    for f in exist_files:
        m = pattern.match(f)
        if m:
            try:
                num = int(m.group(1))
                nums.append(num)
            except Exception:
                continue
    
    next_num = max(nums) + 1 if nums else 1
    filename = f'{next_num:02d}_pcap.txt'
    return os.path.join(out_dir, filename)

def gdb2pcap(content, output_file):
    wrong = []
    packets = []
    current_bytes = []
    empty_line_count = 0
    lines = content.splitlines()
    for idx, line in enumerate(lines):
        line = line.strip()
        if line == '':
            empty_line_count += 1
            # One empty line, as packet separator
            if current_bytes:
                packets.append(current_bytes)
                current_bytes = []
            continue
        else:
            empty_line_count = 0
        # If a line is all '-', also as packet separator
        if all(c == '-' for c in line):
            if current_bytes:
                packets.append(current_bytes)
                current_bytes = []
            continue
        # Skip comment lines
        if line.startswith('#'):
            continue
        words = line.split()
        for word in words:
            if word.startswith('---'):
                if current_bytes:
                    packets.append(current_bytes)
                    current_bytes = []
                continue
            if word.endswith(':'):
                continue
            if word.startswith('0x'):
                hex_value = word[2:]
                # Check validity
                if not (len(hex_value) == 2 and all(c in '0123456789abcdefABCDEF' for c in hex_value)):
                    wrong.append(word)
            else:
                hex_value = word
            current_bytes.append(hex_value)
    if current_bytes:
        packets.append(current_bytes)
    if wrong:
        print_error('Recognized as gdb format, but detected non-hex content')
        sys.exit(1)
    with open(output_file, 'w') as fout:
        for pkt in packets:
            for i, b in enumerate(pkt):
                if i % 16 == 0:
                    fout.write(f"{i:04x}   ")
                fout.write(f"{b} ")
                if (i+1) % 16 == 0:
                    fout.write("\n")
            fout.write("\r\n")  # Blank line between packets

def wireshark2pcap(content, output_file):
    wrong = []
    packets = []
    all_bytes = []
    for line in content.splitlines():
        line = line.strip()
        # Blank line as packet separator (same as ---)
        if line == '':
            if all_bytes:
                packets.append(all_bytes)
                all_bytes = []
            continue
        # If a line is all '-', it is a separator, start a new packet
        if all(c == '-' for c in line):
            if all_bytes:
                packets.append(all_bytes)
                all_bytes = []
            continue
        # If a line starts with #, it is a comment, skip
        if line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        # Skip address (first element)
        hex_bytes = parts[1:]
        for b in hex_bytes:
            if not (len(b) == 2 and all(c in '0123456789abcdefABCDEF' for c in b)):
                wrong.append(b)
        all_bytes.extend(hex_bytes)
    # Last packet
    if all_bytes:
        packets.append(all_bytes)
    if wrong:
        print_error('Recognized as wireshark format, but detected non-hex content')
        sys.exit(1)
    with open(output_file, 'w') as fout:
        for pkt in packets:
            for i, b in enumerate(pkt):
                if i % 16 == 0:
                    fout.write(f"{i:04x}   ")
                fout.write(f"{b} ")
                if (i+1) % 16 == 0:
                    fout.write("\n")
            fout.write("\r\n")  # Blank line between packets

def hex2pcap(content, output_file):
    packets = []
    current_bytes = []
    for line in content.splitlines():
        line = line.strip()
        # Blank line as packet separator (same as ---)
        if line == '':
            if current_bytes:
                packets.append(current_bytes)
                current_bytes = []
            continue
        # If a line is all '-', it is a separator, start a new packet
        if all(c == '-' for c in line):
            if current_bytes:
                packets.append(current_bytes)
                current_bytes = []
            continue
        # If a line starts with #, it is a comment, skip
        if line.startswith('#'):
            continue
        words = line.split()
        for b in words:
            current_bytes.append(b)
    if current_bytes:
        packets.append(current_bytes)
    with open(output_file, 'w') as fout:
        for pkt in packets:
            for i, b in enumerate(pkt):
                if i % 16 == 0:
                    fout.write(f"{i:04x}   ")
                fout.write(f"{b} ")
                if (i+1) % 16 == 0:
                    fout.write("\n")
            fout.write("\r\n")  # Blank line between packets

def judge_format(content):
    lines = [l for l in content.strip().splitlines() if l.strip()]
    if not lines:
        print_error('Error: Input content is empty')
        sys.exit(1)
    # Only keep valid data lines (remove comments, separators, blank lines)
    data_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if all(c == '-' for c in stripped):
            continue
        if stripped.startswith('#'):
            continue
        data_lines.append(line)
    if not data_lines:
        print_error('Error: No valid data lines')
        sys.exit(1)
    # Priority: if any line contains '>', treat as tcpdump
    for l in data_lines:
        if '>' in l:
            print_pass('Automatically recognized input content as tcpdump format (by >)')
            return 'tcpdump'
    # gdb format: starts with 0x, contains colon, and all after colon are 0x-prefixed bytes
    def is_gdb_line(l):
        l = l.strip()
        if not (l.startswith('0x') and ':' in l):
            return False
        parts = l.split(':', 1)[1].strip().split()
        # Allow lines with no data
        if not parts:
            return True
        return all(p.startswith('0x') and len(p) == 4 for p in parts if p)
    if all(is_gdb_line(l) for l in data_lines):
        print(f'\n')
        print_pass('Automatically recognized input content as gdb format')
        return 'gdb'
    # tcpdump format: starts with 0x, contains colon, all after colon are 2 or 4 hex digits (no 0x prefix)
    def is_tcpdump_line(l):
        l = l.strip()
        if not (l.startswith('0x') and ':' in l):
            return False
        parts = l.split(':', 1)[1].strip().split()
        # Allow lines with no data
        if not parts:
            return True
        return all((len(p) == 4 or len(p) == 2) and all(c in '0123456789abcdefABCDEF' for c in p) for p in parts if p)
    if all(is_tcpdump_line(l) for l in data_lines):
        print_pass('Automatically recognized input content as tcpdump format')
        return 'tcpdump'
    # wireshark format: 4-digit address at the beginning, followed by spaces, followed by hex, with colon
    ws_pat = re.compile(r'^[0-9a-fA-F]{4}\s{3,}([0-9a-fA-F]{2}\s+)+')
    if all(ws_pat.match(l.strip()) for l in data_lines):
        print_pass('Automatically recognized input content as wireshark format')
        return 'wireshark'
    # Suspected hex format: each line consists of several non-empty strings
    all_bytes = []
    for l in data_lines:
        all_bytes.extend(l.strip().split())
    if all_bytes:
        wrong = [b for b in all_bytes if not (len(b) == 2 and all(c in '0123456789abcdefABCDEF' for c in b))]
        if wrong:
            print_error('Recognized as hex format, but detected non-hex content')
            sys.exit(1)
        print_pass('Automatically recognized input content as hex format')
        return 'hex'
    print_error('Unable to recognize input format, please check input content!')
    sys.exit(1)

def detect_format(content):
    # 兼容老接口，直接调用新函数
    return judge_format(content)

# 新增tcpdump2pcap函数
def tcpdump2pcap(content, output_file):
    packets = []
    current_bytes = []
    for line in content.splitlines():
        line = line.strip()
        # Blank line as packet separator (same as ---)
        if line == '':
            if current_bytes:
                packets.append(current_bytes)
                current_bytes = []
            continue
        if all(c == '-' for c in line) or '>' in line:
            if current_bytes:
                packets.append(current_bytes)
                current_bytes = []
            continue
        if line.startswith('#'):
            continue
        if line.startswith('0x') and ':' in line:
            parts = line.split(':', 1)[1].strip().split()
            for word in parts:
                if len(word) == 4 and all(c in '0123456789abcdefABCDEF' for c in word):
                    current_bytes.append(word[:2])
                    current_bytes.append(word[2:])
                elif len(word) == 2 and all(c in '0123456789abcdefABCDEF' for c in word):
                    current_bytes.append(word)
        else:
            # Compatible with other lines
            words = line.split()
            for b in words:
                current_bytes.append(b)
    if current_bytes:
        packets.append(current_bytes)
    with open(output_file, 'w') as fout:
        for pkt in packets:
            for i, b in enumerate(pkt):
                if i % 16 == 0:
                    fout.write(f"{i:04x}   ")
                fout.write(f"{b} ")
                if (i+1) % 16 == 0:
                    fout.write("\n")
            fout.write("\r\n")  # Blank line between packets

def text2pcapPro():
    global DEBUG_MODE
    
    # Create a custom formatter for better help display
    class CustomHelpFormatter(argparse.HelpFormatter):
        def _format_action_invocation(self, action):
            if not action.option_strings:
                metavar, = self._metavar_formatter(action, action.dest)(1)
                return metavar
            else:
                parts = []
                if action.nargs == 0:
                    parts.extend(action.option_strings)
                else:
                    default = self._get_default_metavar_for_optional(action)
                    args_string = self._format_args(action, default)
                    for option_string in action.option_strings:
                        parts.append('%s %s' % (option_string, args_string))
                return ', '.join(parts)
    
    parser = argparse.ArgumentParser(
        description='Convert debugging information output from gdb, tcpdump, wireshark into pcap packets',
        epilog='''
Examples:
  # Interactive mode - input data manually
  python3 text2pcapPro.py
  
  # Read from file
  python3 text2pcapPro.py -r input.txt
  
  # Read from file and keep intermediate txt file
  python3 text2pcapPro.py -r input.txt --keep-txt
  
  # Enable debug output
  python3 text2pcapPro.py -d
  
  # Read from file with debug output
  python3 text2pcapPro.py -r input.txt -d

Supported input formats: GDB/Wireshark/Hex/TCPdump, input sample reference: unittest/ok_case/
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    
    # Add help option manually for better control
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                       help='Show this help message and exit')
    
    parser.add_argument('-r', '--read', type=str, metavar='FILE',
                       help='Read input from specified file instead of stdin')
    
    parser.add_argument('-d', '--debug', action='store_true',
                       help='Enable debug output for troubleshooting')
    
    parser.add_argument('--keep-txt', '-k', action='store_true',
                       help='Keep intermediate .txt file after generating .pcap')
    
    args = parser.parse_args()
    
    # Set debug mode
    DEBUG_MODE = args.debug
    
    text2pcap_path = get_text2pcap_path()
    
    # If it's file mode, execute only once
    if args.read:
        process_single_input(args.read, text2pcap_path, args.keep_txt, is_file=True)
        return
    
    # Interactive mode, loop execution
    while True:
        try:
            process_single_input(None, text2pcap_path, args.keep_txt, is_file=False)
            print("\n" + "="*50)
        except KeyboardInterrupt:
            print("\n\nProgram exited")
            return
        except Exception as e:
            print_error(f"Error occurred during processing: {e}")
            return

def process_single_input(input_file, text2pcap_path, keep_txt, is_file=False):
    """Process single input"""
    if is_file:
        try:
            with open(input_file, 'r') as fin:
                content = fin.read()
        except FileNotFoundError:
            print_error(f"File not found '{input_file}'")
            sys.exit(1)
        except PermissionError:
            print_error(f"No permission to read file '{input_file}'")
            sys.exit(1)
    else:
        print_info(" Input format instructions:")
        print("   1. Can be gdb/hex/tcpdump/wireshark format, see README.md for examples")
        print("   2. Multiple packets need to be separated by a blank line or --- on new lines")
        print("   3. Two consecutive empty lines represent end of input (you may need to press Enter up to 3 times)\n")
        print_intput(" Please enter packet capture text information:")

        try:
            lines = []
            empty_line_count = 0
            while True:
                line = input()
                if line.strip() == '':
                    empty_line_count += 1
                    if empty_line_count >= 2:
                        break
                else:
                    empty_line_count = 0
                lines.append(line)
            content = '\n'.join(lines)
        except KeyboardInterrupt:
            print("\nInput cancelled")
            sys.exit(0)
    
    # Check if input content is empty
    if not content.strip():
        print_error('Error: Input content is empty')
        return
    
    output_file = get_output_file()
    fmt = judge_format(content)
    if fmt == 'gdb':
        gdb2pcap(content, output_file)
    elif fmt == 'wireshark':
        wireshark2pcap(content, output_file)
    elif fmt == 'tcpdump':
        tcpdump2pcap(content, output_file)
    else:
        hex2pcap(content, output_file)
    
    # Automatically call text2pcap to generate pcap file
    pcap_file = output_file.replace('.txt', '.pcap')
    try:
        result = subprocess.run([text2pcap_path, output_file, pcap_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if result.returncode == 0:
            print_pass(f'pcap file generated: {pcap_file}')
            # If not keeping txt file, delete it
            if not keep_txt:
                try:
                    os.remove(output_file)
                    print_debug(f'Deleted intermediate file: {output_file}')
                except Exception as e:
                    print_warn(f'Failed to delete intermediate file: {e}')
        else:
            print_error('text2pcap execution failed:')
            print(result.stdout.decode(errors='ignore'))
            print(result.stderr.decode(errors='ignore'))
    except Exception as e:
        print_error(f'text2pcap execution exception: {e}')

if __name__ == "__main__":
    print_logo()
    text2pcapPro()