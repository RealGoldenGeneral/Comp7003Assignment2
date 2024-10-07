from assign2 import PacketCapture
import sys

def main(interface, capture_filter, packet_count):
    try:
        count = int(packet_count)
        if count < 1:
            raise ValueError("Count cannot be less than 1.")
        if len(interface) == 0:
            pc = PacketCapture("eno1", capture_filter=capture_filter, packet_count=count)
        else:
            pc = PacketCapture(interface, capture_filter, count)
        pc.capture_packets()
    except Exception as e:
        print(e)

if __name__ == '__main__':
    if len(sys.argv) == 4:
        main(sys.argv[1], sys.argv[2], sys.argv[3])
    elif len(sys.argv) < 4:
        print("Not enough arguments.")
    elif len(sys.argv) > 4:
        print("too many arguments.")