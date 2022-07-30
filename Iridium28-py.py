import threading
import pcapy
import json
import parse_proto as pp


def package_handle(hdr, data):
    sniff_datas.append(data)


def xor(b_data, b_key):
    decrypt_data = b""
    for j in range(len(b_data)):
        decrypt_data += (b_data[j] ^ b_key[j % len(b_key)]).to_bytes(1, byteorder="big", signed=False)
    return decrypt_data


def remove_magic(b_data):
    try:
        cut1 = b_data[6]
        cut2 = b_data[5]
        b_data = b_data[8 + 2:]
        b_data = b_data[:len(b_data) - 2]
        b_data = b_data[cut2:]
        return b_data[cut1:]
    except IndexError:
        pass  # 特殊包


def get_packet_id(b_data):
    packet_id = int.from_bytes(b_data[2:4], byteorder="big", signed=False)
    return packet_id


def read_packet_id():
    f = open("packet_id.json", "r")
    d_packet_id = json.load(f)
    return d_packet_id


def get_proto_name_by_id(i_id):
    try:
        proto_name = d_pkt_id[str(i_id)]
        return proto_name
    except KeyError:
        return False


def sniff():
    while True:
        pcap.loop(1, package_handle)


def find_key():
    i = 0
    head = ""
    have_got_id_key = False
    # have_got_length_key = False
    have_got_data_key = False
    d_windseed = {}
    encrypted_windseed = b""
    while True:
        if i < len(sniff_datas) - 1:
            b_data = sniff_datas[i]
            b_data = b_data[42:]
            i += 1
            if have_got_data_key and have_got_id_key:
                frg = b_data[9]
                sn = int.from_bytes(b_data[16:20], byteorder="little", signed=False)
                una = int.from_bytes(b_data[20:24], byteorder="little", signed=False)
                if frg + sn == first_frg + first_sn and una == first_una:
                    if frg not in d_windseed:
                        d_windseed[frg] = b_data[28:]
                    else:
                        continue
                    frgs = list(d_windseed.keys())
                    if frgs[0] + 1 == len(frgs):
                        sorted_frgs = sorted(d_windseed.items(), key=lambda x: x[0], reverse=True)
                        t_data = list(zip(*sorted_frgs))[1]
                        for frg_data in t_data:
                            encrypted_windseed += frg_data
                        offset = len(encrypted_windseed) - 58207
                        full_key = xor(encrypted_windseed[offset:], windseed_text)
                        start_index = full_key.find(id_key)
                        end_index = full_key.find(id_key, start_index + 1)
                        decrypted_key = full_key[start_index:end_index]
                        pkg_parser = threading.Thread(target=parse, args=(decrypted_key,))
                        kcp_dealing = threading.Thread(target=handle_kcp, args=(id_key,))
                        pkg_parser.start()
                        kcp_dealing.start()
                        break
            else:
                if not head:
                    if len(b_data) > 20:
                        head = b_data[:2]
                    else:
                        continue

                if len(b_data) > 20:
                        # offset2 = int.from_bytes(xor(windseed_encrypt[6:7], length_key[2:3]), byteorder="big", signed=False)
                        # pkg_parser = threading.Thread(target=parse, args=(full_key,))
                        # pkg_parser.start()
                        # break
                    if not have_got_id_key:
                        b_data = b_data[28:]
                        if b_data.startswith(b"$\x8f") or b_data.startswith(head):
                            continue
                        else:
                            id_key = xor(b_data[:4], b"Eg\x00\x70")
                            if id_key:
                                have_got_id_key = True
                    else:
                        # if len(b_data) > 4 and not b_data.startswith(head):
                        packet_id = xor(b_data[28:32], id_key)
                        if packet_id == b"\x45\x67\x04\xaf":
                            first_frg = b_data[9]
                            first_sn = int.from_bytes(b_data[16:20], byteorder="little", signed=False)
                            first_una = int.from_bytes(b_data[20:24], byteorder="little", signed=False)
                            have_got_data_key = True
                            d_windseed[first_frg] = b_data[28:]


def parse(decrypt_key):
    i = 0
    while True:
        if i < len(packet) - 1:
            get = False
            try:
                if i > 50:
                    get = lock.acquire()
                    for j in range(50):
                        packet.pop(0)
                    i -= 50
            finally:
                if get:
                    lock.release()
            b_data = packet[i]
            i += 1
            b_data = xor(b_data, decrypt_key)
            packet_id = get_packet_id(b_data)
            proto_name = get_proto_name_by_id(packet_id)
            b_data = remove_magic(b_data)
            if proto_name:
                data = pp.parse(b_data, proto_name)
                print(proto_name, data)


def handle_kcp(id_key):
    i = 6
    while True:
        if i < len(sniff_datas) - 1:
            get = False
            try:
                if i > 100:
                    get = lock.acquire()
                    for j in range(100):
                        sniff_datas.pop(0)
                    i -= 100
            finally:
                if get:
                    lock.release()
            data = sniff_datas[i]
            i += 1
            data = data[42:]
            skip = False
            while len(data) != 0:
                length = int.from_bytes(data[24:28], byteorder="little", signed=False)
                if length == 0:
                    data = data[28:]
                    continue
                else:
                    head = xor(data[28:32], id_key)
                    if head.startswith(b"\x45\x67") and data[9] == 0:
                        packet.append(data[28:28 + length])
                        skip = True
                    else:
                        frg = data[9]
                        sn = int.from_bytes(data[16:20], byteorder="little", signed=False)
                        una = int.from_bytes(data[20:24], byteorder="little", signed=False)
                        if (una, frg + sn) in skip_packet:
                            skip = True
                        else:
                            skip = False
                            if head.startswith(b"\x45\x67"):
                                if una not in kcp:
                                    kcp[una] = {}
                                kcp[una][sn + frg] = {frg: data[28: 28 + length]}
                                # {3:{245:{36:data}}, 284:{:}}}
                            else:
                                # 啥玩意，中途换una
                                try:
                                    if frg in kcp[una][sn + frg]:
                                        skip = True
                                    else:
                                        kcp[una][sn + frg][frg] = data[28: 28 + length]
                                except KeyError:
                                    try:
                                        if frg in kcp[una - 1][sn + frg]:
                                            skip = True
                                        else:
                                            kcp[una - 1][sn + frg][frg] = data[28: 28 + length]
                                    except KeyError:
                                        skip = True
                    offset = length + 28
                    data = data[offset:]
            if not skip:
                remove = False
                for key1, value1 in kcp.items():
                    for key2, value2 in value1.items():
                        frgs = list(value2.keys())
                        if len(frgs) == frgs[0] + 1:
                            sorted_dict = sorted(value2.items(), key=lambda x: x[0], reverse=True)
                            t_data = list(zip(*sorted_dict))[1]
                            b_data = b""
                            for frg_data in t_data:
                                b_data += frg_data
                            packet.append(b_data)
                            skip_packet.append((key1, key2))
                            del kcp[key1][key2]
                            remove = True
                            break
                    if remove:
                        break


def read_windseed():
    f = open("plaintext.bin", "rb")
    b_windseed = f.read()
    return b_windseed


windseed_text = read_windseed()
d_pkt_id = read_packet_id()
sniff_datas = []
packet = []
skip_packet = []
kcp = {}
dev = "NPF_{46BA0BF2-6168-45EA-9476-F42ECD5D0EE5}"  # 自行修改
pkg_filter = "udp and port 22102 or port 22101"
lock = threading.Lock()
pcap = pcapy.open_live(dev, 1500, 0, 0)
pcap.setfilter(pkg_filter)
sniffer = threading.Thread(target=sniff)
key_finder = threading.Thread(target=find_key)
sniffer.start()
key_finder.start()


