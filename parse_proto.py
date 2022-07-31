import os
import re
import struct
import base64


def read_proto(file):
    try:
        f = open(file, "r")
        lines = f.readlines()
        f.close()
    except FileNotFoundError:
        print("找不到文件：" + file)
        return False
    proto_name = os.path.basename(file).split(".")[0]
    need_import = []
    enum_dict = {}
    return_dict = {}
    prop_name = {}
    message_return_dict = {}
    message_prop_name = {}
    other_message = {}
    save = False
    for line in lines:
        if line.startswith("import"):
            file_whole_name = re.findall(r'"(.*)"', re.split(" ", line)[1])[0]
            file_name = re.sub(".proto", "", file_whole_name)
            need_import.append(file_name)
        else:
            # 解的proto有时用\t有时用空格
            no_left_space_line = line.lstrip()
            split_line = re.split(" ", no_left_space_line)
            data_type = re.sub("\\t", "", split_line[0])

            if data_type == "}\n":
                save = False
                return_dict = {}
                prop_name = {}
                continue
            elif data_type == "message" or data_type == "enum":
                save = False
                return_dict = {}
                prop_name = {}
            if save:
                if save == "enum":  # 1个proto2个enum?自己改吧。
                    data_id = int(re.findall("\d+", split_line[2])[0])
                    enum_dict[data_id] = data_type
                else:
                    if len(split_line) > 3:  # 空行,忽略oneof
                        if len(split_line) == 4:
                            prop = split_line[1]
                            data_id = int(re.findall("\d+", split_line[3])[0])
                            return_dict[data_id] = data_type
                            prop_name[data_id] = prop
                        elif len(split_line) == 5:  # repeated and map
                            wire_type = re.sub("\\t", "", split_line[0])
                            if wire_type == "repeated":
                                data_type = split_line[1]
                                prop = split_line[2]
                                data_id = int(re.findall("\d+", split_line[4])[0])
                                return_dict[data_id] = "repeated_" + data_type
                                prop_name[data_id] = prop
                            else:
                                data_type = wire_type + split_line[1]
                                prop = split_line[2]
                                data_id = int(re.findall("\d+", split_line[4])[0])
                                return_dict[data_id] = data_type
                                prop_name[data_id] = prop
                    if save == "message":
                        message_return_dict = return_dict
                        message_prop_name = prop_name
                    else:
                        if save not in other_message:
                            other_message[save] = [{}, {}]
                        other_message[save][0].update(return_dict)
                        other_message[save][1].update(prop_name)
            else:
                if data_type == "message":
                    if split_line[1] == proto_name:
                        save = "message"
                    else:
                        save = split_line[1]
                    continue
                elif data_type == "enum":
                    save = "enum"
                else:
                    continue

    return need_import, enum_dict, message_return_dict, message_prop_name, other_message


def judge_type(prop_name):
    zero = ["int32", "int64", "uint32", "uint64", "sint32", "sint64", "bool", "enum"]
    one = ["fixed64", "sfixed64", "double"]
    five = ["fixed32", "sfixed32", "float"]
    if prop_name in zero:
        return 0
    elif prop_name in one:
        return 1
    elif prop_name in five:
        return 5
    else:
        return 2


def varint(now_location, byte_str):
    offset = 0
    data = byte_str[now_location] & 0b1111111
    while True:
        if byte_str[now_location] >> 7:
            offset += 1
            now_location += 1
            data = ((byte_str[now_location] & 0b1111111) << (7 * offset)) | data
        else:
            break
    return data, offset


def parse(byte_str, proto_name, *args):
    # len(args) == 2  传map的类型或嵌套message
    # len(args) == 3  传repeated的类型和data_id = 1
    # print(byte_str)
    # print(proto_name)
    file_path = os.getcwd()
    proto_name = file_path + "\proto\\" + proto_name + ".proto"
    need_import, enum_dict, encoding_rules, prop_name, other_message = read_proto(proto_name)
    # if not need_import and not need_import == []:
    #     return False
    if args:
        encoding_rules, prop_name = args[0], args[1]
    # else:
    #     encoding_rules, prop_name = read_proto(proto_name)
    decode_data = {}
    if len(args) == 3:
        list_decode_data = {"1": []}
    i = 0
    while i < len(byte_str) - 1:
        if len(args) == 3:
            data_id = args[2]
            data_type = judge_type(encoding_rules[data_id])
        else:
            data_type = byte_str[i] & 0b111
            data_id, offset = varint(i, byte_str)
            data_id >>= 3
            i += offset
            i += 1
        if data_id in encoding_rules:
            if data_type == 0:
                data, offset = varint(i, byte_str)
                if encoding_rules[data_id] == "bool":
                    data = bool(data)
                elif encoding_rules[data_id] in need_import:
                    enum_proto_name = file_path + "\proto\\" + encoding_rules[data_id] + ".proto"
                    enum_dict = read_proto(enum_proto_name)[1]
                    data = enum_dict[data]

                decode_data[prop_name[data_id]] = data
                i += offset
                i += 1
            elif data_type == 1:
                if encoding_rules[data_id] == "double":
                    decode_data[prop_name[data_id]] = struct.unpack("<d", byte_str[i:i + 8])[0]
                elif encoding_rules[data_id] == "sfixed64":
                    num = int.from_bytes(byte_str[i:i + 8], byteorder="little", signed=False)
                    decode_data[prop_name[data_id]] = num / 2 if num % 2 == 0 else -(num + 1) / 2
                elif encoding_rules[data_id] == "fixed64":
                    decode_data[prop_name[data_id]] = int.from_bytes(byte_str[i:i + 8], byteorder="little",
                                                                     signed=False)
                else:
                    decode_data[prop_name[data_id]] = "error"
                i += 8
            elif data_type == 5:
                if encoding_rules[data_id] == "float":
                    decode_data[prop_name[data_id]] = struct.unpack("<f", byte_str[i:i + 4])[0]
                elif encoding_rules[data_id] == "sfixed32":
                    num = int.from_bytes(byte_str[i:i + 4], byteorder="little", signed=False)
                    decode_data[prop_name[data_id]] = num / 2 if num % 2 == 0 else -(num + 1) / 2
                elif encoding_rules[data_id] == "fixed32":
                    decode_data[prop_name[data_id]] = int.from_bytes(byte_str[i:i + 4], byteorder="little",
                                                                     signed=False)
                # else:
                #     decode_data[prop_name[data_id]] = "error"
                i += 4
            elif data_type == 2:
                length, offset = varint(i, byte_str)
                i += offset
                i += 1
                if encoding_rules[data_id] == "string":
                    decode_data[prop_name[data_id]] = byte_str[i: i + length].decode()
                elif encoding_rules[data_id] == "bytes":
                    decode_data[prop_name[data_id]] = base64.b64encode(byte_str[i: i + length])
                elif encoding_rules[data_id].startswith("map<"):
                    if not prop_name[data_id] in decode_data:
                        decode_data[prop_name[data_id]] = []
                    type_dict = {}
                    map_private_prop_name = {}
                    type_name = re.findall("map<(.*)>", encoding_rules[data_id])[0]
                    type1, type2 = re.split(",", type_name)
                    type_dict[1] = type1
                    type_dict[2] = type2
                    map_private_prop_name[1] = "first"
                    map_private_prop_name[2] = "second"
                    map_proto_name = os.path.basename(proto_name).split(".")[0]
                    data = parse(byte_str[i:i + length], map_proto_name, type_dict, map_private_prop_name)
                    decode_data[prop_name[data_id]].append({data["first"]: data["second"]})
                elif encoding_rules[data_id].startswith("repeated_"):
                    rule = {}
                    repeated_name = {}
                    data_type = re.sub("repeated_", "", encoding_rules[data_id])
                    if data_type in need_import:
                        repeated_proto_name = data_type
                        data = parse(byte_str[i: i + length], repeated_proto_name)
                    else:
                        rule[1] = data_type
                        repeated_name[1] = "1"
                        repeated_proto_name = os.path.basename(proto_name).split(".")[0]
                        data = parse(byte_str[i: i + length], repeated_proto_name, rule, repeated_name, 1)
                    if not prop_name[data_id] in decode_data:
                        decode_data[prop_name[data_id]] = []
                    decode_data[prop_name[data_id]].append(data)
                elif encoding_rules[data_id] in need_import:
                    decode_data[prop_name[data_id]] = []
                    decode_data[prop_name[data_id]].append(parse(byte_str[i: i + length], encoding_rules[data_id]))
                elif encoding_rules[data_id] in other_message:
                    decode_data[prop_name[data_id]] = []
                    other_message_proto_name = os.path.basename(proto_name).split(".")[0]
                    decode_data[prop_name[data_id]].append(parse(byte_str[i: i + length], other_message_proto_name,
                                                                 other_message[encoding_rules[data_id]][0],
                                                                 other_message[encoding_rules[data_id]][1]))
                i += length
            else:
                print("protobuf该处字节解析失败：" + str(i))
            if len(args) == 3:
                list_decode_data["1"].append(decode_data["1"])
        # else:
        #     return decode_data
    if len(args) == 3:
        decode_data = list_decode_data["1"]
    return decode_data

