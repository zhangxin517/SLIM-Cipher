"""
Author: Zhang Xin & Rao Gang
Date: 2022/4/3
"""

from SLIM_struct import *
import re
import base64


def write_in_file(str_mess):
    try:
        f = open('SLIM.txt', 'w', encoding='utf-8')
        f.write(str_mess)
        f.close()
        print("文件输出成功！")
    except IOError:
        print('文件加解密出错！！！')


def read_out_file():
    try:
        f = open('SLIM.txt', 'r', encoding='utf-8')
        mess = f.read()
        f.close()
        print("文件读取成功！")
        return mess
    except IOError:
        print('文件加解密出错！！！')


def bytes2bin(message):
    res = ""
    for i in message:
        tmp = bin(i)[2:]
        for j in range(0, 8 - len(tmp)):
            tmp = '0' + tmp
        res += tmp
    return res


# 二进制转化为bytes
def bin2bytes(bin_str):
    res = b""
    tmp = re.findall(r'.{8}', bin_str)
    for i in tmp:
        t = int(i, 2)
        h = hex(t)[2:]
        if len(h) < 2:
            h = '0' + h
        res += bytes.fromhex(h)
    return res


# 字符串转化为二进制
def str2bin(message):
    res = ""
    for i in message:
        tmp = bin(ord(i))[2:]
        for j in range(0, 8 - len(tmp)):
            tmp = '0' + tmp
        res += tmp
    return res


# 二进制转化为字符串
def bin2str(bin_str):
    res = ""
    tmp = re.findall(r'.{8}', bin_str)
    for i in tmp:
        res += chr(int(i, 2))
    return res


# 字符串异或操作
def str_xor(my_str1, my_str2):
    res = ""
    for i in range(0, len(my_str1)):
        xor_res = int(my_str1[i], 10) ^ int(my_str2[i], 10)  # 变成10进制是转化成字符串 2进制与10进制异或结果一样，都是1,0
        if xor_res == 1:
            res += '1'
        if xor_res == 0:
            res += '0'
    return res


# 循环左移操作
def left_turn(my_str, num):
    left_res = my_str[num:len(my_str)]
    left_res += my_str[0:num]
    return left_res


def s_box(my_str):
    res = ''
    for i in S:
        res += my_str[i]
    return res


def p_box(my_str):
    res = ''
    for i in P:
        res += my_str[i]
    return res


def f_fun(r_bin_str, key):
    first_out = str_xor(r_bin_str, key)
    sec_out = s_box(first_out)
    third_out = p_box(sec_out)
    return third_out


def gen_key(key_80):
    key_list = []
    for i in range(4, -1, -1):
        key_list.append(key_80[i * 16:(i + 1) * 16])
    LSB = key_80[40:80]
    MSB = key_80[:40]
    for i in range(5, 32):
        tmp1 = left_turn(LSB, 2)
        tmp2 = str_xor(tmp1, MSB)
        tmp3 = s_box(tmp2)
        LSB = tmp3
        tmp4 = left_turn(MSB, 3)
        MSB = str_xor(tmp3, tmp4)
        key_list.append(MSB)
    return key_list


def one_encrypt(bin_message, bin_key):
    key_lst = gen_key(bin_key)
    left_mes = bin_message[0:16]
    right_mes = bin_message[16:32]
    for i in range(32):
        tmp = right_mes
        f_result = f_fun(tmp, key_lst[i])
        right_mes = str_xor(f_result, left_mes)
        left_mes = tmp
    fin_mes = left_mes + right_mes
    return fin_mes  # 01串


def one_decrypt(bin_message, bin_key):
    key_lst = gen_key(bin_key)
    right_mes = bin_message[0:16]
    left_mes = bin_message[16:32]
    for i in range(31, -1, -1):
        tmp = right_mes
        f_result = f_fun(tmp, key_lst[i])
        right_mes = str_xor(f_result, left_mes)
        left_mes = tmp
    fin_mes = right_mes + left_mes

    return fin_mes  # 01 串


# 简单判断以及处理信息分组
def deal_mess(bin_mess):
    """
    :param bin_mess: 二进制的信息流
    :return: 补充的32位信息流
    """
    ans = len(bin_mess)
    if ans % 32 != 0:
        for i in range(32 - (ans % 32)):  # 不够64位补充0
            bin_mess = '0' + bin_mess
    return bin_mess


# 查看秘钥是否为80位
def input_key_judge(bin_key):
    """
    全部秘钥以补0的方式实现长度不满足80位的
    :param bin_key:
    """
    ans = len(bin_key)
    if ans < 80:
        for i in range(80 - ans):  # 不够80位补充0
            bin_key += '0'
    else:
        bin_key = bin_key[0:80]  # 秘钥超过64位的情况默认就是应该跟密文一样长 直接将密钥变为跟明文一样的长度，虽然安全性会有所下降
    return bin_key


def all_message_encrypt(message: bytes, key):
    bin_mess = deal_mess(bytes2bin(message))
    res = ""
    bin_key = input_key_judge(str2bin(key))
    tmp = re.findall(r'.{32}', bin_mess)
    for i in tmp:
        res += one_encrypt(i, bin_key)

    return bin2bytes(res)


def all_message_decrypt(message: bytes, key):
    # bin_mess = deal_mess(bytes2bin(message))
    bin_mess = bytes2bin(message)
    res = ""
    bin_key = input_key_judge(str2bin(key))
    tmp = re.findall(r'.{32}', bin_mess)
    for i in tmp:
        res += one_decrypt(i, bin_key)

    tmp = res[:32]
    special = re.sub(r"([0]{8}){,3}", '', tmp, 1)
    res = special + res[32:]

    # tmp = re.findall(r'.{32}', res)
    # special = tmp[0]
    # special = re.sub(r"([0]{8}){,3}", '', special, 1)
    # res = special + ''.join(tmp[1:])

    return bin2bytes(res)


def get_mode():
    print("1.加密")
    print("2.解密")
    mode = input()
    if mode == '1':
        print("文件名：")
        message = input()
        file = open(message, encoding='utf-8')
        message = "".join(file.readlines())
        file.close()
        # f = open("a.txt", "r", encoding='utf-8')
        # lines = f.readlines()  # 读取全部内容 ，并以列表方式返回
        # message = ''.join(lines)

        print("请输入你的秘钥：")
        key = input()
        s = all_message_encrypt(message.encode("utf-8"), key)
        out_mess = base64.b64encode(s).decode("utf-8")
        print("加密过后的内容:" + out_mess)
        write_in_file(out_mess)
        # print(type(out_mess))
        # base_out_mess = base64.b64encode(out_mess.encode('utf-8'))
        # print("Base64编码过后:"+ base_out_mess.decode())
    elif mode == '2':
        # print("请输入信息输入字符串不能为空：")
        # message = input().replace(' ', '')
        print("请输入你的秘钥：")
        key = input()
        message = read_out_file()
        message = base64.b64decode(message.encode("utf-8"))
        s = all_message_decrypt(message, key)
        print(s.decode("utf-8"))
        file = open("result.txt", 'w', encoding='utf-8')
        file.write(s.decode("utf-8"))
        file.close()
        # s = base64.b64encode(s.encode('utf-8'))
        # out_mess = bin2str(s)
        # print(s.decode('utf-8'))
    else:
        print("请重新输入！")


if __name__ == '__main__':
    while True:
        get_mode()
