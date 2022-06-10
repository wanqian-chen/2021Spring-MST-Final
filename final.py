from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import random
import string
import easygui as g
import base64
from random import randint

def miller_rabin(p):
    '''  Miller Rabin算法，判断是否是素数（概率判断）

    :param p: 待判断的数
    :return: True则大概率是素数，False则不是素数
    '''
    if p == 1: return False
    if p == 2: return True
    if p % 2 == 0: return False
    m, k, = p - 1, 0
    while m % 2 == 0:
        m, k = m // 2, k + 1
    a = randint(2, p - 1)
    x = pow(a, m, p)
    if x == 1 or x == p - 1: return True
    while k > 1:
        x = pow(x, 2, p)
        if x == 1: return False
        if x == p - 1: return True
        k = k - 1
    return False

def Is_prime(p, r = 40):
    ''' 判断是否为素数（概率判断）

    :param p: 待判断的数
    :param r: 重复次数
    :return: True则大概率是素数，False则不是素数
    '''
    for i in range(r):
        if miller_rabin(p) == False:
            return False
    return True

def Prime(upper):
    ''' 寻找小于且值最接近upper的三个素数

    :param upper: 上限
    :return: 以列表形式存储的三个小于且值最接近upper的素数
    '''
    prime_3 = []
    for num in range(upper, 1, -1):  # 逆序寻找
        if Is_prime(num):
            prime_3.append(num)
            if len(prime_3) == 3:
                break
    return prime_3

def Get_GCD(b, c):
    ''' 获取两个数的最大公因数

    :param b: 数1
    :param c: 数2
    :return: 最大公因数
    '''
    remain = b % c
    while remain != 0:
        b = c
        c = remain
        remain = b % c
    return c

def Get_Coefficient(b, c):
    ''' 获取满足式子  1 = x * b + y * c 的系数x，y

    :param b: 数1
    :param c: 数2
    :return: 系数x，系数y
    '''
    if c == 0:
        return 1, 0
    else:
        q = b // c
        remainder = b % c
        x_t, y_t = Get_Coefficient(c, remainder)
        x, y = y_t, x_t - q * y_t
        return x, y

def Get_Inverse(b, c):
    ''' 求逆

    :param b: 数1
    :param c: 数2
    :return: m0为c模b的逆
    '''
    x, y = Get_Coefficient(b, c)
    # print("1 = ", x, "* ", a, " + ", y, " * ", b)
    m0 = y % b
    # print("inverse:", m0)
    return m0

def Remain():
    ''' 中国剩余定理求同余式唯一解   x ≡ a(mod m)

    :param r: 同余式数量
    :param a_all: 所有同余式中的a
    :param m_all: 所有同余式中的m
    :return: 唯一解
    '''
    x_all = ''
    for k in range(0, 4): # 分别对最早被拆分成的4份密钥进行处理
        r = 2
        a_all = []
        m_all = []

        # 对于每四分之一个密钥，一开始被拆分成了三个包，只需要其中两个包就可以得到原（四分之一）密钥
        for i in range(0, 2):
            file_name = 'key\\key_remain%d_%d.txt' % (k, i)
            with open(file_name, 'rb') as f:
                str_a_prime = f.read().decode()
                a = str_a_prime.split(',')[0]
                prime = str_a_prime.split(',')[1]
                a_all.append(int(a))
                m_all.append(int(prime))
                f.close()

        M = 1
        for m in m_all:
            M *= m
        x = 0
        for i in range(r):
            Mi = M / m_all[i]
            yi = Get_Inverse(m_all[i], Mi)
            x_t = (a_all[i] * Mi * yi)
            x += x_t
        x %= M
        x = int(x).to_bytes(4, byteorder='little', signed=True)
        x_all += str(x)[2:4]  # 将四份密钥组合起来
    x_all = x_all.encode()
    return x_all

def Remain_GetKey():
    '''  通过中国剩余定理分配密钥

    :return: 无
    '''
    with open('key\\key.txt', 'rb') as f:  # 读取key
        key_base64 = f.read()
        f.close()
    key = base64.decodebytes(key_base64)

    # 将密钥分成四块，便于之后计算
    key_4 = []
    for i in range(0, 4):
        key_4.append(key[i:i+2])

    k = 0
    for key in key_4:
        key_int = int.from_bytes(key, byteorder='little', signed=True)
        prime_3 = Prime(key_int)[::-1]  # 调整为从大到小
        while prime_3[0] * prime_3[1] <= key_int:
            prime_3 = Prime(key)[::-1]  # 判断是否满足可以使用中国剩余定理的条件

        # a ≡ key mod prime
        a = []
        for prime in prime_3:
            a.append(int(key_int % prime))

        # 以(a, prime) 的形式存储
        for i in range(0, len(prime_3)):
            file_name = 'key\\key_remain%d_%d.txt' % (k, i)
            with open(file_name, 'wb') as f:
                s = str(a[i]) + ',' + str(prime_3[i])
                f.write(s.encode())
                f.close()
        k += 1

    g.msgbox("中国剩余定理分配的密钥已成功写入‘key’文件夹下！")

def DesEncode():
    '''  DES加密

    :return: 无
    '''
    key = Remain()

    des = DES.new(key, DES.MODE_ECB)  # 生成DES对象

    # 交互界面：选择需要加密的文件
    msg = '请选择需要加密的文件'
    title = '加密'
    default = 'story.txt'
    file_type = '.txt'
    file = g.fileopenbox(msg, title, default, file_type)
    file_ts = open(file, 'rb')  # 需要加密的数据
    file_ts = file_ts.read()

    # 保存原文件长度
    lenth = len(file_ts)
    with open('key\\length.txt', 'wb') as f:
        f.write(str(lenth).encode())
        f.close()

    # DES加密，并写入txt
    encrypto_text = des.encrypt(pad(file_ts, 32))  # 被加密的数据需要为8字节的倍数
    msg_save = '请选择加密文件的保存路径'
    title_save = '加密'
    default_save = 'C:\\python\\'
    filepath_save_t = g.diropenbox(msg_save, title_save, default_save)
    filepath_save = filepath_save_t + '\encode.txt'
    with open(filepath_save, 'wb') as f:
        f.write(encrypto_text)
        f.close()

    g.msgbox("加密后数据已成功写入‘%s’！" % filepath_save)

def DesDecode():
    '''  DES解密

    :return: 无
    '''
    key = Remain()

    des = DES.new(key, DES.MODE_ECB)  # 生成DES对象

    # 读取文件应有长度
    with open('key\\length.txt', 'rb') as f:
        length = int(f.read())
        f.close()

    # 交互页面：选择需要解密的文件
    msg = '请选择需要解密的文件'
    title = '解密'
    default = 'encode.txt'
    file_type = '.txt'
    file = g.fileopenbox(msg, title, default, file_type)
    with open(file, 'rb') as f:
        encrypto_text = f.read()
        f.close()

    # DES解密，并写入ts
    decrrpto_text_t = des.decrypt(encrypto_text)
    decrrpto_text = decrrpto_text_t[:length]  # 去除之前补的字节
    msg_save = '请选择解密文件的保存路径'
    title_save = '解密'
    default_save = 'C:\\python\\'
    filepath_save_t = g.diropenbox(msg_save, title_save, default_save)
    filepath_save = filepath_save_t + '\decode.txt'
    with open(filepath_save, 'wb') as f:
        f.write(decrrpto_text)
        f.close()

    g.msgbox("解密后数据已成功写入‘%s’！" % filepath_save)

def DesKey():
    '''  生成密钥，并去除弱密钥和半弱密钥

    :return: 无
    '''
    # 弱密钥
    weak_key = ['0x0101010101010101',\
                '0xFEFEFEFEFEFEFEFE',\
                '0xE0E0E0E0F1F1F1F1',\
                '0x1F1F1F1F0E0E0E0E',\
                '0x0000000000000000',\
                '0xFFFFFFFFFFFFFFFF',\
                '0xE1E1E1E1F0F0F0F0',\
                '0x1E1E1E1E0F0F0F0F']

    # 半弱密钥
    halfweak_key = ['0x011F011F010E010E',\
                    '0x1F011F010E010E01',\
                    '0x01E001E001F101F1',\
                    '0xE001E001F101F101',\
                    '0x01FE01FE01FE01FE',\
                    '0xFE01FE01FE01FE01',\
                    '0x1FE01FE00EF10EF1',\
                    '0xE01FE01FF10EF10E',\
                    '0x1FFE1FFE0EFE0EFE',\
                    '0xFE1FFE1FFE0EFE0E',\
                    '0xE0FEE0FEF1FEF1FE',\
                    '0xFEE0FEE0FEF1FEF1']

    key = ''.join(random.sample(string.ascii_letters + string.digits, 8)).encode()  # key为8字节长度密钥

    # 去除弱密钥和半弱密钥
    while (key in weak_key) or (key in halfweak_key):
        key = ''.join(random.sample(string.ascii_letters + string.digits, 8)).encode()

    encode_64 = base64.encodebytes(key)
    with open('key\\key.txt', 'wb') as f:
        f.write(encode_64)
        f.close()

    g.msgbox("随机生成密钥：%s。成功保存进程序所在路径下‘key\\key.txt’文件！" % key)

def main():
    while 1:
        msg = '是否进入（继续）加解密程序?'
        title = '请选择'
        if g.ccbox(msg, title):  # ok,重新加密
            msg = "请选择所需功能，初次使用请先选择生成key！！\n\
            1.生成key：随机生成密钥（非弱密钥、半弱密钥)\n\
            2.中国剩余定理：通过中国剩余定理分配密钥\n\
            （分成3份，只要有其中两份就可解开）\n\
            3.DES加密：通过DES加密\n\
            4.DES解密：通过DES解密"

            title = "本次加解密使用的是DES！"  # 标题
            choices = ['生成key', '中国剩余定理', 'DES加密', 'DES解密']  # 选项
            choice = g.buttonbox(msg, title, choices)

            # 判断用户选择
            if str(choice) == '生成key':
                DesKey()
            elif str(choice) == '中国剩余定理':
                Remain_GetKey()
            elif str(choice) == 'DES加密':
                DesEncode()
            elif str(choice) == 'DES解密':
                DesDecode()
        else:
            break  # cancel,退出程序

    exit(0)

if __name__ == '__main__':
    main()
