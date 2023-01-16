"""aes 128 cipher"""
from utils import s_box, rcon, inv_rcon, multiply2_matrix, multiply3_matrix, inv_s_box, multiply9_matrix, multiply11_matrix, multiply13_matrix, multiply14_matrix


def xor_strings(str1: str, str2: str) -> list[list[int]]:
    """takes 2 strings and return 4x4 matrix with xored string"""
    # append zeros to the end
    str1 = "{:<016s}".format(str1)
    str2 = "{:<016s}".format(str2)
    result = [[-1 for _ in range(4)] for _ in range(4)]
    str1_matrix = str2vert_matrix(str1)
    str2_matrix = str2vert_matrix(str2)
    for x in range(4):
        for y in range(4):
            result[x][y] = ord(str1_matrix[x][y]) ^ ord(str2_matrix[x][y])
    return result


def get_round_constant(round: int) -> int:
    """generates round constant for key expansion"""
    if round == 1:
        return 1
    if round > 1 and get_round_constant(round-1) < 0x80:
        return get_round_constant(round-1) * 2
    if round > 1 and get_round_constant(round-1) >= 0x80:
        return (get_round_constant(round-1) * 2) ^ 0x11b
    return 0


def key_expansion(key: list[list[int]]):
    """generates round keys for every round"""
    constants = [[get_round_constant(round)] +
                 [0x00]*3 for round in range(1, 11)]
    round_keys = [key]
    for round in range(10):
        key = [list(row) for row in round_keys[round]]
        newkey = [[-1 for _ in range(4)] for _ in range(4)]
        round_constant = constants[round]
        temp = key[0][3]
        for i in range(3):
            newkey[i][0] = key[i + 1][3]
        newkey[3][0] = temp
        hexed_key = matrix2hex(newkey)
        aes_hexed_key = hex_matrix_to_aes_hex_matrix(hexed_key)
        for i in range(4):
            row = int("0x" + aes_hexed_key[i][0][2:3], base=16)
            col = int("0x" + aes_hexed_key[i][0][3:4], base=16)
            newkey[i][0] = s_box[row][col]
        for i in range(4):
            newkey[i][0] ^= round_constant[i]
        for i in range(4):
            newkey[i][0] ^= key[i][0]
        for j in range(3):
            for i in range(4):
                newkey[i][j+1] = newkey[i][j] ^ key[i][j+1]
        round_keys.append(newkey)
    return round_keys


def xor_lists(list1: list[int], list2: list[int]) -> list[int]:
    """takes 2 lists and return list with xored values"""
    return [x ^ y for x, y in zip(list1, list2)]


def add_round_key(
    state: list[list[int]], roundkey: list[list[int]]
) -> list[list[int]]:
    add_round_key_matrix = [[-1 for _ in range(4)] for _ in range(4)]
    for y in range(4):
        for x in range(4):
            add_round_key_matrix[y][x] = state[y][x] ^ roundkey[y][x]
    return add_round_key_matrix


def str2vert_matrix(string: str) -> list[list[str]]:
    """takes string and writes it to matrix. if length of string is less than 16 it appends 0 to the end"""
    # append 0 to end of the string
    string = "{:<016s}".format(string)
    string_matrix = [["" for _ in range(4)] for _ in range(4)]
    for x in range(4):
        for y in range(4):
            string_matrix[x][y] = string[y * 4 + x]
    return string_matrix


def str2matrix(string: str):
    """takes string and writes it to matrix. if length of string is less than 16 it appends 0 to the end"""
    # append 0 to end of the string
    string = "{:<016s}".format(string)
    string_matrix = [[-1 for _ in range(4)] for _ in range(4)]
    for x in range(4):
        for y in range(4):
            string_matrix[x][y] = string[x * 4 + y]
    return string_matrix


def matrix2ascii(matrix: list[list[str]]) -> list[list[int]]:
    """takes string matrix and return int matrix with ascii values"""
    result = []
    for i in range(4):
        result.append([])
        for j in range(4):
            matrix[i][j] = ord(matrix[i][j])
    return matrix


def matrix2hex(matrix: list[list[int]]) -> list[list[str]]:
    """takes int 4x4 matrix and return 4x4 matrix with str hex values"""
    result = []
    for i in range(len(matrix[0])):
        result.append([])
        for j in range(len(matrix)):
            result[i].append(hex(matrix[i][j]))
    return result


def hex_matrix_to_aes_hex_matrix(matrix: list[list[str]]) -> list[list[str]]:
    """takes hex matrix and append zeros to the length 4 e.g. 0xf -> 0x0f"""
    aes_hex_matrix = [["" for _ in range(4)] for _ in range(4)]
    for x in range(len(matrix[0])):
        for y in range(len(matrix)):
            if len(matrix[y][x]) == 4:
                aes_hex_matrix[y][x] = matrix[y][x]
            else:
                aes_hex_matrix[y][x] = "0x0" + matrix[y][x][2]
    return aes_hex_matrix


def print_matrix(matrix, name="default name"):
    print("---print 2dimensional array " + name + "---")
    for i in matrix:
        print(i)
    print("---end print 2dimensional array " + name + "---\n")


def print_matrix_hex(matrix, name="default name"):
    print("---print 2dimensional array hex" + name + "---")
    for i in matrix:
        print(list(map(hex, i)))
    print("---end print 2dimensional array hex " + name + "---\n")


def sub_bytes(matrix: list[list[int]]) -> list[list[int]]:
    """aes bytes substitution"""
    hexed_matrix = matrix2hex(matrix)
    aes_hexed_matrix = hex_matrix_to_aes_hex_matrix(hexed_matrix)
    sub_bytes_matrix = [[-1 for _ in range(4)] for _ in range(4)]
    for y in range(4):
        for x in range(4):
            row = int("0x" + aes_hexed_matrix[y][x][2:3], base=16)
            col = int("0x" + aes_hexed_matrix[y][x][3:4], base=16)
            sub_bytes_matrix[y][x] = s_box[row][col]
    return sub_bytes_matrix


def inverse_sub_bytes(matrix: list[list[int]]):
    """for decryption"""
    hexed_matrix = matrix2hex(matrix)
    aes_hexed_matrix = hex_matrix_to_aes_hex_matrix(hexed_matrix)
    sub_bytes_matrix = [[-1 for _ in range(4)] for _ in range(4)]
    for y in range(4):
        for x in range(4):
            row = int("0x" + aes_hexed_matrix[y][x][2:3], base=16)
            col = int("0x" + aes_hexed_matrix[y][x][3:4], base=16)
            sub_bytes_matrix[y][x] = inv_s_box[row][col]
    return sub_bytes_matrix


def shift_rows(matrix):
    """aes shift rows"""
    matrix[1] = matrix[1][1:] + matrix[1][:1]
    matrix[2] = matrix[2][2:] + matrix[2][:2]
    matrix[3] = matrix[3][3:] + matrix[3][:3]
    return matrix


def multiply2(num: int) -> int:
    """aes GF multiplication by 2"""
    str_aes_hex_num = convert_hex_to_str_aes_hex(num)
    x = int(str_aes_hex_num[2], base=16)
    y = int(str_aes_hex_num[3], base=16)
    return multiply2_matrix[x][y]


def multiply3(num: int) -> int:
    """aes GF multiplication by 3"""
    x = int(convert_hex_to_str_aes_hex(num)[2], base=16)
    y = int(convert_hex_to_str_aes_hex(num)[3], base=16)
    return multiply3_matrix[x][y]


def multiply9(num: int) -> int:
    """aes GF multiplication by 9"""
    x = int(convert_hex_to_str_aes_hex(num)[2], base=16)
    y = int(convert_hex_to_str_aes_hex(num)[3], base=16)
    return multiply9_matrix[x][y]


def multiply11(num: int) -> int:
    """aes GF multiplication by 11"""
    x = int(convert_hex_to_str_aes_hex(num)[2], base=16)
    y = int(convert_hex_to_str_aes_hex(num)[3], base=16)
    return multiply11_matrix[x][y]


def multiply13(num: int) -> int:
    """aes GF multiplication by 13"""
    x = int(convert_hex_to_str_aes_hex(num)[2], base=16)
    y = int(convert_hex_to_str_aes_hex(num)[3], base=16)
    return multiply13_matrix[x][y]


def multiply14(num: int) -> int:
    """aes GF multiplication by 14"""
    x = int(convert_hex_to_str_aes_hex(num)[2], base=16)
    y = int(convert_hex_to_str_aes_hex(num)[3], base=16)
    return multiply14_matrix[x][y]


def convert_hex_to_str_aes_hex(num: int) -> str:
    if len(hex(num)) != 4:
        return "0x0" + hex(num)[2]
    else:
        return hex(num)


def mix_columns(matrix: list[list[int]]) -> list[list[int]]:
    result = [[-1 for _ in range(4)] for _ in range(4)]
    for x in range(4):
        for y in range(4):
            temp = []
            for rcon_xy in range(4):
                # cell_result ^= rcon[y][rcon_xy] * input_matrix[x][rcon_xy]
                if rcon[y][rcon_xy] == 2:
                    temp.append(multiply2(matrix[rcon_xy][x]))
                elif rcon[y][rcon_xy] == 3:
                    temp.append(multiply3(matrix[rcon_xy][x]))
                elif rcon[y][rcon_xy] == 1:
                    temp.append(matrix[rcon_xy][x])
                else:
                    print("mix columns rcon wrong value")
            result[y][x] = temp[0] ^ temp[1] ^ temp[2] ^ temp[3]
    return result


def inv_mix_columns(matrix: list[list[int]]):
    result = [[-1 for _ in range(4)] for _ in range(4)]
    for x in range(4):
        for y in range(4):
            temp = []
            for rcon_xy in range(4):
                # cell_result ^= rcon[y][rcon_xy] * input_matrix[x][rcon_xy]
                if inv_rcon[y][rcon_xy] == 14:
                    temp.append(multiply14(matrix[rcon_xy][x]))
                elif inv_rcon[y][rcon_xy] == 11:
                    temp.append(multiply11(matrix[rcon_xy][x]))
                elif inv_rcon[y][rcon_xy] == 13:
                    temp.append(multiply13(matrix[rcon_xy][x]))
                elif inv_rcon[y][rcon_xy] == 9:
                    temp.append(multiply9(matrix[rcon_xy][x]))
                elif inv_rcon[y][rcon_xy] == 1:
                    temp.append(matrix[rcon_xy][x])
                else:
                    print("mix columns rcon wrong value")
            result[y][x] = temp[0] ^ temp[1] ^ temp[2] ^ temp[3]
    return result


def encrypt(text: str, key: str) -> str:
    text_matrix = str2vert_matrix(text)
    key_matrix = str2vert_matrix(key)
    text_ascii_matrix = matrix2ascii(text_matrix)
    key_ascii_matrix = matrix2ascii(key_matrix)
    round_keys = key_expansion(key_ascii_matrix)
    state = text_ascii_matrix
    state = add_round_key(state, round_keys[0])
    for i in range(10):
        state = sub_bytes(state)
        state = shift_rows(state)
        if i != 9:
            state = mix_columns(state)
        state = add_round_key(state, round_keys[i+1])
    return state


def inverse_shift_rows(matrix):
    """for decryption"""
    matrix[1] = matrix[1][3:] + matrix[1][:3]
    matrix[2] = matrix[2][2:] + matrix[2][:2]
    matrix[3] = matrix[3][1:] + matrix[3][:1]
    return matrix


def matrix2text(matrix):
    text = 0
    for i in range(4):
        for j in range(4):
            text |= (matrix[i][j] << (120 - 8 * (4 * i + j)))
    return text


def decrypt(text: str, key: str) -> str:
    key_matrix = str2vert_matrix(key)
    key_ascii_matrix = matrix2ascii(key_matrix)
    round_keys = key_expansion(key_ascii_matrix)
    state = text
    state = add_round_key(state, round_keys[10])
    state = inverse_shift_rows(state)
    state = inverse_sub_bytes(state)
    for i in range(9):
        state = add_round_key(state, round_keys[9-i])
        state = inv_mix_columns(state)
        state = inverse_shift_rows(state)
        state = inverse_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    result = ""
    for x in range(4):
        for y in range(4):
            result += chr(state[y][x])
    return result


if __name__ == "__main__":
    TEXT = "Two One Nine Two"
    KEY = "Thats my Kung Fu"
    enc_text = encrypt(TEXT, KEY)
    print(enc_text)
    print(decrypt(enc_text, KEY))
