
# declaring the lists that are specified by the NIST
initial_permutation = [58, 50, 42, 34, 26, 18, 10, 2,
                      60, 52, 44, 36, 28, 20, 12, 4,
                      62, 54, 46, 38, 30, 22, 14, 6,
                      64, 56, 48, 40, 32, 24, 16, 8,
                      57, 49, 41, 33, 25, 17, 9, 1,
                      59, 51, 43, 35, 27, 19, 11, 3,
                      61, 53, 45, 37, 29, 21, 13, 5,
                      63, 55, 47, 39, 31, 23, 15, 7]

final_permutation =  [40, 8, 48, 16, 56, 24, 64, 32,
                     39, 7, 47, 15, 55, 23, 63, 31,
                     38, 6, 46, 14, 54, 22, 62, 30,
                     37, 5, 45, 13, 53, 21, 61, 29,
                     36, 4, 44, 12, 52, 20, 60, 28,
                     35, 3, 43, 11, 51, 19, 59, 27,
                     34, 2, 42, 10, 50, 18, 58, 26,
                     33, 1, 41, 9, 49, 17, 57, 25]

right_half_block_expansion_permutation = [32, 1, 2, 3, 4, 5,
                                         4, 5, 6, 7, 8, 9,
                                         8, 9, 10, 11, 12, 13,
                                         12, 13, 14, 15, 16, 17,
                                         16, 17, 18, 19, 20, 21,
                                         20, 21, 22, 23, 24, 25,
                                         24, 25, 26, 27, 28, 29,
                                         28, 29, 30, 31, 32, 1]

after_substitution_permutation =  [16, 7, 20, 21, 29, 12, 28, 17,
                                    1, 15, 23, 26, 5, 18, 31, 10,
                                    2, 8, 24, 14, 32, 27, 3, 9,
                                    19, 13, 30, 6, 22, 11, 4, 25]

key_initial_permutation = [57, 49, 41, 33, 25, 17, 9,
                            1, 58, 50, 42, 34, 26, 18,
                            10, 2, 59, 51, 43, 35, 27,
                            19, 11, 3, 60, 52, 44, 36,
                            63, 55, 47, 39, 31, 23, 15,
                            7, 62, 54, 46, 38, 30, 22,
                            14, 6, 61, 53, 45, 37, 29,
                            21, 13, 5, 28, 20, 12, 4]

shifted_key_permutation =  [14, 17, 11, 24, 1, 5, 3, 28,
                            15, 6, 21, 10, 23, 19, 12, 4,
                            26, 8, 16, 7, 27, 20, 13, 2,
                            41, 52, 31, 37, 47, 55, 30, 40,
                            51, 45, 33, 48, 44, 49, 39, 56,
                            34, 53, 46, 42, 50, 36, 29, 32]


# declaring the S-boxes that are specified by the NIST
sboxes = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]], [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]], [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]], [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]], [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]], [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]], [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]], [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]


# function to permute a list / block with a given permution table
def permute_func(block: list, permutation_table: list):
    return [block[position - 1] for position in permutation_table]

# for printing without needing to print the whole list
def list_to_hex(input_list):
    bin_str = ''.join(map(str, input_list))
    hex_val = hex(int(bin_str, 2))[2:]
    return hex_val

# function with 6 bits input to output the 4 bits that are given by the S-box lookup
def sbox_func(six_bit_input: list, s_box: list):
    # converting six bits to int
    six_bit_value = int("".join(map(str, six_bit_input)), 2)
    # bytes from row and column to ints
    row = ((six_bit_value & 0b100000) >> 4) | (six_bit_value & 0b000001)
    column = (six_bit_value >> 1) & 0b1111
    # lookup in sbox
    s_box_value = s_box[row][column]
    # return int in bits
    return [int(bit) for bit in f"{s_box_value:04b}"]


def sbox_right_side(binary_input: list) -> list:
    if len(binary_input) != 48:
        raise ValueError("Input must be exactly 48 bits long.")

    # split the binary list into 8 segments of 6 bits each
    segments = [binary_input[i:i + 6] for i in range(0, 48, 6)]
    i = 0
    # perform an operation on each segment (example: simply negate the bits)
    processed_segments = []
    for segment in segments:
        processed_segments.append(sbox_func(segment, sboxes[i]))
        i += 1
    

    # combine the processed segments back into a single list
    combined_result = [bit for segment in processed_segments for bit in segment]

    return combined_result





# padding to create a full block
def pad_pkcs7(data: bytes, block_size: int = 8) -> bytes:
    # if data is already a multiple of 8 bytes dont add padding
    print("2. Adding padding to the input")
    if not len(data) % 8:
        print(f"Padding not needed (input is a multiple of 8 bytes), total length : {len(data)}")
        return data

    # calculate the number of padding bytes needed
    padding_length = block_size - (len(data) % block_size)
    # create the padding
    padding = bytes([padding_length] * padding_length)
    # add padding to the data
    print(f"Added {padding_length} bytes of padding to get to a total length of {len(data + padding)}")
    
    return data + padding



def xor(list1, list2):
    return_list = []
    # very basic xor
    for i in range(0, len(list1)):
        if list1[i] == 1 and list2[i] == 1:
            return_list.append(0)
            continue
        if list1[i] == 1 and list2[i] == 0:
            return_list.append(1)
            continue
        if list1[i] == 0 and list2[i] == 1:
            return_list.append(1)
            continue
        if list1[i] == 0 and list2[i] == 0:
            return_list.append(0)
            continue
    return return_list


def divide_and_convert_to_binary(data: bytes, block_size: int = 8) -> list:
    # check that the data length is a multiple of block_size
    if len(data) % block_size != 0:
        raise ValueError("Data length must be a multiple of block_size (8 bytes for DES).")
    
    # process data into blocks and convert each block to binary representation
    binary_blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        binary_block = []
        for byte in block:
            # convert each byte to an 8-bit binary string and add each bit to the binary_block list
            binary_block.extend([int(bit) for bit in f"{byte:08b}"])
        binary_blocks.append(binary_block)
    print(f"\n\n3. Converting the padded text : {data}\nInto a lists of bits (64 bit blocks) {binary_blocks}")
    return binary_blocks



def prepare_blocks(input: str) -> list:
    #returns blocks
    return divide_and_convert_to_binary(pad_pkcs7(input.encode()))


def normalize_bit_array(array):
    byte_array = bytearray()
    
    # convert every 8 bits into a byte
    for i in range(0, len(array), 8):
        # take 8 bits at a time
        byte_bits = array[i:i + 8]
        # convert bits to an integer and then to a byte
        byte = sum(bit << (7 - j) for j, bit in enumerate(byte_bits))
        byte_array.append(byte)

    # return the result as a bytes object
    return bytes(byte_array)



def key_to_binary_list(data: str) -> list:
    # check if the length of the input string is exactly 8 bytes
    if len(data) != 8:
        raise ValueError("Input string must be exactly 8 characters (8 bytes).")
    
    # convert the string to bytes and then to a binary list
    binary_list = []
    for byte in data.encode('utf-8'):
        # convert each byte to an 8-bit binary string and add each bit to binary_list
        binary_list.extend([int(bit) for bit in f"{byte:08b}"])
    
    return binary_list




def left_shift(bits, n):
    return bits[n:] + bits[:n]

def generate_round_keys(key_64bit):
    shift_schedule = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # apply initial key permutation to create the initial 56-bit key
    print("\n\n4. Doing a permutation on the 64bit key with the initial_key_permutation List to get the 56bit key")
    
    key_56bit = permute_func(key_64bit, key_initial_permutation)

    print("Splitting the 56bit key into 2x28 bit keys")
    
    # split the 56-bit key into two 28-bit lists
    C, D = key_56bit[:28], key_56bit[28:] 

    # generate 16 round keys
    round_keys = []
    i = 1
    print(f"Shifting the keys following the key shifting schedule ({shift_schedule})\n\n")
    
    for shift in shift_schedule:
        # left shift C and D according to the shift schedule
        C, D = left_shift(C, shift), left_shift(D, shift)

        # combine C and D, then apply the shifted key permutation to get the 48-bit round key
        combined = C + D
        round_key = permute_func(combined, shifted_key_permutation)
        round_keys.append(round_key)
        print(f"Created a new round key ({i}): {hex(int(''.join(map(str, round_key)), 2))[2:]}")
        
        i += 1
    return round_keys




def main(input: str, encryption_key: str):
    # key to bits
    key_bits = key_to_binary_list(encryption_key)
    print("\n\n1. Converting the key into a binary list for processing")
    print(f"from : {encryption_key}\nTo : {key_bits}\n\n")
        # input to blocks / bits

    blocks_bits = prepare_blocks(input)
    # generate round keys from the "master" key
    round_keys = generate_round_keys(key_bits)

    blocks_bits_encrypted = []
    i = 0

    # all the encryption rounds
    for block in blocks_bits:
        i += 1
        print(f"\n\n\nBlock {i} before rounds : ",list_to_hex(block))
        # initial permutation
        permuted_block = permute_func(block=block, permutation_table=initial_permutation)
        print(f"Block {i} after initial permutation : ",list_to_hex(permuted_block))
        #split block
        left_side, right_side = permuted_block[:32], permuted_block[32:]
        print(f"Block {i} is split into 2 sides (left / right) : ",list_to_hex(left_side),"    ",list_to_hex(right_side),"\n")

        for rounds in range(16):
            # expand right block
            expanded_right_side = permute_func(right_side, right_half_block_expansion_permutation)
            # xor expanded right block with the current round key
            xored_right_side = xor(expanded_right_side, round_keys[rounds])
            # let the right side go through the sboxes 
            sboxed_right_side = sbox_right_side(xored_right_side)
            # permute again
            permuted_right_side = permute_func(sboxed_right_side, after_substitution_permutation)
            # now xor with the left half
            xored_right_side_permuted = xor(permuted_right_side, left_side)
            # swap right and left block
            left_side = xored_right_side_permuted

            if rounds != 15:
                left_side, right_side = right_side, xored_right_side_permuted
            print(f"Left and right (block {i}) side after round {rounds} : {list_to_hex(left_side)}     {list_to_hex(right_side)}")

        # after 16 rounds combine the right and left block
        full_block = left_side + right_side
        # permute for one last time and add to the encrypted bit list
        blocks_bits_encrypted += (permute_func(full_block, final_permutation))
        
        print(f"\nBlock {i} after all rounds : {list_to_hex((permute_func(full_block, final_permutation)))}\n")

    bytes_array = normalize_bit_array(blocks_bits_encrypted)
    
    return bytes_array


not_valid = True
print("Note : The program is in ECB mode")
while not_valid:
    inputtext = input("Text : ")
    try:
        master_key = input("Key (must be 8 bytes exact): ")
        if len(master_key) == 8:
            not_valid = False
    except KeyboardInterrupt:
        exit()
x = main(inputtext, master_key)
print("Ciphertext (bytes): ",x)
print("Ciphertext (hex)  :",x.hex())
print("Press Enter to quit")
input()
