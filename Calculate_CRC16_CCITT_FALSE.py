import sys
import re


def check_packet(user_input : str) -> tuple[bool, bytearray]:
    """
    Check validity of user input, and transform in bytearray
    """

    # Remove spaces
    packet_str = user_input.replace(" ", "")

    # Check if all hex digits
    def is_hex(s):
        return bool(re.match(r'^[0-9a-fA-F]+$', s))
    
    if not is_hex(packet_str):
        print("Wrong packet, not in HEX format\n")
        return False, bytearray(0)
    
    # Convert in byte array
    packet_byte = bytearray.fromhex(packet_str)

    return True, packet_byte



def crc16_ccitt_false(data: bytearray) -> bytearray:
    """
    Compute CRC 16 CCITT-False.
    Input and output are bytearrays
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x11021
            else:
                crc <<= 1
            crc &= 0xFFFF
    # Return the CRC as a 2-byte `bytearray`
    return bytearray([crc >> 8, crc & 0xFF])



def packet_add_crc(data: bytearray) -> bytearray:
    """
    Add CRC16-CCITT-False to packet end.
    Packet as bytearray
    """
    data = data + crc16_ccitt_false(data)

    return data



#======================= MAIN ================================================================

def main():

    PROGRAM_DESC = "Pass packet to compute CRC as string of hex. Spaces are ignored."
    EXAMPLE = 'Example: "a53200", or "a5 32 00"\n'
    print(f"\n{PROGRAM_DESC}\n{EXAMPLE}")


    while True:
        user_input = input("-q to exit, or enter a hex packet: ")

        # Exit
        if user_input == "-q":
            return

        # Check valid packet
        valid_packet, packet = check_packet(user_input)
        if valid_packet:
            print(f"Packet computed: {packet_add_crc(packet).hex()}\n")




if __name__ == "__main__":
    main()

















