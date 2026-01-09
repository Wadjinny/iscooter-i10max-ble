import struct

def hexdump(b):
    return " ".join(f"{x:02x}" for x in b)

with open("btsnoop_hci.log", "rb") as f:
    data = f.read()

# btsnoop global header is 16 bytes
offset = 16
results = []

while offset + 24 < len(data):
    # btsnoop packet header (24 bytes)
    # uint32 len, uint32 len, uint32 flags, uint32 drops, uint64 timestamp
    orig_len, inc_len, flags, drops, ts = struct.unpack(
        ">IIIIQ", data[offset:offset+24]
    )
    offset += 24

    pkt = data[offset:offset+inc_len]
    offset += inc_len

    # Look for ATT Write Request (0x12) or Write Command (0x52)
    for i in range(len(pkt) - 5):
        opcode = pkt[i]
        if opcode in (0x12, 0x52):
            payload = pkt[i+1:]
            # Heuristic: look for packets with structure / ASCII digits
            if (
                b"\x30\x30\x30\x30\x30\x30" in payload or  # "000000"
                b"\x5a" in payload or                      # framed packets
                len(payload) <= 32
            ):
                results.append(payload)

# Deduplicate and print
unique = []
for r in results:
    if r not in unique:
        unique.append(r)

print("=== Extracted ATT write payloads ===\n")
for r in unique:
    print(hexdump(r))
