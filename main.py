import asyncio
import random
from bleak import BleakScanner, BleakClient

# --- CONFIG ---
TARGET_ADDRESS = "11:22:38:03:09:71"
LEGACY_PASSWORD = "000000"

# --- CONSTANTS ---
SERVICE_UUID = "6d581e70-15c6-11ec-82a8-0002a5d5c51b"
WRITE_UUID   = "6d581e71-15c6-11ec-82a8-0002a5d5c51b"
READ_UUID    = "6d581e74-15c6-11ec-82a8-0002a5d5c51b"

KEY = "9883222CD5B257133F3AC675A7132B44"
INV = "9E716E81E1A71CB524884953B2275BBD"
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

class Crypto:
    def __init__(self):
        self.key_tmp = [0] * 16
        self.bonding_hash = [0] * 4
        self.key = list(bytes.fromhex(KEY))
        self.inv = list(bytes.fromhex(INV))

    def sub_bytes(self, arr, length):
        for i in range(length):
            arr[i] = S_BOX[arr[i] & 0xFF]

    def generate_hash(self, nonce_hex):
        nonce = [int(nonce_hex[i:i+2], 16) for i in range(0, 12, 2)]
        c_arr = [0] * 32
        for i in range(6): c_arr[i] = nonce[i]
        for i in range(6): c_arr[i+6] = nonce[i]
        for i in range(4): c_arr[i+12] = nonce[i]
        for i in range(15): c_arr[i+16] = c_arr[i+1]
        c_arr[31] = c_arr[0]

        temp_key = [0] * 4
        self.key_tmp = self.key[:]
        self.sub_bytes(self.key_tmp, 16)
        temp_key = self.key_tmp[0:4]
        
        for c in range(12):
            self.key_tmp[c] = self.key_tmp[c+4]
        for i in range(4):
            self.key_tmp[12+i] = temp_key[i]

        for c in range(16):
            val = c_arr[c]
            i = val ^ self.key_tmp[c]
            c_arr[c] = i ^ self.inv[c]
            c_arr[c+16] = (self.key_tmp[c] ^ c_arr[c+16]) ^ self.inv[c]

        for c in range(1, 16):
            c_arr[c] = c_arr[c] ^ c_arr[c-1]
            c_arr[c+16] = c_arr[c+16] ^ c_arr[c+16-1]

        for c in range(4):
            self.bonding_hash[c] = (
                c_arr[c] ^ c_arr[c+4] ^ c_arr[c+8] ^ 
                (c_arr[c+12] + c_arr[c+16]) ^ 
                c_arr[c+20] ^ c_arr[c+24] ^ c_arr[c+28]
            ) & 0xFF
            
        return "".join([f"{x:02X}" for x in self.bonding_hash])

class ScooterController:
    def __init__(self, client):
        self.client = client
    
    async def send_command(self, sub_cmd, value):

        await self.send_raw_packet([0x03, 0x04, sub_cmd, 0x88, value, 0x00])

    async def send_raw_packet(self, payload):
        xor = 0xAA
        for b in payload:
            xor ^= b
        
        final_cmd = bytes([0xAA] + payload + [xor, 0xBB])
        print(f"CMD: {final_cmd.hex().upper()}")
        await self.client.write_gatt_char(WRITE_UUID, final_cmd)

    async def set_light(self, on):
        await self.send_command(0x02, 0x01 if on else 0x00)
    
    async def set_lock(self, locked):
        await self.send_command(0x04, 0x01 if locked else 0x00)
        
    async def set_mode(self, mode):
        # mode: 1=Eco, 2=Drive, 3=Sport
        await self.send_command(0x01, mode)
        
    async def set_unit(self, mph):
        # mph: True=MPH, False=KMH
        await self.send_command(0x03, 0x01 if mph else 0x00)
        
    async def set_cruise(self, on):
        await self.send_command(0x05, 0x01 if on else 0x00)
        
    async def set_zero_start(self, non_zero):
        # non_zero: True=Kick-to-start, False=Zero-start
        await self.send_command(0x06, 0x00 if non_zero else 0x01)

crypto = Crypto()
q = asyncio.Queue()

def notification_handler(sender, data):
    try:
        # Try decoding as string first (for debug/auth)
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            text = ""
        
        # Filter junk
        if text.isprintable() and len(text) > 1:
            print(f"Received (Str): {text}")
            q.put_nowait(text)
        
        # Binary Packet Parsing (AA ... BB)
        if len(data) >= 6 and data[0] == 0xAA and data[-1] == 0xBB:
            cmd_type = data[1]
            
            # 0xA1: Status (Speed, Battery, Mode)
            if cmd_type == 0xA1 and len(data) >= 10:
                battery = data[3]
                speed_raw = (data[4] << 8) | data[5]
                speed = speed_raw / 10.0
                mode = data[7] & 0x0F # Lower nibble seems to be mode
                
                mode_str = "Unknown"
                if mode == 0: mode_str = "Lock/Limit?"
                elif mode == 1: mode_str = "Eco"
                elif mode == 2: mode_str = "Drive"
                elif mode == 3: mode_str = "Sport"
                
                print(f"[Status] Speed: {speed:.1f} km/h | Battery: {battery}% | Mode: {mode_str}")

            # 0xA2: Trip/Odometer
            elif cmd_type == 0xA2 and len(data) >= 10:
                # Trip: High=data[4], Low=data[3]
                trip_raw = (data[4] << 8) | data[3]
                trip = trip_raw / 10.0
                
                # ODO: High=data[5], Mid=data[6], Low=data[7]
                # Note: Java code: ((b4 & 255) << 16) | ((b5 & 255) << 8) | (b2 & 255)
                # where b4=data[5], b5=data[6], b2=data[7]
                odo_raw = (data[5] << 16) | (data[6] << 8) | data[7]
                odo = odo_raw / 10.0
                
                print(f"[Trip/Odo] Trip: {trip:.1f} km | ODO: {odo:.1f} km")

            # 0xA3: Version Info
            elif cmd_type == 0xA3 and len(data) >= 6:
                sw_ver = data[4]
                hw_ver = data[5]
                print(f"[Version] Software: {sw_ver/10.0:.1f} | Hardware: {hw_ver/10.0:.1f}")
                # Byte 3 might be self-check flags?
                status_byte = data[3]
                if status_byte != 0:
                     print(f"[Status/Check] Flags: {status_byte:08b}")
            
            # 0x04: Speed Limit Response
            # SpeedLimitActivity: AA 04 [Len] [Gear] ... [5][6]==Limit ... BB
            elif cmd_type == 0x04:
                # data[0]=AA
                # data[1]=04
                # data[2]=04 (Maybe Sub-cmd/Length in other contexts, but here just bytes)
                # data[3]=Gear
                # data[4]=?
                # data[5]=Limit High
                # data[6]=Limit Low
                # data[7]=?
                # data[8]=BB
                
                if len(data) >= 9:
                    gear = data[3]
                    limit_raw = (data[5] << 8) | data[6]
                    limit = limit_raw / 10.0 # Activity divides by 10
                    
                    print(f"[SpeedLimit] Gear {gear}: {limit:.1f} km/h")
                else:
                     print(f"[SpeedLimit] Received short packet: {data.hex().upper()}")

            else:
                 print(f"Received (Hex): {data.hex().upper()}")

    except Exception as e:
        print(f"Error parsing packet: {e}")

async def run(address):
    print(f"Connecting to {address}...")
    async with BleakClient(address) as client:
        print(f"Connected: {client.is_connected}")
        
        await client.start_notify(READ_UUID, notification_handler)
        await asyncio.sleep(.1)
        
        # --- Authentication ---
        print("Authenticating...")
        await client.write_gatt_char(WRITE_UUID, b"+VER?")
        # await asyncio.sleep(0.5)
        
        # PM Handshake with Retry
        pm_auth_success = False
        for i in range(3):
            # Flush queue
            while not q.empty():
                try: q.get_nowait()
                except: pass
            
            print(f"Sending +PM? (Attempt {i+1}/3)")
            await client.write_gatt_char(WRITE_UUID, b"+PM?")
            
            try:
                while True:
                    msg = await asyncio.wait_for(q.get(), timeout=2.0)
                    if msg.startswith("+PM>"):
                        challenge = msg[4:].strip()
                        if challenge == "OK":
                            print("PM Authentication Successful")
                            pm_auth_success = True
                            break
                        else:
                            response_hash = crypto.generate_hash(challenge)
                            await client.write_gatt_char(WRITE_UUID, f"+PM<{response_hash}".encode())
                    elif "CODE" in msg:
                         pass
                
                if pm_auth_success:
                    break
            except asyncio.TimeoutError:
                print("Timeout waiting for PM response, retrying...")
        
        if not pm_auth_success:
            print("Warning: PM Authentication did not complete.")
        
        my_random_code = "".join([f"{random.randint(0, 255):02X}" for _ in range(6)])
        await client.write_gatt_char(WRITE_UUID, f"+PA<{my_random_code}".encode())
        await asyncio.sleep(0.1)
        
        await client.write_gatt_char(WRITE_UUID, f"CODE={LEGACY_PASSWORD}".encode())
        await asyncio.sleep(1)
        
        # --- Initialization ---
        await client.write_gatt_char(WRITE_UUID, b"GETDEVID")
        await asyncio.sleep(1)
        
        # Need to UNLOCK to ensure controls work
        print("Initializing (Unlocking)...")
        scooter = ScooterController(client)
        await scooter.set_lock(False)
        await asyncio.sleep(1)

        # --- DEMO ---
        print("\n--- DEMO START ---")
        
        print("Light ON")
        await scooter.set_light(True)
        await asyncio.sleep(2)
        
        print("Light OFF")
        await scooter.set_light(False)
        await asyncio.sleep(1)
        
        print("Setting Speed Mode 3 (Sport)")
        await scooter.set_mode(3)
        await asyncio.sleep(1)
        
        print("Setting Unit to KM/H")
        await scooter.set_unit(False)
        await asyncio.sleep(1)
        
        print("Disable Cruise Control")
        await scooter.set_cruise(False)
        await asyncio.sleep(1)
        
        print("Setting Zero Start ")
        await scooter.set_zero_start(False) 
        await asyncio.sleep(1)
        
        print("--- DEMO END ---")
        print("\nMonitoring scooter status for 15 seconds (Ctrl+C to stop)...")
        try:
            for _ in range(15):
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            pass
        
        print("Disconnecting...")

if __name__ == "__main__":
    try:
        asyncio.run(run(TARGET_ADDRESS))
    except KeyboardInterrupt:
        print("\nUser interrupted.")