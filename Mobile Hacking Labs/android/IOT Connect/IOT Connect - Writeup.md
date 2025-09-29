## Challenge: IOT Connect  

**Objective:** Gain the ability to turn on all devices (master switch) by bypassing the PIN check used by the app (either by reversing to recover the PIN or by hooking the check function at runtime).

---

## Summary 

Two effective ways to win this challenge:

1. **Reverse + brute-force the encrypted static key** — offline crypto attack on the hardcoded cipher text. Result: recovered integer key **`345`**, which decrypts the stored token to `"master_on"`. Use this `key` in an `adb shell am broadcast` to trigger the master switch.
    
2. **Runtime hook (Frida)** — instrument the app and force `Checker.check_key(...)` (or `decrypt(...)`) to return success. This avoids any cryptanalysis and works immediately on the running process.
    

I solved it using both approaches, I recommend doing the 2nd one (using frida) as it is relatively simpler instead of bruteforcing for the key.

---

# Environment & relevant findings

- App package: `com.mobilehackinglab.iotconnect`
    
- The app registers a runtime `BroadcastReceiver` for action `MASTER_ON`. The receiver reads an integer extra named `key` and calls `Checker.check_key(key)`. If true → `turnOnAllDevices()` updates many `SharedPreferences` keys to `true`.
    ![](../../res/Screenshot%202025-09-29%20at%201.24.51%20PM.png)
- Hardcoded cipher text: `OSnaALIWUkpOziVAMycaZQ==` (variable `ds` in `Checker`).
    ![](../../res/Screenshot%202025-09-29%20at%202.58.11%20PM.png)
- Crypto: `AES/ECB/PKCS5Padding`, key derived from string form of integer PIN left-justified into 16 bytes (e.g. `"345"` → bytes `33 34 35 00 ... 00`).
    
Files referenced in code:

- `CommunicationManager` — listens for `MASTER_ON` and calls `Checker.check_key`.
    
- `Checker` — decrypts `ds` using AES with a key generated from the integer PIN; returns true if plaintext equals `"master_on"`.
    

---

# Approach A — Reverse & brute-force the key 

## Rationale

`ds` is static and the key derivation is trivial (UTF-8 of the integer string padded/truncated to 16 bytes). This makes offline brute force trivial - try small integer ranges until AES decryption yields `"master_on"`.

## Steps performed

1. Implemented the `generateKey` logic in Python to mirror the app:
    
    - `key_bytes = str(key).encode('utf-8')` then pad with zero bytes up to 16 bytes.
        
2. Base64-decode `ds`, then use AES-ECB-128 to decrypt and PKCS#5 unpad.
    
3. Brute-forced `key` over `0..999999` (adjustable); stop when decrypted plaintext equals `"master_on"`.
    
## Python Script 

```python
from base64 import b64decode

from math import ceil

import sys


try:

from Crypto.Cipher import AES

except Exception:

try:

from Cryptodome.Cipher import AES

except Exception as e:

raise ImportError("pycryptodome not available in this environment. Install with: pip install pycryptodome") from e

  

CIPHERTEXT_B64 = "OSnaALIWUkpOziVAMycaZQ=="

TARGET_PLAINTEXT = b"master_on"

MAX_KEY = 999999

REPORT_EVERY = 100000

  

ct_bytes = b64decode(CIPHERTEXT_B64)

  

def generate_key_bytes(key_int: int) -> bytes:

s = str(key_int).encode('utf-8')

if len(s) >= 16:

return s[:16]

return s + b'\x00' * (16 - len(s))

  

def pkcs5_unpad(b: bytes) -> bytes:

if not b:

return b

pad_len = b[-1]

if pad_len < 1 or pad_len > 16:

raise ValueError("Invalid padding length")

if b[-pad_len:] != bytes([pad_len]) * pad_len:

raise ValueError("Invalid padding bytes")

return b[:-pad_len]

  

found = False

found_key = None

found_plain = None

  

for key in range(0, MAX_KEY+1):

if key % REPORT_EVERY == 0 and key != 0:

print(f"Checked up to {key}", flush=True)

key_bytes = generate_key_bytes(key)

cipher = AES.new(key_bytes, AES.MODE_ECB)

try:

dec = cipher.decrypt(ct_bytes)

try:

plain = pkcs5_unpad(dec)

except Exception:

continue

if plain == TARGET_PLAINTEXT:

found = True

found_key = key

found_plain = plain.decode('utf-8')

print(f"Found! key={key}, plaintext={found_plain}", flush=True)

break

except Exception:

continue

  

if not found:

print(f"No key found in range 0..{MAX_KEY}. Consider increasing MAX_KEY.", flush=True)

else:

print("Result:")

print(f" Key (int): {found_key}")

print(f" Key bytes (hex): {generate_key_bytes(found_key).hex()}")

print(f" Plaintext: {found_plain}")
```

## Result

 ![](../../res/Screenshot%202025-09-29%20at%202.48.42%20PM.png)

## Using the key

Start the app and send a broadcast:

```bash
adb shell am broadcast -a MASTER_ON --ei key 345
```

If successful, the app will log and toast that “All devices are turned on”, and `turnOnAllDevices()` writes `true` to each device preference.

---

# Approach B — Dynamic instrumentation (Frida hooking)

## Rationale

Runtime hooking avoids offline work. Replace `Checker.check_key()` (or `Checker.decrypt()`) implementation in memory to always return `true` (or return `"master_on"`), so any broadcast with any `key` will succeed.

## Two common strategies

1. Hook `check_key(int)` to always return `true`.
    
2. Hook `decrypt(ds, key)` to directly return the plaintext `"master_on"`.
    

Either approach is effective. I applied the first one.

## Frida script 

I wrote a simple js hooking script to modify the return value of `check_key` to always true.

```js
Java.perform(function(){

try{

var checker = Java.use("Checker");

checker.check_key.implementation = function(key){

send("[+] Checker called with key: " + key);

send("[+] Returning True. . .");

return true;

}

} catch (e){

send("[!] error: " + e);

}

})
```

## Hooking the method

![](../../res/Screenshot%202025-09-29%20at%202.44.12%20PM.png)
This spawns the app with the hook already loaded. 

## After hooking

You can send a broadcast with any key:
![](../../res/Screenshot%202025-09-29%20at%202.45.28%20PM.png)

The hooked `check_key` will return `true`, causing the master switch to activate.
![](../../res/Screenshot%202025-09-29%20at%202.45.42%20PM.png)
![](../../res/Screenshot%202025-09-29%20at%202.46.08%20PM.png)

AC is on brrrrrrr

