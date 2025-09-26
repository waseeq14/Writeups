# Config Editor — SnakeYAML Deserialization RCE

**Target:** Mobile Hacking Lab — _Config Editor_ (APK)

**Summary**

During static analysis of the Config Editor APK, I discovered an unsafe YAML deserialization flow using the SnakeYAML library combined with a legacy command execution utility. This results in remote code execution (RCE) on the device by deserializing attacker-controlled YAML that constructs and executes arbitrary Java commands.

---

## Environment

- APK: `config editor` (Mobile Hacking Lab challenge)
    
- Analysis tools: JADX (decompilation)
    
- Test environment: Android emulator
    

---

## Recon / Initial Observations

- I installed and launched the APK on an emulator. The app presents a minimal UI with two buttons: **Load** and **Save**.
    ![[Screenshot 2025-09-26 at 4.00.34 PM.png]]
- To understand the application behavior I decompiled the APK with JADX and inspected the main activity and related classes.
    

---

## Findings

1. **YAML parsing via SnakeYAML**
    
    - The app parses YAML files as part of its load/save functionality.
        
    - Investigation of the decompiled code revealed the SnakeYAML library is in use for parsing.
        ![[Screenshot 2025-09-26 at 4.01.19 PM.png]]
1. **LegacyCommandUtil — command execution sink**
    
    - Further analysis exposed an activity/class named `LegacyCommandUtil` which accepts a command and executes it.
        ![[Screenshot 2025-09-26 at 4.01.33 PM.png]]
    - The combination of a YAML parser and a class able to execute commands indicates a potentially exploitable deserialization path.
        
1. **Known SnakeYAML vulnerability**
    
    - The SnakeYAML `Constructor` class has known unsafe-deserialization behavior that can be abused to instantiate arbitrary Java types during YAML load, enabling code execution in certain conditions. (See SnakeYAML/CVE-2022-1471 for details.)
        

---

## Proof of Concept (PoC)

Using the YAML deserialization sink to instantiate and invoke the legacy command execution code, I used the following payload to command execution in the app's context:

```
!! com.mobilehackinglab.configeditor.LegacyCommandUtil [ "touch /data/data/com.mobilehackinglab.configeditor/files/haha.txt" ]
```

After supplying the above payload to the parser (via the app's Load functionality or by placing crafted YAML where the app reads it), a new file named `haha.txt` is created under the app's files directory, demonstrating successful command execution.
![[Screenshot 2025-09-26 at 4.03.24 PM.png]]

---

## Recommendations / Mitigations

1. **Update or replace SnakeYAML:** Upgrade to a patched version that addresses unsafe deserialization (or use a safer YAML library/configuration that disables arbitrary type construction). Use a restricted `Constructor` or `SafeConstructor` when parsing untrusted YAML.
    
2. **Remove or restrict legacy command functionality:** Avoid exposing any API that executes arbitrary shell commands. If needed for legacy reasons, restrict usage to tightly validated inputs and require explicit, safe command whitelisting.
    
3. **Input validation / denylist:** Treat YAML and other serialized inputs as untrusted. Implement strict validation and restrict deserialization to known-safe classes.


---

