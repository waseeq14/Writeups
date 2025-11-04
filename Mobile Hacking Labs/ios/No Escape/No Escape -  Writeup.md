## Overview

This was a simple jail break detection bypass challenge. I downloaded the `ipa` extracted it and analyzed the binary with radare2. I found few jail break detection methods:


![](../../res/210d29dbd6c038c006dcfa5228db52fa.png)


But all of them were being called inside a main detection function. Found its full mangled name using `nm`:

![](../../res/2d23ce3a8f91b78cec05c9b3a9355079.png)

Then just wrote a simple frida script to hook and replace the contents, bypassing all the logic.

### script.js
```js
const address = Module.findExportByName(null,"$s9No_Escape12isJailbrokenSbyF");

if (address){

console.log("[+] Found the function: ", address);

console.log("[+] Hooking. . . .");

Interceptor.replace(address, new NativeCallback(()=>{

console.log("[+] Bypassed!");

return 0;

},'int',[]));

};
```


### Flag
Upon bypassing the checks, we get the flag on the UI. But im too lazy to write it word by word so i decided to find the flag in the memory using objection.

![](../../res/bc43cd756f38031bb41fbba9f3bd8d96.png)

`MHL{hidin9_in_p1@in_5i9h+}`

