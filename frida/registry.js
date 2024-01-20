var pNtQueryValueKey = Module.findExportByName('ntdll.dll', 'NtQueryValueKey');
var pNtEnumerateValueKey = Module.findExportByName('ntdll.dll', 'NtEnumerateValueKey');
var pNtQueryKey = Module.findExportByName('ntdll.dll', 'NtQueryKey');
var pExpandEnvironmentStringsW = Module.findExportByName('kernelbase.dll', 'ExpandEnvironmentStringsW');

// Native functions
var fNtQueryKey = new NativeFunction(
    pNtQueryKey,
    "uint",
    [
        "pointer",
        "uint", 
        "pointer", 
        "uint",
        "pointer"
    ]
);

// Given an HKEY, identify the registry path
function getKeyPath(hKey)  {
    var pBuff = Memory.alloc(0x1000);
    var pRes = Memory.alloc(0x4);
    var result = fNtQueryKey(hKey, 3, pBuff, 0x1000, pRes);
    if(result == 0) { // STATUS_SUCCESS
        return(pBuff.add(4)).readUtf16String();
    } else {
        return;
    }
}

function expandEnvVariables(str){
    return str.toLowerCase()
        .replaceAll("%system%", "C:\\Windows\\System32")
        .replaceAll("%systemroot%", "C:\\Windows");
}

function readRegValue(type, ptr) {
    if(type == 0x1) { // REG_SZ
        var strVal = ptr.readUtf16String();
        return [{ 
            value: strVal, 
            ptr: ptr, 
            size: strVal.length * 2 
        }];
    } else if(type == 0x2) { // REG_EXPAND_SZ
        var strVal = ptr.readUtf16String();
        return [{ 
            value: expandEnvVariables(strVal),
            ptr: ptr,
            size: strVal.length * 2
        }];
    } else if(type == 0x7) { // REG_MULTI_SZ
        var arr = [];
        while(ptr.readU16() != 0){
            var strVal = ptr.readUtf16String();
            arr.push({
                value: strVal, 
                ptr: ptr, 
                size: strVal.length * 2 
            });
            ptr = ptr.add(strVal.length * 2 + 2)
        }
        return arr;
    } else {
        return [];
    }
}

function handleQueryResult(mode, data){
    if(mode == 1){ // data is a KEY_VALUE_FULL_INFORMATION 
        var dataOffset = data.add(8).readU32();
        var ptr = data.add(dataOffset);
        var type = data.add(4).readU32();
        return readRegValue(type, ptr);
    } else if(mode == 2) { // data is a KEY_VALUE_PARTIAL_INFORMATION 
        var ptr = data.add(12);
        var type = data.add(4).readU32();
        return readRegValue(type, ptr);
    } else if(mode > 2){
        send("huh...")
    }
    return []
}

Interceptor.attach(pNtQueryValueKey, {
    onEnter: function(args) {
        this.bPrintRes = false;
        
        var hkey = args[0];
        if(hkey && !args[3].isNull()) {
            this.path = getKeyPath(hkey);
            this.valueName = args[1].add(8).readPointer().readUtf16String();
            this.bPrintRes = true;
            this.mode = args[2];
            this.result = args[3];
        }
    },
    
    onLeave: function(retval) {
        if(this.bPrintRes) {
            if(retval.toInt32() == 0) {
                var keyData = handleQueryResult(this.mode, this.result);
                for(var i = 0; i < keyData.length; i++){
                    setTaint(this.path, this.valueName, keyData[i].value, keyData[i].ptr, keyData[i].size);
                }
            }
        }
    }
});

Interceptor.attach(pNtEnumerateValueKey, {
    onEnter: function(args) {
        this.bPrintRes = false;
        
        var hkey = args[0];
        if(hkey && !args[3].isNull()) {
            this.path = getKeyPath(hkey);
            this.bPrintRes = true;
            this.mode = args[2];
            this.result = args[3];
        }
    },
    
    onLeave: function(retval) {
        if(this.bPrintRes) {
            if(retval.toInt32() == 0) {
                var keyData = handleQueryResult(this.mode, this.result);
                var valueName = "unknown";
                if(this.mode == 1){
                    valueName = this.result.add(20).readUtf16String();
                }
                for(var i = 0; i < keyData.length; i++){
                    setTaint(this.path, valueName, keyData[i].value, keyData[i].ptr, keyData[i].size);
                }
            }
        }
    }
});

Interceptor.attach(pExpandEnvironmentStringsW, {
    onEnter: function(args) {
        this.allottedSpace = args[2];
        this.outputMem = args[1];
        this.input = args[0].readUtf16String();
    },
    onLeave: function() {
        var taintInfo = checkTaint(this.input);
        var taint = false;
        if(undefined !== taintInfo){
            taint = true;
            this.input = taintInfo.originalData;
        }

        var expanded = expandEnvVariables(this.input);
        var required = expanded.length + 1;
        if(required > this.allottedSpace){
            return required;
        }

        this.outputMem.writeUtf16String(expanded);

        if(taint){
            setTaint(taintInfo.keyPath, taintInfo.valueName, expanded, this.outputMem, required - 1)
        }

        return required;
    }
})