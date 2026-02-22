var replacements = new Map();
var ranges = [];

function genRandString(size){
    var min = 0x30;
    var max = 0x7E;
    var str = "";
    for(var i = 0; i < size; i++){
        str += String.fromCharCode(Math.floor(Math.random() * (max - min)) + min);
    }
    return str.toLowerCase();
}

function setTaint(keyPath, valueName, value, ptr, size){
    if(value.toLowerCase().endsWith(".dll")){
        var replacement = genRandString(size / 2);

        replacements.set(replacement, {
            keyPath: keyPath,
            valueName: valueName,
            originalData: value,
            replacementData: replacement,
            ptr: ptr,
            size: size
        });

        ptr.writeUtf16String(replacement);
    }
}

function checkTaint(name){
    name = name.toLowerCase();
    if(replacements.has(name)){
        return replacements.get(name);
    }
}
