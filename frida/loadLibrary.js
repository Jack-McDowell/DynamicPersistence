// TODO: use a more robust load library detection (NtCreateSection?)
var pLoadLibraryExW = Module.findExportByName('Kernel32.dll', 'LoadLibraryExW');
var pLoadLibraryW = Module.findExportByName('Kernel32.dll', 'LoadLibraryW');
var pNtQueryAttributesFile = Module.findExportByName('ntdll.dll', 'NtQueryAttributesFile');

var registryLoads = new Set();
var hijacks = new Set();

function loadLibHandlerW (args) {
    var taintInfo = checkTaint(args[0].readUtf16String());
    if(undefined !== taintInfo){
        var foundString = "Library " + taintInfo.originalData + " loaded according to " + taintInfo.keyPath + " : " + taintInfo.valueName;
        if(!registryLoads.has(foundString)){
            registryLoads.add(foundString);
            send(foundString);
        }
        args[0].writeUtf16String(taintInfo.originalData);
        
    }
}

var queryFileHandler = {
    onEnter: function(args){
        this.attrs = args[0];
    },
    onLeave: function(retval){
        /* Fix this later; it should be retval === <ntstatus for file not found>
         * I just don't know off the top of my head which ntstatus value that is */
        if(retval != 0){
            var unicode_str = this.attrs.add(16).readPointer();
            var name = unicode_str.add(8).readPointer().readUtf16String();
            if(name.toLowerCase().endsWith(".dll")){
                if(!hijacks.has(name)){
                    hijacks.add(name);
                    /* TODO: Check the stack to make sure we're inside a call to loadlibrary */
                    //send("DLL Hijack available at " + name);
                }
            }
        }
    }
};

Interceptor.attach(pNtQueryAttributesFile, queryFileHandler);
Interceptor.attach(pLoadLibraryExW, { onEnter: loadLibHandlerW });
Interceptor.attach(pLoadLibraryW, { onEnter: loadLibHandlerW }); 