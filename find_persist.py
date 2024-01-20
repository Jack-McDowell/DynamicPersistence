import frida
import sys
import os
import time

def on_message(message, data):
    print(message.get("payload"))

def main():
    if len(sys.argv) < 2:
        print("Usage:", sys.argv[0], " <program name> <args>")

    program_name = sys.argv[1]
    target_proc = frida.spawn(program_name, argv=sys.argv[1:])
    session = frida.attach(target_proc)

    script_contents = "\n".join([open(os.path.join("frida", f), "r").read() for f in ["taint.js", "loadLibrary.js", "registry.js"]])
    script = session.create_script(script_contents)
    script.on("message", on_message)
    script.load()

    frida.resume(target_proc)
    time.sleep(100)

if __name__ == "__main__":
    main()