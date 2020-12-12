import subprocess, os, sys

CURRENT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))

# TODO: get from build
aids = {
    "Teapot": "B00B5111CA01",
    "Secure": "B00B5111FF01",
    "MemoryCard": "B00B5111CB01",
    "BlindOracle": "B00B5111CE01",
    "SingleUseKey": "B00B5111CD01"
}

if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("No arguments provided.")
        print(f"Usage:    {sys.argv[0]} applet [aid]")
        print(f"Examples: {sys.argv[0]} BlindOracle")
        print(f"          {sys.argv[0]} BlindOracle B00B5111CE01")
        print( "Known applets:")
        for k in aids:
            print(f"  {k: <10}\t{aids.get(k)}")
        sys.exit(1)
    applet = sys.argv[1]
    aid = None
    if len(sys.argv) >= 3:
        aid = sys.argv[2]
    if aid is None and applet not in aids:
        print("Applet not found")
        sys.exit(1)
    args = ["java", "-jar", "simulator.jar", 
            "-p", "21111", 
            "-a", aids[applet], 
            "-c", f"toys.{applet}Applet", 
            "-u", f"file://{CURRENT_DIR}/build/classes/{applet}/"
    ]
    while True:
        print("Starting simulator...")
        proc = subprocess.run(args)
