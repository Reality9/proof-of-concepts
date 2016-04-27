# convert file into a base64 encoded byte array
# rfr@
import sys
import base64

def get_bytes_from_file(filename):
    return open(filename, "rb").read()

if len(sys.argv) == 2:
    print base64.b64encode(get_bytes_from_file(sys.argv[1]))
else:
    print "Usage: " + sys.argv[0] + "<path/to/file>"
