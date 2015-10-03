from collections import defaultdict
import json
import os
import pprint
import re
import sys
import urllib2

DELIM = '\t'

class Cache(object):
    def __init__(self, path, save_freq = 2):
        self.path = path
        self.save_freq = save_freq
        if os.path.exists(self.path):
            # json turns tuples into lists
            self.data = dict([((tuple(args), tuple(kwds)), data)
                                for ((args, kwds), data)
                                in json.load(open(self.path))])
        else:
            self.data = {}
    def __del__(self):
        # best effort
        self.save()
    def save(self):
        json.dump(self.data.items(), open(self.path + '.tmp', 'wb'))
        os.rename(self.path + '.tmp', self.path)
    def __call__(self, fn):
        def wrapper(*args, **kwds):
            key = args, tuple(sorted(kwds.items()))
            if key in self.data:
                res = self.data[key]
            else:
                res = self.data[key] = fn(*args, **kwds)
                if len(self.data) % self.save_freq == 0:
                    self.save()
            return res
        return wrapper

@Cache('whois.cache.json')
def lookup_whois(ip):
    try:
        res = json.loads(urllib2.urlopen('http://whois.arin.net/rest/ip/%s.json' % ip).read())
        net = res['net']
        if 'orgRef' in net:
            return net['orgRef']['@name']
        else:
            return net['customerRef']['@name']
    except Exception, exn:
        pprint.pprint(res)
        raise

def run(argv):
    whois_counts = defaultdict(int)
    if not argv:
        argv = ['-']
    for file in argv:
        if file == '-':
            input = sys.stdin
            out = sys.stdout
        else:
            input = open(file)
            out = open(file + '.out', 'wb')
        for line in input:
            whois = None
            geo = None
            m = re.search(r'\d+.\d+.\d+.\d+', line)
            if m:
                ip = m.group(0)
                whois = lookup_whois(ip)
            whois_counts[whois] += 1
            out.write(DELIM.join([str(whois), str(geo), line]))
        print
        pprint.pprint(dict(whois_counts))


if __name__ == '__main__':
    run(sys.argv[1:])
