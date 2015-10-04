"""
Use
    python annotate_ip.py file.txt file.csv ...

Produces file_out.txt file_out.csv ... with an extra column for the whois info.

Requirements
    * pip install geoip2
"""

from collections import defaultdict
import gzip
import json
import os
import pprint
import re
import shutil
import sys
import urllib2

import geoip2.database


DELIM = ","

class Cache(object):
    def __init__(self, path = None, save_freq = 2):
        self.path = path
        self.save_freq = save_freq
        if self.path and os.path.exists(self.path):
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
        if self.path:
            import json
            import os
            import shutil
            json.dump(self.data.items(), open(self.path + '.tmp', 'wb'))
            shutil.copyfile(self.path + '.tmp', self.path)
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
#RIPE NCC owns IP allocation for Europe, the Middle East,
# and parts of central Asia; re-look up on the RIPE website?
    try:
        customer = " "
        org = " "
        res = json.loads(urllib2.urlopen('http://whois.arin.net/rest/ip/%s.json' % ip).read())
        net = res['net']
        if 'orgRef' in net:
            org = encode(net['orgRef']['@name'])
            org = org.replace(',',' ')
        else:
            customer = encode(net['customerRef']['@name'])
            customer = customer.replace(',',' ')
        return ','.join([customer, org])
    except Exception, exn:
        pprint.pprint(res)
        raise

def encode(s):
    if s:
        return s.encode('ascii', 'ignore')
    else:
        return 'None'

@Cache()
def geoname(ip):
    res = get_geodb().city(ip)
    return ','.join(encode(s) for s in (res.country.iso_code, res.subdivisions.most_specific.iso_code, res.city.name, res.postal.code))

@Cache()
def geozip(ip):
    res = get_geodb().city(ip)
    return res.postal.code

@Cache()
def get_geodb():
    mmdb_path = 'GeoLite2-City.mmdb'
    if not os.path.exists(mmdb_path):
        mmdb_path_gz = mmdb_path + '.gz.gz'
        if not os.path.exists(mmdb_path_gz):
            url = 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz'
            print "Downloading", url
            f_in = urllib2.urlopen(url)
            with gzip.open(mmdb_path_gz, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
            os.system("ls -l")
            print "Done downloading."
        print "Unpacking", mmdb_path
        with gzip.open(mmdb_path_gz, 'rb') as f_in, open(mmdb_path + '.gz', 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        # Double compressed?
        with gzip.open(mmdb_path + '.gz', 'rb') as f_in, open(mmdb_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.system("ls -l")
        print "Done unpacking."
    return geoip2.database.Reader(mmdb_path)

def parse_line(line):
    s = line.split()
    d = re.search(r'\d+:\d+:\d+', line)
    if d:
        time = d.group(0)
    date = s[3]
    index = date.index(':')
    date = date[1:index]
    dest_url = s[6]
    status = s[8]
    user_agent = str(s[11:])
    user_agent = user_agent.replace(',',' ')
    return ','.join([str(dest_url) + "," +  date +  "," + time + "," + user_agent])

def run(argv):

    whois_counts = defaultdict(int)
    geo_counts = defaultdict(int)
    zip_counts = defaultdict(int)

    if not argv:
        argv = ['-']
    for file in argv:
        if file == '-':
            input = sys.stdin
            out = sys.stdout
        else:
            input = open(file)
            base, ext = os.path.splitext(file)
            out = open("%s_out%s" % (base, ".csv"), 'wb')
            zip_heat = open("%s_zip%s" % (base, ".txt"), 'wb')
        total_lines = 0
        small_count = 0
        out.write("Country," + "State," + "City," + "Postal," + "Customer," + "Organization," + "IP address," + "Dest URL," + "Date," + "Time," + "UserAgent," + "\r\n")
        for line in input:
            whois = None
            geo = None
            total_lines += 1
            if line.count('spider') != 0:
                continue
            if line.count('bot') != 0:
                continue
            if line.count('crawl') != 0:
                continue
            # if status == 404 continue
            m = re.search(r'\d+.\d+.\d+.\d+', line)
            if m:
                ip = m.group(0)
                whois = lookup_whois(ip)
                geo = geoname(ip)
                #if geo.find("US"):
                #    continue
                zip = geozip(ip)
                small_count += 1
                line_str = parse_line(line)
            whois_counts[whois] += 1
            geo_counts[geo] += 1
            zip_counts[zip] += 1
            out.write(DELIM.join([str(geo)] + [str(whois)] + [str(ip)] + [line_str]) + "\r\n")
        print "Total hits: " + str(total_lines)
        print "Filtered hits: " + str(small_count)
        for key, value in sorted(zip_counts.iteritems(), key=lambda (k,v): (v,k), reverse=True):
            zip_heat.write(str(key) + "," + str(value) + "\r\n")

if __name__ == '__main__':
    run(sys.argv[1:])
