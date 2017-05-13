#!/usr/bin/env python
#
# s3dump.py - Similar to a tape driver, in that you pour bits in or
# pour them out.  Meant to be used with dump/restore, but doesn't care
# what your bits are.
#
# Copyright 2006-2017 Mikey Dickerson.  Use permitted under the terms
# of BSD-3-Clause at: https://opensource.org/licenses/BSD-3-Clause
"""
Usage: s3dump.py (-d|-r|-l|-i|-c n) [-h hostname] [-w YYYY-MM-DD] [-a] fs level

Choose exactly one of the following:
  -d: dump (write data to s3)
  -r: restore (read data back from s3)
  -l: list dumps stored in s3
  -i: initialize dumps bucket (need to run only once)
  -c: (clean:) delete all but n latest dumps of each fs and level

Arguments and switches:
  -a: list or delete dumps for all hosts, not just me
  -h: override default hostname
  -w: override default date stamp, use format YYYY-MM-DD
  -L: ratelimit outgoing dump to n bytes/sec.  optional suffixes k, m, g.
  fs: name of filesystem you are dumping, or an arbitrary string
  level: an arbitrary int, possibly the dump level (0-9)
"""

import getopt
import socket
import sys
import time
import s3

DEFAULT_KEEP = 2
CONFIG_FILE = '/etc/s3_keys'
BLOCK_SIZE = 10 * 1024 # default dump block size is 10k
S3_CHUNK_SIZE = 1024 * 1024 * 50 # 50MB
DATE_FMT = '%Y-%m-%d'


# For future reference if re-implementing rate limit in s3.py. - mikeyd
"""
  def send_with_ratelimit(self, data):
    now = time.time()
    sent_last_sec = self.ratelimit
    to_send = len(data)

    while self.ratelimit and sent_last_sec + to_send > self.ratelimit:
      sent_last_sec = 0
      for (byte_count, when) in self.writes:
        if now - when < 1:
          sent_last_sec += byte_count
          if sent_last_sec + to_send > self.ratelimit:
            # sleep long enough for the budget breaker to rotate out
            to_sleep = 1 - (now - when)
            time.sleep(to_sleep)
            now = time.time()
            break
        else:
          # looking more than 1s ago
          break

    self.conn.send_stream(data)

    self.writes.insert(0, (len(data), now))
    while now - self.writes[-1][1] > 1:
      self.writes = self.writes[:-1]
"""


def RetrieveDumpTree(conn):
  # The map of stored dumps is complicated:
  #  hostname ember
  #     |-- filesystem /usr
  #     |      |-- level 0
  #     |      |     |-- date 2006-10-10: size 12345
  #     |      |     |-- date 2006-10-04: size 67890
  #     |      |     +-- ...
  #     |      |-- level 1
  #     |      +-- ...
  #     |-- filesystem /home
  #     +-- ...
  dumps = { }
  for e in conn.list_bucket():
    try:
      host, fs, level, datechunk = e.key.split(':')
      date, chunk = datechunk.split('/')
    except ValueError:
      sys.stderr.write('warning: found weird key named %s\n' % e.key)
      continue
    dumps.setdefault(host, {}).setdefault(fs, {}).setdefault(level, {})\
                           .setdefault(date, 0)
    dumps[host][fs][level][date] += e.size

  return dumps


def PrintDumpTree(t):
  filesystems = t.keys()
  filesystems.sort()
  total = 0L
  for f in filesystems:
    print '  ' + f
    levels = t[f].keys()
    levels.sort()
    for l in levels:
      dates = t[f][l].keys()
      dates.sort()
      for d in dates:
        print '    Level %s %s: %8s' % (l, d, HumanizeBytes(t[f][l][d]))
        total += t[f][l][d]
  return total


def HumanizeBytes(b):
  "Convert 2220934 to 2.2M, etc."
  units = ((40, 'T'), (30, 'G'), (20, 'M'), (10, 'k'))
  for u in units:
    if b > 2 ** u[0]: return '%.1f%s' % (float(b) / 2 ** u[0], u[1])
  return str(b)


def DehumanizeBytes(s):
  units = ((40, 'T'), (30, 'G'), (20, 'M'), (10, 'K')) # NB K not k
  for bits, u in units:
    if s.upper().endswith(u):
      return long(s[:-1]) * (2 ** bits)
  else:
    return long(s)


def usage():
  sys.stderr.write(__doc__)
  sys.stderr.write('\n')
  sys.exit(1)


if __name__ == '__main__':

  try:
    config = s3.AWSConfig(config_file=CONFIG_FILE)
  except s3.AWSConfigError, e:
    sys.stderr.write('Error in config file %s: %s' % (CONFIG_FILE, e))
    sys.exit(1)
                     
  
  # parse command line
  try:
    opts, remainder = getopt.getopt(sys.argv[1:], 'drilac:h:w:L:y')
    opts = dict(opts)
    if '-d' in opts or '-r' in opts:
      filesystem, level = remainder
      if ':' in filesystem or ':' in level:
        raise ValueError('filesystem, level cannot contain :')
      _ = int(level) # force a ValueError if not an int
    if '-c' in opts: opts['-c'] = int(opts['-c'])
    if '-h' in opts:
      host = opts['-h']
    else:
      host = socket.gethostname().split('.')[0].strip()
    if ':' in host:
      raise ValueError('host cannot contain :')
    if '-L' in opts and not '-d' in opts:
      raise ValueError('-L only works with -d')
    elif '-L' in opts:
      ratelimit = DehumanizeBytes(opts['-L'])
    else:
      ratelimit = 0
    if ('-d' in opts) + ('-r' in opts) + ('-l' in opts) + ('-i' in opts) \
           + ('-c' in opts) != 1:
      raise ValueError('must select exactly one of -d, -r, -l, -i')
  except (getopt.GetoptError, ValueError, IndexError), e:
    sys.stderr.write('command line error: %s\n' % e)
    usage()

  if '-i' in opts:
    # initialize dumps bucket
    print 'Creating bucket %s' % config.bucket_name
    conn = s3.Bucket(config)
    print conn.create_bucket().reason
    print conn.put('testkey', s3.S3Object('this is a test')).reason
    print conn.get('testkey').reason
    print conn.delete('testkey').reason

  elif '-d' in opts:
    date = opts.get('-w', time.strftime(DATE_FMT))
    key_prefix = ':'.join([host, filesystem, level, date])
    md5 = s3.StoreChunkedFile(sys.stdin, s3.Bucket(config), key_prefix,
                              stdout=sys.stdout, stderr=sys.stderr)
    sys.stderr.write('md5 of data stored: %s\n' % md5)
    
  elif '-c' in opts:
    # delete expired dumps
    if not '-y' in opts:
      print 'NOT DELETING ANYTHING -- add -y switch to delete for real.'
    conn = s3.Bucket(config)
    dumps = RetrieveDumpTree(conn)
    for h in dumps.keys():
      if host == h or '-a' in opts:
        for fs in dumps[h]:
          for level in dumps[h][fs]:
            dates = dumps[h][fs][level].keys()
            dates.sort()
            for d in dates[:0 - opts['-c']]:
              print 'deleting dump of %s:%s, level %s, %s' % \
                    (h, fs, level, d)
              if '-y' in opts:
                s3.DeleteChunkedFile(conn, ':'.join([h, fs, level, d]))
      
  elif '-l' in opts:
    print 'Using bucket %s' % config.bucket_name
    conn = s3.Bucket(config)
    try:
      dumps = RetrieveDumpTree(conn)
    except s3.Error, e:
      print 'Error reading from S3: %s' % e
      sys.exit(1)
    total = 0L
    if host in dumps:
      print 'Dumps for this host (%s):' % host
      total += PrintDumpTree(dumps[host])
    if '-a' in opts:
      hosts = filter(lambda x: x != host, dumps.keys())
      hosts.sort()
      for h in hosts:
        print
        print 'Dumps for host %s:' % h
        total += PrintDumpTree(dumps[h])
    print
    print 'Total data stored: %s ($%.2f/month)' % \
      (HumanizeBytes(total), total / (2**30) * 0.023)

  elif '-r' in opts:
    conn = s3.Bucket(config)
    if '-w' in opts:
      date = opts['-w']
    else:
      dumps = RetrieveDumpTree(conn)[host][filesystem][level]
      date = sorted(dumps.keys())[-1]

    key_prefix = ':'.join([host, filesystem, level, date])
    md5 = s3.RetrieveChunkedFile(sys.stdout, conn, key_prefix,
                                 stderr=sys.stderr)
    sys.stderr.write('md5 of data returned: %s' % md5)

  else:
    assert 'Unpossible!' == 0

  sys.exit(0)
