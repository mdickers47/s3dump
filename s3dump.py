#!/usr/bin/env python
#
# s3dump.py - Similar to a tape driver, in that you pour bits in or
# pour them out.  Meant to be used with dump/restore, but doesn't care
# what your bits are.
#
# Copyright 2006-2017 Mikey Dickerson.  Use permitted under the terms
# of BSD-3-Clause at: https://opensource.org/licenses/BSD-3-Clause
"""
Usage: s3dump.py [opts] command

command must be one of:

dump    - write data to S3
restore - retrieve data from S3
          Must supply either 'fs level' args, or '-k' option.
          fs level - arbitrary strings, maybe filesystem and level
          -k <arg>: literal name of key in S3 bucket
          -h <arg>: override default hostname with <arg>
          -w <arg>: override default date, use YYYY-MM-DD
          -L <arg>: ratelimit S3 socket to <arg>{k,m,g} bytes/sec.

list    - print list of dumps available in S3
          -a: list for all all hosts
          -h <arg>: list for host <arg>

init    - create and test bucket

clean   - delete all but the last -c dumps of each fs and level
          -a: clean all dumps, not just mine
          -c <arg>: keep the last <arg> dumps of each fs and level
"""

import getopt
import socket
import sys
import time
import s3

CONFIG_FILE = '/etc/s3_keys'
DATE_FMT = '%Y-%m-%d'


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
      host, fs, level, date = e.key.split(':')
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


def usage(msg):
  sys.stderr.write('error: %s\n' % msg)
  sys.stderr.write(__doc__)
  sys.stderr.write('\n')
  sys.exit(1)


if __name__ == '__main__':

  # parse command line
  try:
    opts, remainder = getopt.getopt(sys.argv[1:], 'ac:h:w:L:y')
    opts = dict(opts)

    if not remainder: raise ValueError('must supply a command word')
    cmd, remainder = remainder[0], remainder[1:]

    host = opts.get('-h', socket.gethostname().split('.')[0].strip())
    if ':' in host or '/' in host:
      raise ValueError('hostname cannot contain : or /')
    date = opts.get('-w', time.strftime(DATE_FMT))
    if ':' in date or '/' in date:
      raise ValueError('date cannot contain : or /')
    clean_level = int(opts.get('-c', 2))
    ratelimit = int(DehumanizeBytes(opts.get('-L', '0')))

    if cmd in ('dump', 'restore'):
      if '-k' in opts:
        key_prefix = opts['-k']
      elif len(remainder) == 2:
        filesystem, level = remainder
        if ':' in filesystem + level:
          raise ValueError(': cannot appear in filesystem or level')
        key_prefix = ':'.join([host, filesystem, level, date])
      else:
        raise ValueError('must supply either -k or filesystem/level args')

  except (getopt.GetoptError, ValueError, IndexError), e:
    usage(str(e))

  # load config
  try:
    config = s3.AWSConfig(config_file=CONFIG_FILE)
  except s3.AWSConfigError, e:
    sys.stderr.write('Error in config file %s: %s' % (CONFIG_FILE, e))
    sys.exit(1)

  b = s3.Bucket(config)
  b.ratelimit = ratelimit

  if cmd == 'init' or cmd == 'initialize':
    # initialize dumps bucket
    print 'Creating bucket %s' % config.bucket_name
    print b.create_bucket().reason
    print 'Testing ability to write, read, and delete:'
    print b.put('testkey', s3.S3Object('this is a test')).reason
    print b.get('testkey').reason
    print b.delete('testkey').reason

  elif cmd == 'dump':
    b.put_streaming(key_prefix, sys.stdin,
                    stdout=sys.stdout, stderr=sys.stderr)
    
  elif cmd == 'clean':
    if not '-y' in opts:
      print 'NOT DELETING ANYTHING -- add -y switch to delete for real.'
    dumps = RetrieveDumpTree(b)
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
      
  elif cmd == 'list':
    print 'Using bucket %s' % config.bucket_name
    try:
      dumps = RetrieveDumpTree(b)
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

  elif cmd == 'restore' or cmd == 'retrieve':
    if '-w' in opts or '-k' in opts:
      key = key_prefix
    else:
      # find the last dump
      key_prefix = '%s:%s:%s:' % (host, filesystem, level)
      key = b.list_bucket(key_prefix)[-1].key

    b.get_streaming(key, sys.stdout, stdout=sys.stderr, stderr=sys.stderr)

  else:
    usage('unrecognized command word: %s' % cmd)

  sys.exit(0)
