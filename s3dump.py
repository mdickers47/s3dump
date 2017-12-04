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

dump FS LEVEL    - write an object to S3
restore FS LEVEL - retrieve an object from S3
delete FS LEVEL  - delete an object in S3

          -k <arg>: Optional literal name of key in S3 bucket.  Otherwise,
                    must provide FS and LEVEL on the command line, and a
                    key will be created using hostname, fs, level, date.
          -h <arg>: Override default hostname with <arg>
          -w <arg>: Override default date, use format YYYY-MM-DD

list    - print list of dumps/objects available in S3

init    - create and test bucket

clean N - delete all but the most recent N dumps at each fs and level
          -a: clean all dumps, not just ones for this host

getacl  - print given key's ACL XML document to stdout
putacl  - read ACL XML document from stdin, apply to given key

options that apply to any command:

-q: suppress status messages, only report errors
-L <arg>: ratelimit S3 socket to <arg>{k,m,g} bytes per second
-f <arg>: read S3 configuration from <arg> rather than ~/.s3keys
-i: use S3 'infrequent access' storage class
"""

import getopt
import os
import s3
import signal
import socket
import sys
import time

DATE_FMT = '%Y-%m-%d'

# Need this in a global so that signal handlers can change the ratelimit.
global bucket

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


def PrintDumpTable(bucket):
  dumpsizes = {}
  othersizes = {}
  total_bytes = 0
  for e in bucket.list_bucket():
    try:
      host, fs, level, date = e.key.split(':')
      t = (host, fs, level, date)
      dumpsizes.setdefault(t, 0)
      dumpsizes[t] += e.size
      total_bytes += e.size
    except ValueError:
      othersizes.setdefault(e.key, 0)
      othersizes[e.key] += e.size
      total_bytes += e.size

  # flatten the dicts of (host,fs,level,date) => size to a 2d array
  if dumpsizes:
    rows = [ tuple([h, f, l, d, HumanizeBytes(s)])
             for (h, f, l, d), s in dumpsizes.items() ]
    rows.sort()
    rows.insert(0, ('-- host', 'filesystem', 'level', 'date', 'size'))
    if othersizes: print '-- Dump-style objects:'
    PrintTable(rows, sys.stdout)
  if othersizes:
    rows = [ tuple([k, HumanizeBytes(v)]) for k, v in othersizes.items() ]
    rows.sort()
    rows.insert(0, ('-- key', 'size'))
    if dumpsizes: print '-- Other objects:'
    PrintTable(rows, sys.stdout)

  return total_bytes


def PrintTable(array, stream):
  """given a 2d array (list of tuples), figure out column widths and
  printf an ascii-art table."""
  col_widths = [0] * len(array[0])
  for row in array:
    for i, val in enumerate(row):
      if len(str(val)) > col_widths[i]: col_widths[i] = len(str(val))
  fmt_str = ' '.join(['%-' + str(x) + 's' for x in col_widths]) + '\n'
  hrule = '-' * ( sum(col_widths) + len(col_widths) - 1) + '\n'
  stream.write(fmt_str % array[0])
  stream.write(hrule)
  for row in array[1:]: stream.write(fmt_str % row)
  stream.write(hrule)


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


def ChangeRatelimit(signum, _):
  # we don't use the frame parameter; naming it _ makes pychecker ignore it.
  global bucket
  if not bucket.ratelimit:
    new_ratelimit = 256 * 1024 # 256 kB/s
  elif signum == signal.SIGUSR1:
    new_ratelimit = bucket.ratelimit / 2
  else:
    assert signum == signal.SIGUSR2
    new_ratelimit = bucket.ratelimit * 2
  if new_ratelimit > 10 * (2**20) or new_ratelimit < 1024:
    # out of the range 1kB - 10MB per second
    sys.stderr.write('s3dump: removing ratelimit\n')
    bucket.ratelimit = None
  else:
    sys.stderr.write('s3dump: new ratelimit %ld bytes/sec\n' % new_ratelimit)
    bucket.ratelimit = new_ratelimit


def usage(msg):
  sys.stderr.write('error: %s\n' % msg)
  sys.stderr.write(__doc__)
  sys.stderr.write('\n')
  sys.exit(1)


if __name__ == '__main__':

  # parse command line
  try:
    opts, remainder = getopt.getopt(sys.argv[1:], 'aiyqh:w:L:f:k:')
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
    config_file = opts.get('-f', os.path.expanduser('~/.s3keys'))

    if cmd in ('dump', 'restore', 'delete', 'putacl', 'getacl'):
      if '-k' in opts:
        key_prefix = opts['-k']
      elif len(remainder) == 2:
        filesystem, level = remainder
        if ':' in filesystem + level:
          raise ValueError('colon (:) cannot appear in filesystem or level')
        key_prefix = ':'.join([host, filesystem, level, date])
      else:
        raise ValueError('must supply either -k or filesystem/level args')

  except (getopt.GetoptError, ValueError, IndexError), e:
    usage(str(e))

  # load config
  try:
    config = s3.AWSConfig(config_file)
  except s3.AWSConfigError, e:
    sys.stderr.write('Error in config file %s: %s' % (config_file, e))
    sys.exit(1)

  global bucket
  bucket = s3.Bucket(config)
  bucket.ratelimit = ratelimit
  if '-i' in opts: bucket.set_storage_class(s3.STORAGE_IA)
  bucket_stdout = sys.stdout
  if '-q' in opts: bucket_stdout = None

  signal.signal(signal.SIGUSR1, ChangeRatelimit)
  signal.signal(signal.SIGUSR2, ChangeRatelimit)

  if cmd == 'init' or cmd == 'initialize':
    # initialize dumps bucket
    print 'Creating bucket %s' % config.bucket_name
    print bucket.create_bucket().reason
    print 'Testing ability to write, read, and delete:'
    print bucket.put('testkey', s3.S3Object('this is a test')).reason
    print bucket.get('testkey').reason
    print bucket.delete('testkey').reason

  elif cmd == 'delete':
    try:
      if bucket.list_bucket(key_prefix + '/'):
        s3.DeleteChunkedFile(bucket, key_prefix,
                             stdout=bucket_stdout, stderr=sys.stderr)
      else:
        bucket.delete(key_prefix)
    except s3.Error, e:
      sys.stderr.write(e.message + '\n')
      sys.exit(1)

  elif cmd == 'dump':
    try:
      bucket.put_streaming(key_prefix, sys.stdin,
                           stdout=bucket_stdout, stderr=sys.stderr)
    except s3.Error, e:
      sys.stderr.write(e.message + '\n')
      sys.exit(1)
    
  elif cmd == 'clean':
    if not '-y' in opts:
      print 'NOT DELETING ANYTHING -- add -y switch to delete for real.'

    try:
      nkeep = int(remainder[0])
    except:
      usage('must specify number of dumps to keep, such as "clean 2"')

    dumps = RetrieveDumpTree(bucket)
    for h in dumps.keys():
      if host == h or '-a' in opts:
        for fs in dumps[h]:
          for level in dumps[h][fs]:
            dates = dumps[h][fs][level].keys()
            dates.sort()
            for d in dates[:0 - int(remainder[0])]:
              if not '-q' in opts:
                print 'deleting dump of %s:%s, level %s, %s' % \
                      (h, fs, level, d)
              if '-y' in opts:
                s3.DeleteChunkedFile(bucket, ':'.join([h, fs, level, d]))
      
  elif cmd == 'list':
    print '-- Listing contents of %s' % config.bucket_name
    try:
      total = PrintDumpTable(bucket)
    except s3.AWSHttpError, e:
      sys.stderr.write(e.message + '\n')
      sys.exit(1)
    print '-- Total data stored: %s ($%.2f/month)' % \
      (HumanizeBytes(total), total / (2**30) * 0.023)

  elif cmd == 'restore' or cmd == 'retrieve':
    if '-w' in opts or '-k' in opts:
      key = key_prefix
    else:
      # find the last dump
      key_prefix = '%s:%s:%s:' % (host, filesystem, level)
      objs = bucket.list_bucket(key_prefix)
      if not objs:
        sys.stderr.write('no objects found at prefix %s\n' % key_prefix)
        sys.exit(1)
      key = objs[-1].key

    # in this case we have the bucket send status messages to stderr,
    # because stdout is where the data goes.
    if not '-q' in opts: bucket_stdout = sys.stderr

    try:
      bucket.get_streaming(key, sys.stdout,
                           stdout=bucket_stdout, stderr=sys.stderr)
    except s3.Error, e:
      sys.stderr.write(e.message + '\n')
      sys.exit(1)

  elif cmd == 'getacl':
    print bucket.get_acl(key_prefix).data

  elif cmd == 'putacl':
    #acl = sys.stdin.read()
    r = bucket.put_acl(key_prefix, s3.S3Object(sys.stdin.read()))
    print '%s (%s)' % (r.status, r.reason)

  else:
    usage('unrecognized command word: %s' % cmd)

  sys.exit(0)
