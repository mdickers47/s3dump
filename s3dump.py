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

dump    - write an object to S3
restore - retrieve an object from S3
delete  - delete an object in S3

          May use '-k' to provide a name ('key') for the S3 object.
          -k <arg>: literal name of key in S3 bucket

          Otherwise, must provide 'fs level' on the command line, and a key
          will be constructed using current host name, fs, level, and date.
          fs level - arbitrary strings, intended to be filesystem and level
          -h <arg>: override default hostname with <arg>
          -w <arg>: override default date, use format YYYY-MM-DD

list    - print list of dumps/objects available in S3

init    - create and test bucket

clean   - delete all but the most recent n dumps at each fs and level
          -a: clean all dumps, not just ones for this host
          -c <arg>: keep the last <arg> dumps of each fs and level

getacl  - print given key's ACL XML document to stdout
putacl  - read ACL XML document from stdin, apply to given key

options that apply to any command:

-L <arg>: ratelimit S3 socket to <arg>{k,m,g} bytes per second
-f <arg>: read S3 configuration from <arg> rather than /etc/s3_keys
-i: use S3 'infrequent access' storage class
"""

import getopt
import os
import s3
import socket
import sys
import time

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


def usage(msg):
  sys.stderr.write('error: %s\n' % msg)
  sys.stderr.write(__doc__)
  sys.stderr.write('\n')
  sys.exit(1)


if __name__ == '__main__':

  # parse command line
  try:
    opts, remainder = getopt.getopt(sys.argv[1:], 'aiyc:h:w:L:f:k:')
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
          raise ValueError(': cannot appear in filesystem or level')
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

  b = s3.Bucket(config)
  b.ratelimit = ratelimit
  if '-i' in opts: b.set_storage_class(s3.STORAGE_IA)

  if cmd == 'init' or cmd == 'initialize':
    # initialize dumps bucket
    print 'Creating bucket %s' % config.bucket_name
    print b.create_bucket().reason
    print 'Testing ability to write, read, and delete:'
    print b.put('testkey', s3.S3Object('this is a test')).reason
    print b.get('testkey').reason
    print b.delete('testkey').reason

  elif cmd == 'delete':
    try:
      if b.list_bucket(key_prefix + '/'):
        s3.DeleteChunkedFile(b, key_prefix,
                             stdout=sys.stdout, stderr=sys.stderr)
      else:
        b.delete(key_prefix)
    except s3.Error, e:
      sys.stderr.write(e.message + '\n')
      sys.exit(1)

  elif cmd == 'dump':
    try:
      b.put_streaming(key_prefix, sys.stdin,
                      stdout=sys.stdout, stderr=sys.stderr)
    except s3.Error, e:
      sys.stderr.write(e.message + '\n')
      sys.exit(1)
    
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
                s3.DeleteChunkedFile(b, ':'.join([h, fs, level, d]))
      
  elif cmd == 'list':
    print '-- Listing contents of %s' % config.bucket_name
    total = PrintDumpTable(b)
    print '-- Total data stored: %s ($%.2f/month)' % \
      (HumanizeBytes(total), total / (2**30) * 0.023)

  elif cmd == 'restore' or cmd == 'retrieve':
    if '-w' in opts or '-k' in opts:
      key = key_prefix
    else:
      # find the last dump
      key_prefix = '%s:%s:%s:' % (host, filesystem, level)
      key = b.list_bucket(key_prefix)[-1].key

    try:
      b.get_streaming(key, sys.stdout, stdout=sys.stderr, stderr=sys.stderr)
    except s3.Error, e:
      sys.stderr.write(e.message + '\n')
      sys.exit(1)

  elif cmd == 'getacl':
    print b.get_acl(key_prefix).data

  elif cmd == 'putacl':
    #acl = sys.stdin.read()
    r = b.put_acl(key_prefix, s3.S3Object(sys.stdin.read()))
    print '%s (%s)' % (r.status, r.reason)

  else:
    usage('unrecognized command word: %s' % cmd)

  sys.exit(0)
