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

import Queue
import getopt
import socket
import sys
import threading
import time
import s3

DEFAULT_KEEP = 2
CONFIG_FILE = '/etc/s3_keys'
BLOCK_SIZE = 10 * 1024 # default dump block size is 10k
S3_CHUNK_SIZE = 1024 * 1024 * 50 # 50MB
DATE_FMT = '%Y-%m-%d'

class ChunkUploader(threading.Thread):
  
  def __init__(self, queue, ringbuf, key_prefix, ratelimit, aws_config):
    threading.Thread.__init__(self)
    self.queue = queue
    self.ringbuf = ringbuf
    self.key_prefix = key_prefix
    self.ratelimit = ratelimit
    self.aws_config = aws_config
    self.conn = None
    self.writes = []

  def run(self):
    chunk = 0
    read_ptr = 0
    while True:
      stop_ptr = self.queue.get()
      if stop_ptr == -1: break # all done

      print 'uploader: uploading blocks [%d,%d)' % (read_ptr, stop_ptr)
      buf = []
      i = start_ptr = read_ptr
      while i != stop_ptr:
        buf.append(self.ringbuf[i])
        i = (i + 1) % len(self.ringbuf)
      key = '%s:%s' % (self.key_prefix, chunk)
      data = ''.join(buf)

      tries = 20
      bucket = None
      while tries:
        try:
          print 'uploader: key is %s (%ld bytes)' % (key, len(data))
          bucket = s3.Bucket(self.aws_config)
          r = bucket.put(key, data)
          body = r.read() # have to read() before starting a new request
          bucket.close()
          if r.status >= 300:
            raise Exception, 'Amazon returned HTTP %d (%s):\n%s' % \
                  (r.status, r.reason, body)
          break
        except Exception, e:
          if bucket.last_response:
            sys.stderr.write('Amazon returned HTTP %d (%s)\n' %
                             (bucket.last_response.status,
                              bucket.last_response.reason))
            sys.stderr.write(bucket.last_response.body + '\n')
          tries -= 1
          to_sleep = min(600, 2 ** (20 - tries))
          sys.stderr.write('uploading chunk %d failed: %s\n' % (chunk, e))
          sys.stderr.write('trying again in %ds (%d remaining).\n' % \
                             (to_sleep, tries))
          time.sleep(to_sleep)
      else:
        # kill this thread
        return

      # Release the memory only after the chunk is successfully posted.
      read_ptr = start_ptr
      while read_ptr != stop_ptr:
        self.ringbuf[read_ptr] = None
        read_ptr = (read_ptr + 1) % len(self.ringbuf)

      chunk += 1
    print 'uploader: done'
    return

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


def _SortByChunkNumber(a, b):
  ca = int(a.split(':')[-1])
  cb = int(b.split(':')[-1])
  return cmp(ca, cb)


def ListChunks(conn, prefix):
  keys = [ x.key for x in conn.list_bucket().entries ]
  keys = filter(lambda x: x.startswith(prefix), keys)
  keys.sort(_SortByChunkNumber)
  return keys


def DeleteChunkedFile(conn, prefix):
  #print 'delete %s' % prefix
  #return ### TEST
  for k in ListChunks(conn, prefix):
    res = conn.delete(k)
    res.read() # have to read() before you can start a new request
    if res.status >= 300:
      print 'deleting %s, Amazon returned error %d: %s' % \
            (k, res.status, res.reason)


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
  for e in conn.list_bucket().entries:
    try:
      host, fs, level, date, chunk = e.key.split(':')
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
    # dump data to s3
    # This will be a list of BLOCK_SIZE sized chunks, which will function
    # as a crude ring buffer.  The uploader thread and reader thread will
    # both use it at the same time, hopefully without stomping on each
    # other.  We rely on the promise that operations on python native types,
    # such as lists, are thread safe.
    block_buf = [ None ] * int((S3_CHUNK_SIZE / BLOCK_SIZE) * 1.25)
    chunk_bytes = write_ptr = buffered_bytes = 0
    chunk_queue = Queue.Queue()
    date = opts.get('-w', time.strftime(DATE_FMT))
    key_prefix = '%s:%s:%s:%s' % (host, filesystem, level, date)
    uploader = ChunkUploader(chunk_queue, block_buf, key_prefix,
                             ratelimit, config)
    uploader.setDaemon(True)
    uploader.start()
    
    while True:
      if not uploader.is_alive():
        sys.exit(1)
      while block_buf[write_ptr] is not None:
        #print 'main: waiting for buffer slot %d to clear' % write_ptr
        time.sleep(0.1)
      data = sys.stdin.read(BLOCK_SIZE)
      block_buf[write_ptr] = data
      buffered_bytes += BLOCK_SIZE
      write_ptr = (write_ptr + 1) % len(block_buf)
      if (buffered_bytes >= S3_CHUNK_SIZE or len(data) < BLOCK_SIZE):
        print 'main: queueing chunk for upload'
        chunk_queue.put(write_ptr)
        buffered_bytes = 0
      if len(data) < BLOCK_SIZE:
        break

    chunk_queue.put(-1) # magic value meaning 'you're done'

    print 'main: waiting for uploader to finish'
    uploader.join()

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
                DeleteChunkedFile(conn, ':'.join([h, fs, level, d]))
      
  elif '-l' in opts:
    print 'Using bucket %s' % config.bucket_name
    conn = s3.Bucket(config)
    try:
      dumps = RetrieveDumpTree(conn)
    except s3.ListBucketError, e:
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
      dates = dumps.keys()
      dates.sort()
      date = dates[-1]
    
    chunks = ListChunks(conn, ':'.join([host, filesystem, level, date]))
    
    for chunk in chunks:
      sys.stderr.write('Reading chunk %s of %d\n' % (chunk, len(chunks)))
      response = conn.get(chunk)
      if response.http_response.status != 200: break
      sys.stdout.write(response.object.data)

  else:
    assert 'Unpossible!' == 0

  sys.exit(0)
