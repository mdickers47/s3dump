#!/usr/bin/env python
#
# s3dump.py - Similar to a tape driver, in that you pour bits in or
# pour them out.  Meant to be used with dump/restore, but doesn't care
# what your bits are.
#
# Copyright 2006-12 Michael Dickerson (mikey@singingtree.com).
# Use permitted under the same terms as the license provided with the
# Amazon code, below.
#
# Some parts, mostly AWSAuthConnection,  were taken from Amazon's sample
# s3 implementation.  The license that came with that code is:
#
#  This software code is made available "AS IS" without warranties of any
#  kind.  You may copy, display, modify and redistribute the software
#  code either by itself or as incorporated into your code; provided that
#  you do not remove any proprietary notices.  Your use of this software
#  code is at your own risk and you waive any claim against Amazon
#  Digital Services, Inc. or its affiliates with respect to your use of
#  this software code. (c) 2006 Amazon Digital Services, Inc. or its
#  affiliates.

import Queue
import base64
import hashlib
import hmac
import httplib
import getopt
import re
import socket
import sys
import threading
import time
import urllib
import xml.sax

HOSTNAME = socket.gethostname().split('.')[0].strip()
DEFAULT_KEEP = 2
CONFIG_FILE = '/etc/s3_keys'
BLOCK_SIZE = 10 * 1024 # default dump block size is 10k
S3_CHUNK_SIZE = 1024 * 1024 * 50 # 50MB
DATE_FMT = '%Y-%m-%d'
METADATA_PREFIX = 'x-amz-meta-'

# Nothing below this line should need to be changed.

class AWSConfigError(Exception): pass

class AWSConfig(object):
  def __init__(self, config_file=None):
    self.access_key_id = None
    self.secret_access_key = None
    self.bucket_name = None

    if config_file:
      with open(config_file, 'r') as fh:
        for line in fh:
          if line.startswith('#'): continue
          key, val = line.split('=')
          if key == 'key_id':
            self.access_key_id = val.strip()
          elif key == 'secret_key':
            self.secret_access_key = val.strip()
          elif key == 'bucket':
            self.bucket_name = val.strip()
          else:
            raise AWSConfigError('bad config line: %s' % line)

    if not self.access_key_id:
      raise AWSConfigError('key_id must be defined')
    if not self.secret_access_key:
      raise AWSConfigError('secret_key must be defined')
    if not self.bucket_name:
      self.bucket_name = self.access_key_id + '-dumps'

# generates the aws canonical string for the given parameters
def canonical_string(method, path, headers, expires=None):
  interesting_headers = {
    'content-type' : '',
    'content-md5'  : '',
  }

  for key, val in headers.items():
    lk = key.lower()
    if (lk in ['content-md5', 'content-type', 'date']
        or lk.startswith('x-amz-')):
      interesting_headers[lk] = val.strip()

  # just in case someone used this.  it's not necessary in this lib.
  if 'x-amz-date' in interesting_headers:
    interesting_headers['date'] = ''

  # if you're using expires for query string auth, then it trumps date
  # (and x-amz-date)
  if expires:
    interesting_headers['date'] = str(expires)

  buf = "%s\n" % method
  for key in sorted(interesting_headers.keys()):
    if key.startswith('x-amz-'):
      buf += "%s:%s\n" % (key, interesting_headers[key])
    else:
      buf += "%s\n" % interesting_headers[key]

  # don't include anything after the first ? in the resource...
  if not path.startswith('/'): buf += '/'
  buf += path.split('?')[0]

  # ...unless there is an acl or torrent parameter
  if re.search("[&?]acl($|=|&)", path):
    buf += "?acl"
  elif re.search("[&?]torrent($|=|&)", path):
    buf += "?torrent"

  return buf


def compute_hmac(secret_key, data):
  hm = hmac.new(secret_key, data, hashlib.sha1)
  return base64.encodestring(hm.digest()).strip()

class S3BucketError(Exception): pass

class S3Bucket:

  def __init__(self, aws_config, server='s3.amazonaws.com'):
    self.aws_access_key_id = aws_config.access_key_id
    self.aws_secret_access_key = aws_config.secret_access_key
    self.bucket = aws_config.bucket_name
    self.connection = httplib.HTTPSConnection(server)
    self.debug_log = None

  def _debug(self, msg):
    if self.debug_log: self.debug_log.write(msg, '\n')
    #print msg

  def _make_request(self, method, path, headers=None, s3obj=None,
                    open_stream=False):
    if headers:
      h = headers.copy()
    else:
      h = {}
    if method == 'PUT' and s3obj:
      for k, v in s3obj.metadata.items(): h[METADATA_PREFIX + k] = v
    elif method == 'PUT' and not s3obj:
      raise S3BucketError('missing object to put request')
    elif method != 'PUT' and s3obj:
      raise S3BucketError('non-PUT request cannot take an object')

    if not path.startswith('/'): path = '/' + path
    
    if not 'Date' in h:
      h['Date'] = time.strftime('%a, %d %b %Y %X GMT', time.gmtime())

    # sign the request with 'Authorization' header
    c_string = canonical_string(method, path, h)
    hmac = compute_hmac(self.aws_secret_access_key, c_string)
    h['Authorization'] = 'AWS %s:%s' % (self.aws_access_key_id, hmac)

    self._debug('Request: %s %s' % (method, path))
    #self._debug('Canonical string: %s' % c_string)
    #self._debug('Authorization header: %s' % h['Authorization'])
    
    if open_stream:
      self.connection.putrequest(method, path)
      for k, v in h: self.connection.putheader(k, v)
      self.connection.endheaders()
      if s3obj: self.connection.send(s3obj.data)
      ret = None
    else:
      if s3obj:
        data = s3obj.data
      else:
        data = ''
      self.connection.request(method, path, '', h)
      ret = self.connection.getresponse()
      self._debug('Response status: %s' % ret.status)

    return ret

  def close(self):
    self.connection.close()

  def create_bucket(self, headers=None):
    return self._make_request('PUT', self.bucket, headers=headers)

  def delete_bucket(self, headers=None):
    return self._make_request('DELETE', self.bucket, headers=headers)

  def get_bucket_acl(self, headers=None):
    return self.get_acl('', headers=headers)

  def put_bucket_acl(self, acl_xml_document, headers=None):
    return self.put_acl('', acl_xml_document, headers=headers)
  
  def list_bucket(self, options=None, headers=None):
    self.entries = []
    if not options: options = {} # this silences a pychecker error
    while True:
      path = '/' + self.bucket
      if options:
        stringify = lambda p: '%s=%s' % (p, urllib.quote_plus(str(options[p])))
        path += '?' + '&'.join(map(stringify, options.keys()))

      lst = ListBucketResponse(self._make_request('GET', path,
                                                  headers=headers))

      self.entries.extend(lst.entries)
      if not lst.is_truncated: break

      # re-request with the marker set at the last one we got
      # this time round. This sort of conflicts with the NextMarker
      # code posted all over the web - but seems to work an dovetails
      # nicely with
      # http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGET.html
      options['marker'] = self.entries[-1].key
      
    return self

  def put(self, key, obj, headers=None, open_stream=False):
    if not isinstance(obj, S3Object): obj = S3Object(obj)
    r = self._make_request('PUT',
                           '/%s/%s' % (self.bucket, urllib.quote_plus(key)),
                           headers=headers,
                           s3obj=obj,
                           open_stream=open_stream)
    return r

  def get(self, key, headers=None):
    r = self._make_request('GET',
                           '/%s/%s' % (self.bucket, urllib.quote_plus(key)),
                           headers=headers)
    return GetResponse(r)
  
  def delete(self, key, headers=None):
    r = self._make_request('DELETE',
                           '/%s/%s' % (self.bucket, urllib.quote_plus(key)),
                           headers=headers)
    return r

  def put_acl(self, key, acl_xml_document, headers=None):
    r = self._make_request('PUT',
                           '%s/%s?acl' % (self.bucket, urllib.quote_plus(key)),
                           headers=headers,
                           s3obj=acl_xml_document)
    return r
  
  def get_acl(self, key, headers=None):
    r = self._make_request('GET',
                           '/%s/%s?acl' % (self.bucket, urllib.quote_plus(key)),
                           headers=headers)
    return GetResponse(r)

  def send_stream(self, data):
    self.connection.send(data)

  def close_stream(self):
    return self.connection.getresponse()
    

class S3Object:
  def __init__(self, data, metadata={}):
    self.data = data
    self.metadata = metadata


class ListBucketError(Exception): pass


class ListBucketResponse:
  def __init__(self, http_response):
    self.body = http_response.read()
    if http_response.status < 300:
      handler = ListBucketHandler()
      xml.sax.parseString(self.body, handler)
      self.entries = handler.entries
      self.common_prefixes = handler.common_prefixes
      self.name = handler.name
      self.marker = handler.marker
      self.prefix = handler.prefix
      self.is_truncated = handler.is_truncated
      self.delimiter = handler.delimiter
      self.max_keys = handler.max_keys
      self.next_marker = handler.next_marker
    else:
      raise ListBucketError('HTTP error %d' % http_response.status)
      #self.entries = []


class Owner:
  def __init__(self, id='', display_name=''):
    self.id = id
    self.display_name = display_name


class ListEntry:
  def __init__(self, key='', last_modified=None, etag='', size=0, storage_class='', owner=None):
    self.key = key
    self.last_modified = last_modified
    self.etag = etag
    self.size = size
    self.storage_class = storage_class
    self.owner = owner


class CommonPrefixEntry:
  def __init__(self, prefix=''):
    self.prefix = prefix


class GetResponse:
  def __init__(self, http_response):
    self.http_response = http_response
    self.body = http_response.read()
    response_headers = http_response.msg   # older pythons don't have getheaders
    metadata = self.get_aws_metadata(response_headers)
    self.object = S3Object(self.body, metadata)

  def get_aws_metadata(self, headers):
    metadata = {}
    for hkey in headers.keys():
      if hkey.lower().startswith(METADATA_PREFIX):
        metadata[hkey[len(METADATA_PREFIX):]] = headers[hkey]
        del headers[hkey]
    return metadata


class ListBucketHandler(xml.sax.ContentHandler):
  def __init__(self):
    xml.sax.handler.ContentHandler.__init__(self)
    self.entries = []
    self.curr_entry = None
    self.curr_text = ''
    self.common_prefixes = []
    self.curr_common_prefix = None
    self.name = ''
    self.marker = ''
    self.prefix = ''
    self.is_truncated = False
    self.delimiter = ''
    self.max_keys = 0
    self.next_marker = ''
    self.is_echoed_prefix_set = False

  def startElement(self, name, attrs):
    del attrs # shut up pychecker
    if name == 'Contents':
      self.curr_entry = ListEntry()
    elif name == 'Owner':
      self.curr_entry.owner = Owner()
    elif name == 'CommonPrefixes':
      self.curr_common_prefix = CommonPrefixEntry()
            

  def endElement(self, name):
    if name == 'Contents':
      self.entries.append(self.curr_entry)
    elif name == 'CommonPrefixes':
      self.common_prefixes.append(self.curr_common_prefix)
    elif name == 'Key':
      self.curr_entry.key = self.curr_text
    elif name == 'LastModified':
      self.curr_entry.last_modified = self.curr_text
    elif name == 'ETag':
      self.curr_entry.etag = self.curr_text
    elif name == 'Size':
      self.curr_entry.size = int(self.curr_text)
    elif name == 'ID':
      self.curr_entry.owner.id = self.curr_text
    elif name == 'DisplayName':
      self.curr_entry.owner.display_name = self.curr_text
    elif name == 'StorageClass':
      self.curr_entry.storage_class = self.curr_text
    elif name == 'Name':
      self.name = self.curr_text
    elif name == 'Prefix' and self.is_echoed_prefix_set:
      self.curr_common_prefix.prefix = self.curr_text
    elif name == 'Prefix':
      self.prefix = self.curr_text
      self.is_echoed_prefix_set = True            
    elif name == 'Marker':
      self.marker = self.curr_text
    elif name == 'IsTruncated':
      # lore on the web suggests 'True;' - but this has not
      # been observed at the 6 AWS endpoints 2012-01-05
      self.is_truncated = self.curr_text.lower() == 'true'
    elif name == 'Delimiter':
      self.delimiter = self.curr_text
    elif name == 'MaxKeys':
      self.max_keys = int(self.curr_text)
    elif name == 'NextMarker':
      self.next_marker = self.curr_text

    self.curr_text = ''

  def characters(self, content):
    self.curr_text += content


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
      byte_count = 0
      i = start_ptr = read_ptr
      while i != stop_ptr:
        byte_count += len(self.ringbuf[i])
        i = (i + 1) % len(self.ringbuf)
      key = '%s:%s' % (self.key_prefix, chunk)

      tries = 20
      while tries:
        try:
          print 'uploader: key is %s (%ld bytes)' % (key, byte_count)
          self.conn = S3Bucket(self.aws_config)
          self.conn.put(key, bytes, open_stream=True)
          read_ptr = start_ptr
          while read_ptr != stop_ptr:
            self.send_with_ratelimit(self.ringbuf[read_ptr])
            read_ptr = (read_ptr + 1) % len(self.ringbuf)
          response = self.conn.close_stream()
          response.read() # have to read() before starting a new request
          self.conn.close()
          self.conn = None
          if response.status >= 300:
            raise Exception, 'Amazon returned error %d: %s' % \
                  (response.status, response.reason)
          break
        except Exception, e:
          try:
            self.conn.close_stream().read()
          except:
            pass
          self.conn = None
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
  print 'Usage: s3dump.py (-d|-r|-l|-i|-c n) [-h hostname] [-w YYYY-MM-DD] [-a] fs level\n' \
        '\n' \
        'Choose exactly one of the following:\n' \
        '  -d: dump (write data to s3)\n' \
        '  -r: restore (read data back from s3)\n' \
        '  -l: list dumps stored in s3\n' \
        '  -i: initialize dumps bucket (need to run only once)\n' \
        '  -c: (clean:) delete all but n latest dumps of each fs and level\n' \
        '\n' \
        'Arguments and switches:\n' \
        '  -a: list or delete dumps for all hosts, not just me\n' \
        '  -h: override default hostname (%s)\n' \
        '  -w: override default date stamp, use format YYYY-MM-DD\n' \
        '  -L: ratelimit outgoing dump to n bytes/sec.  optional suffixes k, m, g.\n' \
        '  fs: name of filesystem you are dumping, or an arbitrary string\n' \
        '  level: an arbitrary int, possibly the dump level (0-9)' % HOSTNAME
  return 1


if __name__ == '__main__':

  try:
    config = AWSConfig(config_file=CONFIG_FILE)
  except AWSConfigError, e:
    sys.stderr.write('Error in config file %s: %s' % (CONFIG_FILE, e))
    sys.exit(1)
                     
  
  # parse command line
  try:
    opts, remainder = getopt.getopt(sys.argv[1:], 'drilac:h:w:L:')
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
      host = HOSTNAME
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
    sys.stderr.write('command line error: %s\n\n' % e)
    sys.exit(usage())

  if '-i' in opts:
    # initialize dumps bucket
    print 'Creating bucket %s' % config.bucket_name
    conn = S3Bucket(config)
    print conn.create_bucket().reason

    print conn.put('testkey', S3Object('this is a test')).reason
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
    conn = S3Bucket(config)
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
              DeleteChunkedFile(conn, ':'.join([h, fs, level, d]))
      
  elif '-l' in opts:
    print 'Using bucket %s' % config.bucket_name
    conn = S3Bucket(config)
    try:
      dumps = RetrieveDumpTree(conn)
    except ListBucketError, e:
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
    conn = S3Bucket(config)
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
