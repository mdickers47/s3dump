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
import os
import re
import socket
import sys
import threading
import time
import urllib
import xml.sax

# Hard code your public and secret key if you want to.  Otherwise they
# will be read from a file in /etc.

BUCKET_NAME = None
AWS_ACCESS_KEY_ID = None
AWS_SECRET_ACCESS_KEY = None
HOSTNAME = socket.gethostname().split('.')[0].strip()
DEFAULT_KEEP = 2

# Nothing below this line should need to be changed.

if None in (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, BUCKET_NAME):
  with open('/etc/s3_keys', 'r') as fh:
    for line in fh:
      key, val = line.split('=')
      if key == 'key_id':
        AWS_ACCESS_KEY_ID = val.strip()
      elif key == 'secret_key':
        AWS_SECRET_ACCESS_KEY = val.strip()
      elif key == 'bucket':
        BUCKET_NAME = val.strip()
      else:
        print 'Bad config line: %s' % line

BLOCK_SIZE = 10 * 1024 # default dump block size is 10k
S3_CHUNK_SIZE = 1024 * 1024 * 50 # 50MB
DATE_FMT = '%Y-%m-%d'
DEFAULT_HOST = 's3.amazonaws.com'
METADATA_PREFIX = 'x-amz-meta-'
AMAZON_HEADER_PREFIX = 'x-amz-'
BUCKET_NAME = BUCKET_NAME or AWS_ACCESS_KEY_ID + '-dumps'

# generates the aws canonical string for the given parameters
def canonical_string(method, path, headers, expires=None):
  interesting_headers = {}
  for key in headers:
    lk = key.lower()
    if lk in ['content-md5', 'content-type', 'date'] or lk.startswith(AMAZON_HEADER_PREFIX):
      interesting_headers[lk] = headers[key].strip()

  # these keys get empty strings if they don't exist
  if not interesting_headers.has_key('content-type'):
    interesting_headers['content-type'] = ''
  if not interesting_headers.has_key('content-md5'):
    interesting_headers['content-md5'] = ''

  # just in case someone used this.  it's not necessary in this lib.
  if interesting_headers.has_key('x-amz-date'):
    interesting_headers['date'] = ''

  # if you're using expires for query string auth, then it trumps date
  # (and x-amz-date)
  if expires:
    interesting_headers['date'] = str(expires)

  sorted_header_keys = interesting_headers.keys()
  sorted_header_keys.sort()

  buf = "%s\n" % method
  for key in sorted_header_keys:
    if key.startswith(AMAZON_HEADER_PREFIX):
      buf += "%s:%s\n" % (key, interesting_headers[key])
    else:
      buf += "%s\n" % interesting_headers[key]

  # don't include anything after the first ? in the resource...
  buf += "/%s" % path.split('?')[0]

  # ...unless there is an acl or torrent parameter
  if re.search("[&?]acl($|=|&)", path):
    buf += "?acl"
  elif re.search("[&?]torrent($|=|&)", path):
    buf += "?torrent"

  return buf


# computes the base64'ed hmac-sha hash of the canonical string and the secret
# access key, optionally urlencoding the result
def encode(aws_secret_access_key, str, urlencode=False):
  b64_hmac = base64.encodestring(hmac.new(aws_secret_access_key, str,
                                          hashlib.sha1).digest()).strip()
  if urlencode:
    return urllib.quote_plus(b64_hmac)
  else:
    return b64_hmac


def merge_meta(headers, metadata):
  final_headers = headers.copy()
  for k in metadata.keys():
    final_headers[METADATA_PREFIX + k] = metadata[k]
  return final_headers


class AWSAuthConnection:
    
  def __init__(self, is_secure=True, server=DEFAULT_HOST, port=None):

    if not port:
      port = {True: httplib.HTTPS_PORT, False: httplib.HTTP_PORT}[is_secure]

    self.aws_access_key_id = AWS_ACCESS_KEY_ID
    self.aws_secret_access_key = AWS_SECRET_ACCESS_KEY
    if (is_secure):
      self.connection = httplib.HTTPSConnection("%s:%d" % (server, port))
    else:
      self.connection = httplib.HTTPConnection("%s:%d" % (server, port))

  def close(self):
    self.connection.close()
    
  def create_bucket(self, bucket, headers={}):
    return self.make_request('PUT', bucket, headers)

  def list_bucket(self, bucket, options={}, headers={}):
    self.entries = []
    while True:
      path = bucket
      if options:
        path += '?'
        path += '&'.join(["%s=%s" % (param, urllib.quote_plus(str(options[param]))) for param in options])

      lst = ListBucketResponse(self.make_request('GET', path, headers))

      for e in lst.entries:
        self.entries.append(e)

      if not lst.is_truncated:
        break

      # re-request with the marker set at the last one we got
      # this time round. This sort of conflicts with the NextMarker
      # code posted all over the web - but seems to work an dovetails
      # nicely with http://docs.amazonwebservices.com/AmazonS3/latest/API/RESTBucketGET.html
      #
      options.update({'marker': self.entries[-1].key})

    return self

  def delete_bucket(self, bucket, headers={}):
    return self.make_request('DELETE', bucket, headers)

  def put(self, bucket, key, obj, headers={}):
    if not isinstance(obj, S3Object): obj = S3Object(obj)

    return self.make_request('PUT',
                             '%s/%s' % (bucket, urllib.quote_plus(key)),
                             headers,
                             obj.data,
                             obj.metadata)

  def open_stream(self, bucket, key, datalen):
    # add auth header
    path = '%s/%s' % (bucket, urllib.quote_plus(key))
    headers = { 'Content-Length': datalen }
    self.add_aws_auth_header(headers, 'PUT', path)
    self.connection.putrequest('PUT', '/' + path)
    for h in headers:
      self.connection.putheader(h, headers[h])
    self.connection.endheaders()

  def send_stream(self, data):
    self.connection.send(data)

  def close_stream(self):
    return self.connection.getresponse()
    
  def get(self, bucket, key, headers={}):
    return GetResponse(self.make_request('GET',
                                         '%s/%s' % (bucket, urllib.quote_plus(key)),
                                         headers))

  def delete(self, bucket, key, headers={}):
    return self.make_request('DELETE',
                             '%s/%s' % (bucket, urllib.quote_plus(key)),
                             headers)

  def get_bucket_acl(self, bucket, headers={}):
    return self.get_acl(bucket, '', headers)

  def get_acl(self, bucket, key, headers={}):
    return GetResponse(self.make_request('GET',
                                         '%s/%s?acl' % (bucket, urllib.quote_plus(key)),
                                         headers))

  def put_bucket_acl(self, bucket, acl_xml_document, headers={}):
    return self.put_acl(bucket, '', acl_xml_document, headers)

  def put_acl(self, bucket, key, acl_xml_document, headers={}):
    return self.make_request('PUT',
                             '%s/%s?acl' % (bucket, urllib.quote_plus(key)),
                             headers,
                             acl_xml_document)

  def make_request(self, method, path, headers=None, data='', metadata={}):
    if not headers: headers = {}
    final_headers = merge_meta(headers, metadata);
    # add auth header
    self.add_aws_auth_header(final_headers, method, path)
    self.connection.request(method, "/%s" % path, data, final_headers)
    return self.connection.getresponse()


  def add_aws_auth_header(self, headers, method, path):
    if not headers.has_key('Date'):
      headers['Date'] = time.strftime("%a, %d %b %Y %X GMT", time.gmtime())

    c_string = canonical_string(method, path, headers)
    headers['Authorization'] = \
           "AWS %s:%s" % (self.aws_access_key_id,
                          encode(self.aws_secret_access_key, c_string))


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
  
  def __init__(self, queue, ringbuf, key_prefix, ratelimit):
    threading.Thread.__init__(self)
    self.queue = queue
    self.ringbuf = ringbuf
    self.key_prefix = key_prefix

    self.ratelimit = ratelimit
    self.conn = None
    self.writes = []

  def run(self):
    self.conn = AWSAuthConnection(is_secure=True)
    chunk = 0
    read_ptr = 0
    while True:
      stop_ptr = self.queue.get()
      if stop_ptr == -1: break # all done

      print 'uploader: uploading blocks [%d,%d)' % (read_ptr, stop_ptr)
      bytes = 0
      i = start_ptr = read_ptr
      while i != stop_ptr:
        bytes += len(self.ringbuf[i])
        i = (i + 1) % len(self.ringbuf)
      key = '%s:%s' % (self.key_prefix, chunk)

      tries = 20
      while tries:
        try:
          print 'uploader: key is %s (%ld bytes)' % (key, bytes)
          self.conn = AWSAuthConnection(is_secure=True)
          self.conn.open_stream(BUCKET_NAME, key, bytes)
          read_ptr = start_ptr
          while read_ptr != stop_ptr:
            self.send_with_ratelimit(self.ringbuf[read_ptr])
            read_ptr = (read_ptr + 1) % len(self.ringbuf)
          response = self.conn.close_stream()
          response.read() # have to read() before starting a new request
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
    i = 0
    sent_last_sec = self.ratelimit
    to_send = len(data)

    while self.ratelimit and sent_last_sec + to_send > self.ratelimit:
      sent_last_sec = 0
      for (bytes, when) in self.writes:
        if now - when < 1:
          sent_last_sec += bytes
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
  keys = [ x.key for x in conn.list_bucket(BUCKET_NAME).entries ]
  keys = filter(lambda x: x.startswith(prefix), keys)
  keys.sort(_SortByChunkNumber)
  return keys


def DeleteChunkedFile(conn, prefix):
  #print 'delete %s' % prefix
  #return ### TEST
  for k in ListChunks(conn, prefix):
    res = conn.delete(BUCKET_NAME, k)
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
  for e in conn.list_bucket(BUCKET_NAME).entries:
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
    print 'Creating bucket %s' % BUCKET_NAME
    conn = AWSAuthConnection(is_secure=False)
    print conn.create_bucket(BUCKET_NAME).reason

    print conn.put(BUCKET_NAME, 'testkey', S3Object('this is a test')).reason
    print conn.delete(BUCKET_NAME, 'testkey').reason

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
    uploader = ChunkUploader(chunk_queue, block_buf, key_prefix, ratelimit)
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
    conn = AWSAuthConnection(is_secure=False)
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
    print 'Using bucket %s' % BUCKET_NAME
    conn = AWSAuthConnection(is_secure=False)
    dumps = RetrieveDumpTree(conn)
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
      (HumanizeBytes(total), total / (2**30) * 0.095)

  elif '-r' in opts:
    if '-w' in opts:
      date = opts['-w']
    else:
      dumps = RetrieveDumpTree(AWSAuthConnection())[host][filesystem][level]
      dates = dumps.keys()
      dates.sort()
      date = dates[-1]
    
    chunks = ListChunks(AWSAuthConnection(), ':'.join([host, filesystem, level, date]))
    
    for chunk in chunks:
      sys.stderr.write('Reading chunk %s of %d\n' % (chunk, len(chunks)))
      response = AWSAuthConnection().get(BUCKET_NAME, chunk)
      if response.http_response.status != 200: break
      sys.stdout.write(response.object.data)

  else:
    assert 'Unpossible!' == 0

  sys.exit(0)
