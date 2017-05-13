#
# Copyright 2006-2017 Mikey Dickerson (mikey@singingtree.com).
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

import hashlib
import hmac
import httplib
import sys
import time
import urllib
import xml.etree.ElementTree as ET

METADATA_PREFIX = 'x-amz-meta-'
SIG_ALGORITHM = 'AWS4-HMAC-SHA256'
X_AMZ_DATE_FMT = '%Y%m%dT%H%M%SZ'
AWS_NS = { 'aws': 'http://s3.amazonaws.com/doc/2006-03-01/' }

class Error(Exception): pass
class AWSConfigError(Error): pass
class BucketError(Error): pass


class AWSHttpError(Error):
  def __init__(self, http_response):
    self.message = 'Amazon returned HTTP %d (%s)\n' % \
                   (http_response.status, http_response.reason)
    if 'body' in http_response.__dict__:
      self.message += ('-' * 20 + '\n' + http_response.body + '\n' +
                       '-' * 20 + '\n')
    elif 'read' in http_response.__dict__:
      self.message += ('-' * 20 + '\n' + http_response.read() + '\n' +
                       '-' * 20 + '\n')


class S3Object(object):
  def __init__(self, data, metadata={}):
    self.data = data
    self.metadata = metadata


class AWSConfig(object):
  def __init__(self, config_file='/etc/s3_keys'):
    self.access_key_id = None
    self.secret_access_key = None
    self.bucket_name = None
    self.server = 's3.amazonaws.com'
    self.region = 'us-east-1'
    self.service = 's3'

    if config_file:
      with open(config_file, 'r') as fh:
        for line in fh:
          if line.startswith('#'): continue
          try:
            key, val = line.split(' ')
          except ValueError:
            raise AWSConfigError('each line must consist of "key val"')
          if key in self.__dict__:
            self.__dict__[key] = val.strip()
          else:
            raise AWSConfigError('config line not understood: %s' % line)

    if not self.access_key_id:
      raise AWSConfigError('key_id must be defined')
    if not self.secret_access_key:
      raise AWSConfigError('secret_key must be defined')
    if not self.bucket_name:
      self.bucket_name = self.access_key_id + '-dumps'


def canonical_string_v4(method, path, headers):
  """Refer to AWS documentation: "Signature Calcuations for the
  Authorization Header: Transferring Payload in a Single Chunk (AWS
  Signature Version 4)
  """
  buf = []

  # HTTPMethod
  buf.append(method)
  buf.append('\n')

  # CanonicalURI
  components = path.split('?')
  uri = components[0]
  if not uri.startswith('/'): buf.append('/')
  buf.append(uri)
  buf.append('\n')

  # CanonicalQueryString
  if len(components) > 1:
    params = {}
    for pair in components[1].split('&'):
      if '=' in pair:
        param, val = pair.split('=')
      else:
        param, val = pair, ''
      params[param] = val
    param_buf = []
    for p in sorted(params.keys()):
      # We assume you have already url-encoded the query string, which is
      # likely since it was provided as an assembled url.
      param_buf.append('%s=%s' % (p, params[p]))
    buf.append('&'.join(param_buf))
  buf.append('\n')

  # CanonicalHeaders
  # rename all headers to lower case and remove whitespace
  lheaders = {}
  for (k, v) in headers.iteritems():
    # cheesy way to replace strings of whitespace with single spaces,
    # as required
    lheaders[k.lower()] = ' '.join(v.strip().split())
  headers = lheaders

  headers_to_sign = set()
  headers_to_sign.add('host') # required
  # headers_to_sign.add('x-amz-content-sha256') # also required

  for h in headers.keys():
    if h == 'content-type' or h == 'date' or h.startswith('x-amz-'):
      headers_to_sign.add(h)

  for h in sorted(list(headers_to_sign)):
    if not h in headers:
      raise ValueError, 'missing required header: %s' % h
    buf.append(h)
    buf.append(':')
    buf.append(headers[h].strip())
    buf.append('\n')
  buf.append('\n') # yes, you do 2 newlines in a row.

  # SignedHeaders
  # This has to go inside this string and also inside the much higher
  # level authorization header directly for some godforsaken reason.
  signed_headers = ';'.join(sorted(list(headers_to_sign)))
  buf.append(signed_headers)
  buf.append('\n')

  # HashedPayload
  if 'x-amz-content-sha256' in headers:
    buf.append(headers['x-amz-content-sha256'])
  else:
    buf.append(hashlib.sha256('').hexdigest())
  # it does not end with a newline for some reason.

  # All done.
  return signed_headers, ''.join(buf)


def string_to_sign_v4(canonical_req, amz_time, datestr, region, service):
  buf = []
  buf.append(SIG_ALGORITHM)
  buf.append('\n')
  #buf.append(time.strftime(X_AMZ_DATE_FMT, time.gmtime()))
  buf.append(amz_time)
  buf.append('\n')
  buf.append(datestr)
  buf.append('/')
  buf.append(region)
  buf.append('/')
  buf.append(service)
  buf.append('/aws4_request\n')
  buf.append(hashlib.sha256(canonical_req).hexdigest())
  return ''.join(buf)


def _sign(key, data):
  return hmac.new(key, data.encode('utf-8'), hashlib.sha256).digest()


def signing_key_v4(secret_access_key, datestr, region, service):
  """This has gotten ridiculous."""
  key = _sign('AWS4' + secret_access_key, datestr)
  key = _sign(key, region)
  key = _sign(key, service)
  key = _sign(key, 'aws4_request')
  return key


def auth_header_v4(method, path, headers, config):
  datestr = time.strftime('%Y%m%d', time.gmtime())
  credential = '/'.join((config.access_key_id, datestr, config.region,
                         config.service, 'aws4_request'))
  buf = []
  buf.append(SIG_ALGORITHM)
  buf.append(' Credential=')
  buf.append(credential)

  buf.append(', SignedHeaders=')
  signed_headers, c_string = canonical_string_v4(method, path, headers)
  buf.append(signed_headers)

  buf.append(', Signature=')
  signing_key = signing_key_v4(config.secret_access_key,
                               datestr, config.region, config.service)
  string_to_sign = string_to_sign_v4(c_string, headers['x-amz-date'],
                                     datestr, config.region,
                                     config.service)
  #print 'c_string:\n%s' % c_string
  #print 'string_to_sign:\n%s' % string_to_sign

  buf.append(hmac.new(signing_key, string_to_sign, hashlib.sha256).hexdigest())

  return ''.join(buf)


class Bucket:

  def __init__(self, aws_config):
    self.config = aws_config
    self.connection = None
    self.debug_log = None
    self.last_response = None

  def _debug(self, msg):
    if self.debug_log: self.debug_log.write(msg, '\n')
    #print msg

  def _make_request(self, method, path, headers=None, s3obj=None):
    # Note that all of the hard stuff here is handling the HTTP
    # requests and getting the signature right.  This is not S3; this
    # applies to all of the AWS API.  Someday this will probably need
    # to be moved to a superclass of "AWSRequest", where S3 functions
    # are just one case.

    # lowercase all the header names now, because all the bizarre
    # signing algorithm requires it.
    if headers:
      h = {}
      for k, v in headers.items():
        h[k.lower()] = str(v)
      headers = h
    else:
      headers = {}

    if s3obj:
      payload = s3obj.data
    else:
      payload = ''

    if method != 'PUT' and s3obj:
      raise BucketError('non-PUT request cannot take an object')

    if not path.startswith('/'): path = '/' + path

    if not 'x-amz-date' in headers:
      headers['x-amz-date'] = time.strftime(X_AMZ_DATE_FMT, time.gmtime())

    if not 'host' in headers:
      headers['host'] = self.config.bucket_name + '.' + self.config.server

    if not 'x-amz-content-sha256' in headers:
      headers['x-amz-content-sha256'] = hashlib.sha256(payload).hexdigest()

    # sign the request with 'Authorization' header
    headers['authorization'] = auth_header_v4(method, path, headers,
                                              self.config)

    self._debug('Request: %s %s' % (method, path))
    self._debug('Opening connection: %s' % headers['host'])
    if self.connection: self.connection.close()
    self.connection = httplib.HTTPSConnection(headers['host'])
    self.connection.request(method, path, payload, headers)
    ret = self.connection.getresponse()
    self._debug('Response: %s (%s)' % (ret.status, ret.reason))

    return ret

  def create_bucket(self, bucket_name=None, headers=None):
    return self._make_request('PUT', bucket_name or self.config.bucket_name,
                              headers=headers)

  def delete_bucket(self, bucket_name=None, headers=None):
    return self._make_request('DELETE', bucket_name or self.config.bucket_name,
                              headers=headers)

  def get_bucket_acl(self, headers=None):
    return self.get_acl('', headers=headers)

  def put_bucket_acl(self, acl_xml_document, headers=None):
    return self.put_acl('', acl_xml_document, headers=headers)
  
  def list_bucket(self, key_prefix=None, headers=None):
    entries = []
    params = {'list-type': '2'}
    stringify = lambda p: '%s=%s' % (p, urllib.quote_plus(str(params[p])))
    if key_prefix: params['prefix'] = key_prefix

    while True:
      path = '/?' + '&'.join(map(stringify, params.keys()))
      r = self._make_request('GET', path, headers=headers)
      root = ET.fromstring(r.read())
      for entry in root.findall('aws:Contents', AWS_NS):
        entries.append(ListBucketEntry(entry))
      if root.find('aws:IsTruncated', AWS_NS).text == 'true':
        ct = root.find('aws:NextContinuationToken', AWS_NS).text
        params['continuation-token'] = ct
      else:
        break

    return entries

  def put(self, key, obj, headers=None):
    if not isinstance(obj, S3Object): obj = S3Object(obj)
    if not headers: headers = {}
    for k, v in obj.metadata.items(): headers[METADATA_PREFIX + k] = v
    try:
      r = self._make_request('PUT', urllib.quote(key),
                             headers=headers, s3obj=obj)
      return r
    except Exception:
      # failures happen here a lot, so try to capture the HTTP response so
      # the upstream exception handler has a chance to look at it.
      if self.connection:
        self.last_response = self.connection.getresponse()
        self.last_response.body = self.last_response.read()
      raise

  def get(self, key, headers=None):
    r = self._make_request('GET', urllib.quote(key), headers=headers)
    return GetResponse(r)
  
  def delete(self, key, headers=None):
    return self._make_request('DELETE', urllib.quote(key), headers=headers)

  def put_acl(self, key, acl_xml_document, headers=None):
    return self._make_request('PUT',
                              '%s?acl' % urllib.quote(key),
                              headers=headers,
                              s3obj=acl_xml_document)
  
  def get_acl(self, key, headers=None):
    r = self._make_request('GET',
                           '/%s?acl' % urllib.quote(key),
                           headers=headers)
    return GetResponse(r)

  def close(self):
    self.connection.close()
    self.connection = None


class ListBucketEntry(object):
  def __init__(self, element):
    assert element.tag.endswith('Contents')
    for k in ('Key', 'LastModified', 'ETag', 'Size', 'StorageClass'):
      self.__dict__[k.lower()] = element.find('aws:%s' % k, AWS_NS).text
    self.size = int(self.size)


class GetResponse(S3Object):
  def __init__(self, http_response):
    self.http_response = http_response
    self.body = http_response.read()
    response_headers = http_response.msg   # older pythons don't have getheaders
    metadata = self.get_aws_metadata(response_headers)
    super(GetResponse, self).__init__(self.body, metadata)

  def get_aws_metadata(self, headers):
    metadata = {}
    for hkey in headers.keys():
      if hkey.lower().startswith(METADATA_PREFIX):
        metadata[hkey[len(METADATA_PREFIX):]] = headers[hkey]
        del headers[hkey]
    return metadata


def StoreChunkedFile(stream, bucket, key_prefix, chunk_size=None,
                     stdout=None, stderr=None):

    if not chunk_size: chunk_size = 50 * 2**20 # 50 MB
    chunk_num = 0
    md5 = hashlib.md5()

    while True:

      data = stream.read(chunk_size)
      md5.update(data)
      if len(data) == 0: break
      key = '%s/chunk_%06d' % (key_prefix, chunk_num)
      tries = 20

      while True:
        try:
          if stdout:
            stdout.write('uploading %s (%ld bytes)\n' % (key, len(data)))
          r = bucket.put(key, data)
          if r.status >= 300: raise AWSHttpError(r)
          break # this is the exit point if the upload succeeds
        except Exception, e:
          if bucket and bucket.last_response:
            err = AWSHttpError(bucket.last_response)
            if stderr: stderr.write(err.message + '\n')
          elif stderr:
            stderr.write('error: %s\n' % e)
          tries -= 1
          if not tries: raise # this is the exit point if we give up
          to_sleep = min(600, 2 ** (20 - tries))
          if stderr:
            stderr.write('trying again in %ds (%d remaining)\n' %
                         (to_sleep, tries))
          time.sleep(to_sleep)

      chunk_num += 1
      if len(data) < chunk_size: break

    stream.close()
    return md5.hexdigest()


def RetrieveChunkedFile(stream, bucket, key_prefix, stdout=None, stderr=None):
  """This is easier, because we don't have to care what the chunks are
  named or how big they are.  We just take everything matching
  key_prefix and concatenate their contents.
  """
  if not key_prefix.endswith('/'): key_prefix += '/'
  chunks = sorted([x.key for x in bucket.list_bucket(key_prefix)])
  md5 = hashlib.md5()
  if stdout:
    stdout.write('%ld chunks to assemble\n' % len(chunks))
  for k in chunks:
    if stdout: stdout.write('downloading %s\n' % k)
    data = bucket.get(k).data
    md5.update(data)
    stream.write(data)
  return md5.hexdigest()


def DeleteChunkedFile(bucket, key_prefix, stdout=None, stderr=None):
  if not key_prefix.endswith('/'): key_prefix += '/'
  chunks = sorted([x.key for x in bucket.list_bucket(key_prefix)])
  if stdout: stdout.write('%ld chunks to delete\n' % len(chunks))
  for k in chunks:
    if stdout: stdout.write('deleting %s\n' % k)
    bucket.delete(k)


class stream_generator(object):
  def __init__(self, data):
    self.data = data

  def read(self, n):
    block = self.data[:n]
    self.data = self.data[n:]
    return block

  def close(self):
    self.data = ''


if __name__ == '__main__':

  print 'Running S3 integration tests'
  print 'Reading config file'
  cfg = AWSConfig()
  for k, v in cfg.__dict__.items():
    if k == 'secret_access_key': v = v[:4] + '...'
    print '  %-17s = %s' % (k, v)

  b = Bucket(cfg)

  # Run example API call from the python sample program in the
  # AWS API documentation.
  cfg.service = 'ec2'
  method = 'GET'
  path = '/?Action=DescribeRegions&Version=2013-10-15'
  headers = {'Host': 'ec2.amazonaws.com'}
  signed_headers, cstr = canonical_string_v4(method, path, headers)

  def _print_status(r):
    print '  return status %d (%s)' % (r.status, r.reason)
    if r.status >= 300:
      print '  ----- body of response -----'
      print r.read()
      print '  ----------------------------'

  def _print_checksum(c1, c2):
    if c1 == c2:
      print '  md5 checksum matches: %s' % c1
    else:
      print '  md5 checksum failed'
      print '  was: %s' % c1
      print '  now: %s' % c2

  def _print_time(start_time, byte_count):
    elapsed_time = time.time() - start_time
    print '  %.2f seconds / %ld bytes per second' % \
      (elapsed_time, int(byte_count / elapsed_time))

  print 'Listing EC2 regions'
  _print_status(b._make_request(method, path, headers))

  cfg.service = 's3'
  print 'Listing buckets'
  _print_status(b._make_request('GET', '/', {'host': 's3.amazonaws.com'}))

  test_bucket_name = cfg.access_key_id.lower() + '-s3.py-test-bucket'
  print 'Creating test bucket %s' % test_bucket_name
  _print_status(b.create_bucket(test_bucket_name))

  print 'Deleting test bucket %s' % test_bucket_name
  _print_status(b.delete_bucket(test_bucket_name))

  print 'Listing contents of %s' % cfg.bucket_name
  lst = b.list_bucket()
  print '  returned %ld entries' % len(lst)
  for i in (0, 1, 2, 3):
    if i+1 > len(lst): break
    print '  %s' % lst[i].key

  test_key = '0000_s3.py:test/key'
  test_data = 'I\'m Mr. Meeseeks!  Caaaaaaaan Do!'
  print 'Writing test key %s' % test_key
  _print_status(b.put(test_key, S3Object(test_data)))

  print 'Reading test key %s' % test_key
  r = b.get(test_key)
  _print_status(r.http_response)
  assert r.data == test_data

  print 'Reading ACL of test key %s' % test_key
  r = b.get_acl(test_key)
  _print_status(r.http_response)
  test_acl = r.data

  print 'Writing ACL of test key %s' % test_key
  _print_status(b.put_acl(test_key, S3Object(test_acl)))

  test_data = open('/dev/urandom').read(12 * 2**20)
  orig_md5 = hashlib.md5(test_data).hexdigest()

  print 'Writing a big fatty blob (%ld bytes)' % len(test_data)
  start_time = time.time()
  _print_status(b.put(test_key, S3Object(test_data)))
  _print_time(start_time, len(test_data))

  print 'Reading the big fatty blob'
  start_time = time.time()
  r = b.get(test_key)
  _print_status(r.http_response)
  _print_time(start_time, len(r.data))
  new_md5 = hashlib.md5(r.data).hexdigest()
  _print_checksum(orig_md5, new_md5)

  print 'Deleting test key %s' % test_key
  _print_status(b.delete(test_key))

  print 'Writing a big fatty key in chunks'
  start_time = time.time()
  new_md5 = StoreChunkedFile(stream_generator(test_data),
                             b, test_key, chunk_size=2*2**20,
                             stdout=sys.stdout, stderr=sys.stderr)
  _print_time(start_time, len(test_data))
  _print_checksum(orig_md5, new_md5)

  print 'Reading back the big fatty key from chunks'
  start_time = time.time()
  new_md5 = RetrieveChunkedFile(open('/dev/null', 'w'), b, test_key,
                                stdout=sys.stdout, stderr=sys.stderr)
  _print_time(start_time, len(test_data))
  _print_checksum(orig_md5, new_md5)

  print 'Deleting chunked key %s' % test_key
  DeleteChunkedFile(b, test_key, stdout=sys.stdout, stderr=sys.stderr)
