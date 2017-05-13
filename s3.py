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
import time
import urllib
import xml.sax

METADATA_PREFIX = 'x-amz-meta-'
SIG_ALGORITHM = 'AWS4-HMAC-SHA256'
X_AMZ_DATE_FMT = '%Y%m%dT%H%M%SZ'

class Error(Exception): pass

class AWSConfigError(Error): pass

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


class BucketError(Error): pass


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
  
  def list_bucket(self, options=None, headers=None):
    self.entries = []
    if not options: options = {} # this silences a pychecker error
    while True:
      path = '/'
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


class S3Object(object):
  def __init__(self, data, metadata={}):
    self.data = data
    self.metadata = metadata

    
class ListBucketError(Error): pass


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
      print 'HTTP response body:'
      print self.body
      raise ListBucketError('HTTP error %d (%s)' % (http_response.status,
                                                    http_response.reason))
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
  l = b.list_bucket()
  print '  returned %ld entries' % len(l.entries)
  for i in (0, 1, 2, 3):
    if i+1 > len(l.entries): break
    print '  %s' % l.entries[i].key

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

  #test_data = '0123456789abcde' * 1024 * 1024
  test_data = open('/dev/urandom').read(12 * 2**20)
  print 'Writing a big fatty key (%ld bytes)' % len(test_data)
  start_time = time.time()
  _print_status(b.put(test_key, S3Object(test_data)))
  elapsed_time = time.time() - start_time
  print '%.2f seconds / %ld bytes per second' % \
      (elapsed_time, int(len(test_data) / elapsed_time))

  print 'Deleting test key %s' % test_key
  _print_status(b.delete(test_key))
