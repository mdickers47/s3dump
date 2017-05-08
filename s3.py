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

import base64
import hashlib
import hmac
import httplib
import re
import time
import urllib
import xml.sax

METADATA_PREFIX = 'x-amz-meta-'

class Error(Exception): pass

class AWSConfigError(Error): pass

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

class BucketError(Error): pass

class Bucket:

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
      self.connection.request(method, path, data, h)
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

