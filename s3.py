#!/usr/bin/env python
"""Amazon S3 API client in plain Python.

This is a plain-jane python library that implements several Amazon
AWS REST client functions with the 'version 4' signature scheme.

Mainly you need to instantiate an AWSConfig by supplying a path to a
config file.  The config file must at least provide an API key and
bucket name.  You then instantiate a Bucket using the AWSConfig.  The
Bucket now provides get(), put(), list(), and other things vaguely
similar to a key-value blob store.

StoreChunkedFile, RetrieveChunkedFile, and DeleteChunkedFile implement
a crude mechanism for making operations with very large files more
reliable.  There is not much need for them since the API now provides
multipart upload and download.

This started in 2006 with some ingredients taken from Amazon sample
code.  Since then, calling conventions and signature requirements have
all changed, so there is little to none of that code left.
Nevertheless, the following is a notice that came with it:

  This software code is made available "AS IS" without warranties of any
  kind.  You may copy, display, modify and redistribute the software
  code either by itself or as incorporated into your code; provided that
  you do not remove any proprietary notices.  Your use of this software
  code is at your own risk and you waive any claim against Amazon
  Digital Services, Inc. or its affiliates with respect to your use of
  this software code. (c) 2006 Amazon Digital Services, Inc. or its
  affiliates.

The rest is Copyright 2006-2017 Mikey Dickerson.  Use is permitted
under the same terms as the above notice.
"""

import base64
import hashlib
import hmac
import httplib
import os
import sys
import time
import urllib
import xml.etree.ElementTree as ET

METADATA_PREFIX = 'x-amz-meta-'
SIG_ALGORITHM = 'AWS4-HMAC-SHA256'
X_AMZ_DATE_FMT = '%Y%m%dT%H%M%SZ'
AWS_NS = { 'aws': 'http://s3.amazonaws.com/doc/2006-03-01/' }
STORAGE_CLASS_HEADER = 'x-amz-storage-class'
STORAGE_STD, STORAGE_IA, STORAGE_RR = ('STANDARD', 'STANDARD_IA',
                                       'REDUCED_REDUNDANCY')

# This is the size beyond which put_streaming() will automatically
# switch to multipart upload.  The maximum number of parts S3 will
# take is 10,000.  Therefore the largest object you can store via
# put_streaming() is 10,000 * MIN_PART_SIZE.
MIN_PART_SIZE = 20 * 2**20 # actual S3 minimum is 5MB as of May 2017

class Error(Exception): pass
class AWSConfigError(Error): pass
class BucketError(Error): pass


class AWSHttpError(Error):
  def __init__(self, http_response, exception=None):
    self.message = ''
    if exception: self.message = str(exception) + '\n'
    if http_response and 'status' in http_response.__dict__:
      self.message += 'Amazon returned HTTP %d (%s)\n' % \
                      (http_response.status, http_response.reason)
    if http_response and 'body' in http_response.__dict__:
      self.message += ('-' * 20 + '\n' + http_response.body + '\n' +
                       '-' * 20 + '\n')
    elif http_response and 'read' in http_response.__dict__:
      self.message += ('-' * 20 + '\n' + http_response.read() + '\n' +
                       '-' * 20 + '\n')

  def __str__(self):
    return self.message


class S3Object(object):
  def __init__(self, data, metadata={}):
    self.data = data
    self.metadata = metadata
    self.status = None # these are copied from HTTPResponse when the
    self.reason = None # object was retrieved from S3
    self.headers = {}

  def getheader(self, h):
    return self.headers[h.lower()]


class AWSConfig(object):
  def __init__(self, config_file=os.path.expanduser('~/.s3keys')):
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

    for s in ('access_key_id', 'secret_access_key', 'bucket_name'):
      if not self.__dict__[s]:
        raise AWSConfigError('%s must be defined' % s)


def canonical_string_v4(method, path, headers):
  """Refer to AWS documentation: 'Signature Calcuations for the
  Authorization Header: Transferring Payload in a Single Chunk (AWS
  Signature Version 4)'
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

  # these are discovered on the fly, usually.
  must_sign_if_present = ('content-type', 'content-md5', 'date')
  for h in headers.keys():
    if h in must_sign_if_present or h.startswith('x-amz-'):
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
    self.multipart_upload_id = None
    self.multipart_upload_key = None
    self.multipart_upload_parts = None
    self.persistent_headers = {}
    self.ratelimit = None
    self.storage_class = None

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
      for k, v in headers.items(): h[k.lower()] = str(v).strip()
      headers = h
    else:
      headers = {}

    for k, v in self.persistent_headers.items():
      if k.lower() not in headers:
        headers[k.lower()] = str(v).strip()

    if s3obj:
      """Modify headers dict with metadata about the object."""
      payload = s3obj.data
      for k, v in s3obj.metadata.items(): headers[METADATA_PREFIX + k] = v
    else:
      payload = ''

    headers['content-length'] = str(len(payload))
    d = hashlib.md5(payload).digest()
    headers['content-md5'] = base64.encodestring(d).strip()

    if not 'x-amz-date' in headers:
      headers['x-amz-date'] = time.strftime(X_AMZ_DATE_FMT, time.gmtime())

    if not 'host' in headers:
      headers['host'] = self.config.bucket_name + '.' + self.config.server

    if not 'x-amz-content-sha256' in headers:
      headers['x-amz-content-sha256'] = hashlib.sha256(payload).hexdigest()

    # sign the request with 'Authorization' header
    headers['authorization'] = auth_header_v4(method, path, headers,
                                              self.config)

    if not path.startswith('/'): path = '/' + path
    res = None

    try:
      self._debug('Request: %s %s' % (method, path))
      self._debug('Opening connection: %s' % headers['host'])
      if self.connection: self.connection.close()
      self.connection = httplib.HTTPSConnection(headers['host'])

      # if we were not trying to do the ratelimiting, this could be simply:
      #self.connection.request(method, path, payload, headers)
      #return self.connection.getresponse()

      self.connection.putrequest(method, path, skip_host=True)
      for k, v in headers.items(): self.connection.putheader(k, v)
      self.connection.endheaders()
      WriteWithRatelimit(self.connection, payload, self.ratelimit)
      res = self.connection.getresponse()

    except Exception, e:
      # try really hard to capture everything AWS sent in response, even
      # if we were killed mid-request by e.g. TCP reset, because it usually
      # explains the error which can otherwise be impossible to guess.
      if not res:
        try:
          res = self.connection.getresponse()
          res.body = res.read()
        except:
          pass
      raise AWSHttpError(res, exception=e)

    # now interpret the response.  If it is HTTP 2xx, save the headers
    # and metadata and response body, and return an S3Object.  If it is
    # >= HTTP 300, throw exception.

    self._debug('Response: %s (%s)' % (res.status, res.reason))
    if res.status >= 300:
      res.body = res.read()
      e = AWSHttpError(res)
      self._debug(e.message)
      raise e

    headers = {}
    for k, v in res.getheaders():
      self._debug('Header %s: %s' % (k, v))
      headers[k.lower()] = v.strip()

    metadata = {}
    for k in filter(lambda x: x.lower().startswith(METADATA_PREFIX),
                    headers.keys()):
      metadata[k[len(METADATA_PREFIX):]] = headers[k]
      del headers[k]
    obj = S3Object(ReadWithRatelimit(res, self.ratelimit), metadata)
    obj.status = res.status
    obj.reason = res.reason
    obj.headers = headers
    return obj

  ##### Any HTTP header (e.g. controlling AWS metadata) can be supplied
  ##### on any request.  But for convenience the calling script can set
  ##### it once on the Bucket() and leave it for all subsequent calls.

  def set_header(self, header, val):
    self.persistent_headers[header] = val

  def delete_header(self, header):
    if header in self.persistent_headers:
      del self.persistent_headers[header]

  ##### This is annoying, but storage_class can't just be set as a
  ##### persistent header and left alone, because AWS fails the
  ##### request if the header is present in certain places including
  ##### multipart upload.

  def set_storage_class(self, storage_class):
    if storage_class == STORAGE_STD:
      self.storage_class = None
    elif storage_class in (STORAGE_IA, STORAGE_RR):
      self.storage_class = storage_class
    else:
      raise BucketError('invalid setting for storage class')

  def _add_storage_class_header(self, headers):
    if self.storage_class:
      headers[STORAGE_CLASS_HEADER] = self.storage_class

  ##### Bucket operations: create, delete, list, set ACL

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
      root = ET.fromstring(r.data)
      for entry in root.findall('aws:Contents', AWS_NS):
        entries.append(ListBucketEntry(entry))
      if root.find('aws:IsTruncated', AWS_NS).text == 'true':
        ct = root.find('aws:NextContinuationToken', AWS_NS).text
        params['continuation-token'] = ct
      else:
        break

    return entries

  ##### Simple put/get/delete, best for small in-memory objects.

  def put(self, key, obj, headers=None):
    if not isinstance(obj, S3Object): obj = S3Object(obj)
    if not headers: headers = {}
    self._add_storage_class_header(headers)
    return self._make_request('PUT', urllib.quote(key),
                              headers=headers, s3obj=obj)

  def get(self, key, headers=None):
    return self._make_request('GET', urllib.quote(key), headers=headers)
  
  def delete(self, key, headers=None):
    return self._make_request('DELETE', urllib.quote(key), headers=headers)

  ##### Streaming put/get, good when you don't know the size of the
  ##### object, or want to avoid ever materializing the whole thing in
  ##### RAM.

  def put_streaming(self, key, stream, headers=None, stdout=None, stderr=None):
    """Read object data from stream.  If stream is big enough, do a
    multipart upload (avoids ever materializing the entire blob in
    RAM).  Otherwise do a simple PUT.
    """
    data_block = stream.read(MIN_PART_SIZE)
    if len(data_block) < MIN_PART_SIZE:
      r = self.put(key, data_block, headers=headers)
    else:
      block_count = 1
      self.begin_multipart(key, headers=headers)
      TryReallyHard(lambda: self.put_multipart(data_block, headers=headers),
                    'uploading %ld byte part (1)' % len(data_block),
                    stdout=stdout, stderr=stderr)
      while len(data_block) == MIN_PART_SIZE:
        data_block = stream.read(MIN_PART_SIZE)
        block_count += 1
        msg = 'uploading %ld byte part (%d)' % (len(data_block), block_count)
        TryReallyHard(lambda: self.put_multipart(data_block, headers=headers),
                      msg, stdout=stdout, stderr=stderr)
      r = self.complete_multipart(headers=headers)
    stream.close()
    return r

  def get_streaming(self, key, stream, headers=None, stdout=None, stderr=None):
    if not headers: headers = {}
    ptr = 0
    while True:
      r = 'bytes=%d-%d' % (ptr, ptr + MIN_PART_SIZE - 1)
      headers['Range'] = r
      if stdout: stdout.write('retrieving %s\n' % r)
      r = self.get(key, headers=headers)
      stream.write(r.data)
      ptr += MIN_PART_SIZE
      if len(r.data) < MIN_PART_SIZE: break
    stream.close()
    return r

  ##### ACL put/get

  def put_acl(self, key, acl_xml_document, headers=None):
    return self._make_request('PUT',
                              '%s?acl' % urllib.quote(key),
                              headers=headers,
                              s3obj=acl_xml_document)
  
  def get_acl(self, key, headers=None):
    return  self._make_request('GET',
                               '/%s?acl' % urllib.quote(key),
                               headers=headers)

  ##### Multipart put, use when you have a big object divided into
  ##### pieces and you know in advance.

  def begin_multipart(self, key, headers=None):
    if (self.multipart_upload_key or self.multipart_upload_id or
        self.multipart_upload_parts):
      raise BucketError('multipart upload already inititated.')

    if not headers: headers = {}
    self._add_storage_class_header(headers)

    r = self._make_request('POST', '%s?uploads' % urllib.quote(key),
                           headers=headers)
    root = ET.fromstring(r.data)
    if not root.tag.endswith('InitiateMultipartUploadResult'):
      raise BucketError('AWS responded with unexpected element %s' % root.tag)
    b = root.find('aws:Bucket', AWS_NS).text
    if b != self.config.bucket_name:
      raise BucketError('AWS responded with unexpected bucket name %s' % b)
    k = root.find('aws:Key', AWS_NS).text
    if k != key:
      raise BucketError('AWS responded with unexpected key %s' % k)

    self.multipart_upload_key = key
    self.multipart_upload_id = root.find('aws:UploadId', AWS_NS).text
    self.multipart_upload_parts = []
    return r

  def put_multipart(self, obj, headers={}):
    if None in (self.multipart_upload_key, self.multipart_upload_id,
                self.multipart_upload_parts):
      raise BucketError('multipart upload must be initialized first.')
    if not isinstance(obj, S3Object): obj = S3Object(obj)
    path = '%s?partNumber=%d&uploadId=%s' % \
           (urllib.quote(self.multipart_upload_key),
            len(self.multipart_upload_parts) + 1, self.multipart_upload_id)

    r = self._make_request('PUT', path, s3obj=obj, headers=headers)
    self.multipart_upload_parts.append(r.getheader('ETag'))
    return r

  def complete_multipart(self, headers={}):
    body = []
    body.append('<CompleteMultipartUpload>')
    for i, p in enumerate(self.multipart_upload_parts):
      body.append('<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>' \
                  % (i + 1, p))
    body.append('</CompleteMultipartUpload>')
    body = '\n'.join(body)
    path = '/%s?uploadId=%s' % (urllib.quote(self.multipart_upload_key),
                                urllib.quote(self.multipart_upload_id))
    r = self._make_request('POST', path, s3obj=S3Object(body),
                           headers=headers)
    root = ET.fromstring(r.data)
    if root.tag.endswith('CompleteMultipartUploadResult'):
      self.multipart_upload_key = None
      self.multipart_upload_id = None
      self.multipart_upload_parts = None
    elif root.tag.endswith('Error'):
      raise BucketError(root.find('aws:Message', AWS_NS).text)
    else:
      raise BucketError('AWS responded with unexpected element %s' % root.tag)

    return r

  def abort_multipart(self, headers={}):
    path = '/%s?uploadId=%s' % (urllib.quote(self.multipart_upload_key),
                                urllib.quote(self.multipart_upload_id))
    r = self._make_request('DELETE', path, headers=headers)
    self.multipart_upload_key = None
    self.multipart_upload_id = None
    self.multipart_upload_parts = None
    return r

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


def ReadWithRatelimit(httpresponse, bytes_per_sec):
  """Call read() up to 4 times per second, with naps in between that
  are adjusted to try to target bytes_per_second per second.
  """
  if not bytes_per_sec: return httpresponse.read()
  segment_size = bytes_per_sec / 4
  if segment_size < 1: raise Error('impossibly low rate limit')
  segment = ' ' * segment_size
  data = ''
  last_read = time.time()
  while len(segment) == segment_size:
    segment = httpresponse.read(segment_size)
    data += segment
    to_sleep = max(0, 0.25 - (time.time() - last_read))
    last_read = time.time()
    time.sleep(to_sleep)
  return data


def WriteWithRatelimit(httpconn, data, bytes_per_sec):
  if not bytes_per_sec: return httpconn.send(data)
  segment_size = bytes_per_sec / 4
  if segment_size < 1: raise Error('impossibly low rate limit')
  last_read = time.time()
  while data:
    httpconn.send(data[:segment_size])
    data = data[segment_size:]
    to_sleep = max(0, 0.25 - (time.time() - last_read))
    last_read = time.time()
    time.sleep(to_sleep)


def TryReallyHard(what, desc=None, stdout=None, stderr=None):
  """Try up to 20 times to complete what() without catching an
  exception.  Comments on how it's going are written to stdout and
  stderr if provided.  If we fail 20 times, the last Exception is
  raised.  Otherwise we return the return value of what().
  """
  tries = 20
  ret = None
  while True:
    try:
      if desc and stdout: stdout.write(desc + '\n')
      ret = what()
      return ret # this is the exit of 'while True' if we succeed
    except Exception, e:
      if stderr: stderr.write('failed: %s\n' % e.message)
      tries -= 1
      if not tries: raise # this is the exit if we give up
      to_sleep = min(600, 2 ** (20 - tries))
      if stderr:
        stderr.write('trying again in %ds (%d remaining)\n' % (to_sleep, tries))
      time.sleep(to_sleep)


def StoreChunkedFile(stream, bucket, key_prefix, chunk_size=MIN_PART_SIZE,
                     stdout=None, stderr=None):
    chunk_num = 0
    md5 = hashlib.md5()

    while True:
      data = stream.read(chunk_size)
      md5.update(data)
      if len(data) == 0: break
      key = '%s/chunk_%06d' % (key_prefix, chunk_num)
      TryReallyHard(lambda: bucket.put(key, data),
                    'uploading %s (%ld bytes)' % (key, len(data)),
                    stdout=stdout, stderr=stderr)
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


class stream_consumer(object):
  def __init__(self):
    self.byte_count = 0
    self.md5 = hashlib.md5()

  def write(self, data):
    self.byte_count += len(data)
    self.md5.update(data)

  def close(self): pass


if __name__ == '__main__':

  print 'Running S3 integration tests'
  print 'Reading config file'
  cfg = AWSConfig()
  for k, v in cfg.__dict__.items():
    if k == 'secret_access_key': v = v[:4] + '...'
    print '  %-17s = %s' % (k, v)

  b = Bucket(cfg)

  def _print_status(r):
    print '  return status %d (%s)' % (r.status, r.reason)
    if r.status >= 300:
      print '  ----- body of response -----'
      print r.data
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

  # These may fail with an IAM key that is restricted to a specific
  # bucket, which is not a problem if you are only going to be
  # reading and writing that bucket.

  print 'Listing EC2 regions'
  cfg.service = 'ec2'
  method = 'GET'
  path = '/?Action=DescribeRegions&Version=2013-10-15'
  headers = {'Host': 'ec2.amazonaws.com'}
  try:
    _print_status(b._make_request(method, path, headers))
  except AWSHttpError, e:
    print e

  cfg.service = 's3'
  print 'Listing buckets'
  try:
    _print_status(b._make_request('GET', '/', {'host': 's3.amazonaws.com'}))
  except AWSHttpError, e:
    print e

  test_bucket_name = cfg.access_key_id.lower() + '-s3.py-test-bucket'
  try:
    print 'Creating test bucket %s' % test_bucket_name
    _print_status(b.create_bucket(test_bucket_name))
    print 'Deleting test bucket %s' % test_bucket_name
    _print_status(b.delete_bucket(test_bucket_name))
  except AWSHttpError, e:
    print e

  # You probably need the rest of these tests to succeed.

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
  _print_status(r)
  assert r.data == test_data

  print 'Reading ACL of test key %s' % test_key
  r = b.get_acl(test_key)
  _print_status(r)
  test_acl = r.data

  print 'Writing ACL of test key %s' % test_key
  _print_status(b.put_acl(test_key, S3Object(test_acl)))

  print 'Writing a multipart upload'
  orig_md5 = hashlib.md5()
  start_time = time.time()
  _print_status(b.begin_multipart(test_key))
  for i in range(4):
    # Documentation says 5MB is the smallest allowed part size.
    test_data = open('/dev/urandom').read(5 * 2**20)
    orig_md5.update(test_data)
    _print_status(b.put_multipart(test_data))
  test_data = open('/dev/urandom').read(1 * 2**20 + 11)
  orig_md5.update(test_data)
  _print_status(b.put_multipart(test_data))
  _print_status(b.complete_multipart())
  _print_time(start_time, 21 * 2**20 + 11)

  print 'Reading back multipart-assembled blob'
  start_time = time.time()
  r = b.get(test_key)
  _print_status(r)
  _print_time(start_time, len(r.data))
  new_md5 = hashlib.md5(r.data).hexdigest()
  _print_checksum(orig_md5.hexdigest(), new_md5)

  print 'Starting a new multipart upload'
  _print_status(b.begin_multipart(test_key))
  _print_status(b.put_multipart(test_data))
  print 'Aborting multipart upload'
  _print_status(b.abort_multipart())

  print 'Setting rate limit to 200kB/s'
  b.ratelimit = 200 * 1024

  test_data = open('/dev/urandom').read(12 * 2**20)
  orig_md5 = hashlib.md5(test_data).hexdigest()
  print 'Writing a big fatty blob (%ld bytes)' % len(test_data)
  start_time = time.time()
  _print_status(b.put(test_key, S3Object(test_data)))
  _print_time(start_time, len(test_data))

  print 'Reading the big fatty blob'
  start_time = time.time()
  r = b.get(test_key)
  _print_status(r)
  _print_time(start_time, len(r.data))
  new_md5 = hashlib.md5(r.data).hexdigest()
  _print_checksum(orig_md5, new_md5)

  print 'Removing rate limit'
  b.ratelimit = None

  print 'Writing a big fatty blob via put_streaming'
  start_time = time.time()
  _print_status(b.put_streaming(test_key, stream_generator(test_data),
                                stdout=sys.stdout, stderr=sys.stderr))
  _print_time(start_time, len(test_data))

  print 'Reading the big fatty blob with get_streaming'
  start_time = time.time()
  sink = stream_consumer()
  _print_status(b.get_streaming(test_key, sink, stdout=sys.stdout,
                                stderr=sys.stderr))
  _print_time(start_time, sink.byte_count)
  _print_checksum(orig_md5, sink.md5.hexdigest())

  print 'Writing a big fatty blob with storage class STORAGE_IA'
  b.set_storage_class(STORAGE_IA)
  start_time = time.time()
  _print_status(b.put_streaming(test_key, stream_generator(test_data),
                                stdout=sys.stdout, stderr=sys.stderr))
  _print_time(start_time, len(test_data))

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
