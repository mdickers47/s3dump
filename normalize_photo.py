#!/usr/bin/env python

import argparse
import hashlib
import os
import re
import shutil
import sys
import time

JHEAD_TIME = '%Y:%m:%d %H:%M:%S'


DATE_RE_SUBS = { 'Y': r'(?P<Y>[12]\d{3})',
                 'm': r'(?P<m>[01]?\d)',
                 'd': r'(?P<d>[0123]?\d)',
                 'H': r'(?P<H>[012]?\d)',
                 'M': r'(?P<M>[012345]\d)',
                 'S': r'(?P<S>[012345]\d)',
                 'A': r'(?P<A>AM|am|PM|pm)',
                 'T': r'(?P<T>jpe?g|gif|png|PNG)',
                 '1': r'(\(\d\))?'}

FILE_SCHEMES = (
  r'IMG_{Y}{m}{d}_{H}{M}{S}{1}\.{T}',
  r'IMG_{Y}{m}{d}_{H}{M}{S}\d*(_HDR)?\.{T}',
  r'{Y}-{m}-{d}\.{T}',
  r'download_{Y}{m}{d}_{H}{M}{S}{1}\.{T}',
  r'signal-{Y}-{m}-{d}-{H}{M}{S}{1}.jpg',
  r'textsecure-{Y}-{m}-{d}-{H}{M}{S}{1}.jpg',
  r'Screen Shot {Y}-{m}-{d} at {H}\.{M}\.{S} {A}{1}.{T}',
  r'Screenshot_{Y}-{m}-{d}-{H}-{M}-{S}.png',
  r'IMG-{Y}{m}{d}-WA\d+\.jpg',
  r'IMG_{Y}{m}{d}_{H}{M}{S}-(ANIMATION|MOTION|SMILE).{T}',
  r'VID-{Y}{m}{d}-WA\d+\.gif',
  )


def compile_REs():
  filename_re = []
  for f in FILE_SCHEMES:
    for k, v in DATE_RE_SUBS.items():
      f = f.replace('{%s}' % k, v)
    #print f
    filename_re.append(re.compile(f))
  return filename_re  


def time_from_fname(fname, filename_re):
  for r in filename_re:
    m = r.match(fname)
    if m: break
  else:
    sys.stdout.write('   Can\'t parse filename: %s\n' % fname)
    return None
  groups = m.groupdict()
  for k in DATE_RE_SUBS.keys(): groups.setdefault(k, 0)
  normalized = '%(Y)s:%(m)s:%(d)s %(H)s:%(M)s:%(S)s' % groups
  normalized = time.strptime(normalized, JHEAD_TIME)
  return normalized

  
def file_jhead(fname):
  props = {}
  for line in os.popen('jhead "%s" 2>/dev/null' % fname):
    line = line.strip()
    if not line: continue
    #print line
    key, val = line.split(':', 1)
    props[key.strip()] = val.strip()
  return props


def file_md5(fname):
  return hashlib.md5(open(fname, 'r').read()).hexdigest()


def file_ident(fname):
  ident = os.popen('identify "%s"' % fname).read()
  fields = ident[len(fname):].split()
  if re.match('\[\d\]', fields[0]): del fields[0]
  filetype, resolution = fields[0], fields[1]
  return filetype, resolution

  
def normalize_ext(fname):
  ext = fname.split('.')[-1]
  ext = ext.lower()
  if ext == 'jpeg': ext = 'jpg'
  assert ext in ('jpg', 'gif', 'png')
  return ext


def max_dim(resolution):
  atoi = lambda a: int(a.strip())
  return max(map(atoi, resolution.split('x')))


def size_category(resolution):
  md = max_dim(resolution)
  if md > 1200: return 'L'
  if md > 640:  return 'M'
  return 'S'


def crash(msg):
  sys.stderr.write(msg + '\n')
  sys.exit(1)


def count_by_prefix(md5_index, prefix):
  p = lambda fname: fname.startswith(prefix)
  return len(filter(p, md5_index.values()))


if __name__ == '__main__':

  parser = argparse.ArgumentParser()
  parser.add_argument('-i', dest='in_path', help='input path')
  parser.add_argument('-o', dest='out_path', help='output path')
  args = parser.parse_args()

  
  if not (args.in_path and os.path.isdir(args.in_path)):
    crash('input path bad or missing')
  if not (args.out_path and os.path.isdir(args.out_path)):
    crash('output path bad or missing')

  md5_index = {}
  
  for f in os.listdir(args.out_path):
    sys.stdout.write('Hashing %s: ' % f)
    md5 = file_md5(os.path.join(args.out_path, f))
    md5_index[md5] = f
    sys.stdout.write(md5 + '\n')

  sys.stdout.write('\nHashed %d preexisting output files.\n\n' %
                   len(md5_index.keys()))
  filename_re = compile_REs()

  
  for f in os.listdir(args.in_path):
    sys.stdout.write('%s: ' % f)
    if not os.path.isfile(os.path.join(args.in_path, f)):
      sys.stdout.write('not a file\n')
      continue

    md5 = file_md5(os.path.join(args.in_path, f))
    if md5 in md5_index:
      sys.stdout.write('matches %s\n' % md5_index[md5])
      continue
    else:
      sys.stdout.write(md5 + '\n')

    try:
      filetype, resolution = file_ident(os.path.join(args.in_path, f))
    except Exception, e:
      sys.stdout.write('   skipping: %s\n' % e)
      continue
      
    sys.stdout.write('   type %s resolution %s\n' % (filetype, resolution))
    timestamp = None
    source = None

    if filetype == 'JPEG':
      props = file_jhead(os.path.join(args.in_path, f))
      if 'Date/Time' in props:
        timestamp = time.strptime(props['Date/Time'], JHEAD_TIME)
        source = 'exif'
      
    if not timestamp:
      timestamp = time_from_fname(f, filename_re)
      source = 'filename'

    if not timestamp:
      timestamp = time.strptime(props['File date'], JHEAD_TIME)
      source = 'mtime'

    sys.stdout.write('   Normalized timestamp %s is from %s\n' %
                     (time.strftime(JHEAD_TIME, timestamp), source))

    prefix, ext = { 'JPEG': ('img', 'jpg'),
                    'GIF':  ('img', 'gif'),
                    'PNG':  ('img', 'png'),
                    'PBM':  ('img', 'pdf'),
                    }[filetype]

    newfile = prefix + '_'
    newfile += time.strftime('%Y%m%d_%H%M', timestamp) + '_'
    newfile += '%02d' % count_by_prefix(md5_index, newfile)
    if resolution: newfile += size_category(resolution)
    newfile += '.' + ext

    sys.stdout.write('   New file: %s\n' % newfile)
    md5_index[md5] = newfile

    shutil.copy2(os.path.join(args.in_path, f),
                 os.path.join(args.out_path, newfile))
    


    

        
