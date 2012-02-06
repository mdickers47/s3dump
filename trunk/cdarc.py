#!/usr/bin/python
"""cdarc - Maintain an offline catalog of optical discs that mirror files on disk.

Usage: cdarc [-r which] [-v] (scan | burn | init path label)

Copyright 2012 Michael Dickerson <mikey@singingtree.com>
"""

import getopt
import hashlib
import os
import psycopg2 as pydbi # apt-get install python-psycopg2
import psycopg2.extras
import subprocess
import sys
import tempfile

DBSPEC='dbname=cdarc user=cdarc'


def humanize_bytes(b):
  """Convert 2220934 to '2.2M', etc."""
  units = ((40, 'T'), (30, 'G'), (20, 'M'), (10, 'k'))
  for u in units:
    if b > 2 ** u[0]: return '%.1f%s' % (float(b) / 2 ** u[0], u[1])
  return str(b)


def dbquote(s):
  """Enclose any string in ' and double any exising 's."""
  return "'" + s.replace("'", "''") + "'"


def connect():
  return pydbi.connect(DBSPEC)


def dcursor(conn):
  """Construct a dictionary cursor from conn.

  If you need to change the factory class, you only have to do it here.
  """
  return conn.cursor(cursor_factory=psycopg2.extras.DictCursor)


def find_field(text, field):
  """From a multi-line string where each line looks like 'description: value',
  find a given field and extract the string to the right of the colon.

  Used to parse 'wodim -atip' and 'dvd+rw-mediainfo'
  """
  for line in text.split('\n'):
    if not ':' in line: continue
    key, val = map(lambda x: x.strip(), line.split(':'))
    if key == field: return val
  return None


def get_disc_device():
  """Use wodim to guess the cd-rom device."""
  dinfo = subprocess.check_output(['wodim', '-atip'], stderr=subprocess.STDOUT)
  return find_field(dinfo, 'Detected CD-R drive')
  

def get_disc_capacity(device):
  try:
    minfo = subprocess.check_output(['dvd+rw-mediainfo', device],
                                    stderr=subprocess.STDOUT)
  except subprocess.CalledProcessError:
    return 0 # no disc
  blocks = find_field(minfo, 'Free Blocks')
  assert blocks.endswith('*2KB')  # make smarter if necessary
  return int(blocks[:-4]) * 2048


def burn_disc(conn, rootid, capacity, label):

  fh, path_list = tempfile.mkstemp(prefix='cdarc_file_list_')
  img_size = 0
  img_file_ids = []
  cur = dcursor(conn)

  print 'Generating %s volume named %s' % (humanize_bytes(capacity), label)
  print 'Temporary packing list at %s' % path_list
  cur.execute('SELECT id, file, st_size FROM file WHERE disc_vol IS NULL '
              'AND root=%d ORDER BY st_mtime ASC;' % rootid)
  row = cur.fetchone()
  while row:
    if img_size + row['st_size'] > capacity: break
    esc_file = row['file'].replace('\\', '\\\\').replace('=', '\\=')
    os.write(fh, esc_file + '=' + esc_file + '\n')
    img_size += row['st_size']
    img_file_ids.append(row['id'])
    row = cur.fetchone()
  os.close(fh)

  fh, img_file = tempfile.mkstemp(prefix='cdarc_iso_')
  os.close(fh)
  print 'Building iso image at %s (takes a few minutes)' % img_file
  subprocess.check_call(['genisoimage', '-r', '-V', label, '-o', img_file,
                         '-graft-points', '-path-list', path_list, '-quiet'])

  print 'Burning iso image.'
  subprocess.check_call(['wodim', img_file])
  print
  print 'Updating file catalog (%d files stored).' % len(img_file_ids)
  for fid in img_file_ids:
    cur.execute('UPDATE file SET disc_vol=%s, disc_date=NOW() '
                'WHERE id=%d;' % (dbquote(label), fid))
  conn.commit()

  print 'Cleaning up temporary files.'
  os.unlink(path_list)
  os.unlink(img_file)
  print 'Done.'


def guess_label(conn, root):
  """Try to guess a plausible label for the next disc volume for the given root.

  If the largest existing disc label (asciibetically) is something that ends
  with digits ('pictures_0002') then add 1 to the digits and create a string of
  the same length.  Otherwise add the suffix '_0000'.  If no labels exist at
  all, use the root label ('pictures') and add '_0000'.

  Args:
    conn - dbi connection
    root - (id, path, label) tuple
  Returns:
    str suggested label
  """

  cur = conn.cursor()
  cur.execute('SELECT MAX(disc_vol) FROM file WHERE root=%d;' % root[0])
  row = cur.fetchone()
  if row and row[0]:
    # try to find any numeric suffix, cut it off, add 1, put it back
    label = row[0]
    tail = ''
    while label[-1] in '0123456789':
      tail = label[-1] + tail
      label = label[:-1]
    if tail:
      fmt_str = '%0' + str(len(tail)) + 'd'
      tail = fmt_str % (int(tail) + 1)
      label = label + tail
    else:
      label = label + '_0000'
  else:
    label = root[2] + '_0000'

  # double check that we didn't construct a duplicate
  cur.execute('SELECT id FROM file WHERE root=%d AND disc_vol=%s;' 
              % (root[0], dbquote(label)))
  row = cur.fetchone()
  cur.close()
  if row: raise ValueError('label generation went wrong!')

  return label


def get_roots(conn):
  """Find all tree roots known in the table.

  Returns: a list of tuples (int id, str root_path, str label)
  """
  roots = []
  cur = conn.cursor()
  cur.execute('SELECT id, file, disc_vol FROM file WHERE root=0;')
  for row in cur.fetchall(): roots.append((row[0], row[1], row[2]))
  return roots


def get_root(conn, which):
  """Find a root given a string which describes either the path, or the label.

  Returns: a tuple (int id, str root_path, str label)
  """
  cur = conn.cursor()
  cur.execute('SELECT id, file, disc_vol FROM file WHERE file=%s AND root=0;'
              % dbquote(which))
  row = cur.fetchone()
  if row: return (row[0], row[1], row[2])
  cur.execute('SELECT id, file, disc_vol FROM file WHERE disc_vol=%s AND '
              'root=0;' % dbquote(which))
  row = cur.fetchone()
  if row: return (row[0], row[1], row[2])
  raise IndexError('string %s does not match any roots' % which)


def print_status(conn, root):
  cur = dcursor(conn)
  rootid, root, label = root
  print
  print '===== %s (%s)' % (label, root)
  cur.execute('SELECT disc_date FROM file WHERE id=%d;' % rootid)
  row = cur.fetchone()
  if row[0]: print 'Last scan: %s' % row[0].strftime('%Y-%m-%d %H:%M')
  cur.execute('SELECT count(*) AS fc, SUM(st_size) AS bytes FROM file '
              'WHERE root=%d AND disc_vol IS NULL;' % rootid)
  row = cur.fetchone()
  print 'New files: %d' % row['fc']
  print 'New bytes: %ld (%s)' % (row['bytes'], 
                                 humanize_bytes(row['bytes']))
  cur.execute('SELECT count(DISTINCT disc_vol) AS av FROM file '
              'WHERE root=%d;' % rootid)
  row = cur.fetchone()
  print 'Archive volumes: %d' % row['av']
  cur.execute('SELECT disc_vol FROM file WHERE root=%d AND disc_vol '
              'IS NOT NULL ORDER BY disc_date DESC LIMIT 1;' % rootid)
  row = cur.fetchone()
  if row: print 'Last volume title: %s' % row['disc_vol']
  cur.execute('SELECT count(*) AS fc, SUM(st_size) AS bytes FROM file '
              'WHERE root=%d AND disc_vol IS NOT NULL;' % rootid)
  row = cur.fetchone()
  print 'Archived files: %d' % row['fc']
  print 'Archived bytes: %ld (%s)' % (row['bytes'] or 0,
                                      humanize_bytes(row['bytes'] or 0))



def scan_all(conn):
  """Fetch all of the root paths from the table, run scan_tree on them.

  Args: conn - dbi connection
  Returns: None
  """
  for root in get_roots(conn): scan_tree(conn, root)
    

def scan_tree(conn, root, verbose=False):
  """Find all files under the given root, check for them in the database table,
  update the table when necessary.

  Args:
    conn - dbi connection
    root - (id, path_root, label) tuple
    verbose - print the name of each file and its status
  Returns:
    (total size of new files, total size of files with no backups)
  """

  cur = dcursor(conn)
  new_bytes = 0
  nobackup_bytes = 0
  files_seen = {}
  rootid, root_path = root[:2]

  for parent, dirs, files in os.walk(root_path):
    for f in files:
      path = os.path.join(parent, f)
      st = os.stat(path)
      # don't want to deal with float st_mtime that we sometimes get
      st_mtime = int(st.st_mtime)
      st_size = st.st_size

      cur.execute('SELECT id, st_mtime, st_size, disc_vol FROM file WHERE '
                  'file=%s AND root=%d;' % (dbquote(path), rootid))
      row = cur.fetchone()
      if row:
        if row['st_mtime'] == st_mtime and row['st_size'] == st_size:
          # file is already known and unmodified..
          if row['disc_vol']:
            # ..and backed up
            status = ' '
          else:
            # ..and not backed up
            status = '.'
            nobackup_bytes += st.st_size
        else:
          # file is already known, but stat changed
          cur.execute('UPDATE file SET st_mtime=%d, st_size=%d, disc_vol=NULL, '
                      'disc_date=NULL WHERE id=%d;' % 
                      (st.st_mtime, st.st_size, row['id']));
          conn.commit()
          status = '+'
          new_bytes += st.st_size
          nobackup_bytes += st.st_size
      else:
        # file has never been seen
        cur.execute('INSERT INTO file (file, st_mtime, st_size, root) VALUES '
                    '(%s, %d, %d, %d);' %
                    (dbquote(path), st.st_mtime, st.st_size, rootid))
        conn.commit()
        status = '+'
        new_bytes += st.st_size
        nobackup_bytes += st.st_size
      
      if verbose: print status + ' ' + path
      # to save memory, we remember only the 16-byte md5 hash of the filename
      h = hashlib.new('md5')
      h.update(path)
      files_seen[h.digest()] = True


  # now check that all files not yet on a disc still exist
  cur.execute('SELECT id, file FROM file WHERE root=%d AND disc_vol IS NULL;'
              % rootid)
  for row in cur.fetchall():
    h = hashlib.new('md5')
    h.update(row[1])
    if h.digest() in files_seen:
      del files_seen[h.digest()]
    else:
      cur.execute('DELETE FROM file WHERE id=%d;' % row[0])
      conn.commit();
      if verbose: print '- ' + row[1]

  # use root entry's disc_date to record time of last scan
  cur.execute('UPDATE file SET disc_date=now() WHERE id=%d;' % rootid)
  conn.commit();

  return new_bytes, nobackup_bytes



if __name__ == '__main__':

  conn = connect()
  verbose = False
  which_root = None
  disc_label = None
  command = None
  roots = []

  try:
    opts, remainder = getopt.getopt(sys.argv[1:], 'vr:l:')
    opts = dict(opts)
    if '-v' in opts: verbose = True
    if '-r' in opts: roots.append(get_root(conn, opts['-r']))
    if '-l' in opts: disc_label = opts['-l']
    command = remainder[0]
    remainder = remainder[1:]
  except (getopt.GetoptError, IndexError), e:
    sys.stderr.write('command line error: %s\n\n' % e)
    sys.stderr.write(__doc__)
    sys.exit(1)

  if not roots: roots = get_roots(conn)

  if command == 'scan':
    for root in roots:
      scan_tree(conn, root, verbose)
  elif command == 'burn':
    if len(roots) > 1:
      sys.stderr.write('must specify which root.\n')
      sys.exit(1)
    if not disc_label: disc_label = guess_label(conn, roots[0])
    capacity = get_disc_capacity(get_disc_device())
    burn_disc(conn, roots[0][0], capacity, disc_label)
  elif command == 'status':
    for root in roots: print_status(conn, root)
  else:
    sys.stderr.write(__doc__)
    sys.exit(1)

  conn.close()




