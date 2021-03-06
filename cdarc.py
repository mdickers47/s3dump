#!/usr/bin/python
"""cdarc - Maintain an offline catalog of optical discs that mirror files on disk.

Usage: cdarc [-r which] [-d /cdr/device] [-v] [-N] command

-r: which root to operate on; can be specified by path or label
-d: use specified cdrom device (otherwise try to guess)
-v: more verbosity
-N: prepare and catalog an ISO image, but don't really burn

command:
  scan - compare database records against disk, and update database
  burn - burn an optical disc with as many files as will fit, oldest first
  status - print some statistics
  selftest - check binaries, database, and disc status

  TODO:
  init - create records for a new tree root
  delete - delete all records associated with named root

Copyright 2012 Michael Dickerson <mikey@singingtree.com>
"""

# -----------------------------------------------------------------
# To adapt to whatever SQL database you have handy, you should only
# need to modify this part.

import psycopg2 as pydbi # apt-get install python-psycopg2
import psycopg2.extras

DBSPEC='dbname=cdarc user=cdarc'

def connect():
  return pydbi.connect(DBSPEC)

def dcursor(conn):
  """Construct a dictionary cursor from conn."""
  return conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

# -----------------------------------------------------------------

import getopt
import hashlib
import os
import re
import subprocess
import sys
import tempfile

ONE_GB = 2**30 # bytes


def humanize_bytes(b):
  """Convert 2220934 to '2.2M', etc."""
  units = ((40, 'T'), (30, 'G'), (20, 'M'), (10, 'k'))
  for u in units:
    if b > 2 ** u[0]: return '%.1f%s' % (float(b) / 2 ** u[0], u[1])
  return str(b)


def dbquote(s):
  """Enclose any string in ' and double any exising 's."""
  return "'" + s.replace("'", "''") + "'"


def find_field(text, field):
  """From a multi-line string where each line looks like 'description: value',
  find a given field and extract the string to the right of the colon.

  Used to parse 'wodim -atip' and 'dvd+rw-mediainfo'
  """
  for line in text.split('\n'):
    if not ':' in line: continue
    key, val = map(lambda x: x.strip(), line.split(':', 1))
    if key == field: return val
  return None


def self_test():

  def _check_process(args, expected=0):
    null = open('/dev/null', 'w')
    ret = subprocess.call(args, stdout=null, stderr=null)
    if ret == expected:
      print 'Able to execute %s' % args[0]
      return True
    else:
      print 'Can\'t execute %s' % args[0]
      return False

  ok = True
  ok &= _check_process(['wodim', '--version'])
  ok &= _check_process(['dvd+rw-mediainfo'], expected=150)
  ok &= _check_process(['growisofs', '-version'])
  ok &= _check_process(['genisoimage', '-version'])

  try:
    cur = dcursor(connect())
    cur.execute('SELECT * FROM file LIMIT 1;')
    cur.close()
    print 'Database connection is ok'
  except Exception, e:
    print e
    ok = False 

  disc = get_disc_capacity()
  print 'Media capacity appears to be: %s' % humanize_bytes(disc)
  return ok


def guess_disc_device():
  """Use wodim to guess the cd-rom device.  wodim returns nonzero upon
  successfully doing this.  Who writes this crap?
  """
  pipe = subprocess.Popen(['wodim', '--devices'], stdout=subprocess.PIPE)
  stdout, stderr = pipe.communicate()
  for line in stdout.split('\n'):
    m = re.search(r"dev='([a-z0-9/]+)'\s+[rwx\-]{6} : '(.*?)' '(.*?)'", line)
    if m:
      print 'Using dev=%s (%s %s)' % (m.group(1), m.group(2), m.group(3))
      return m.group(1)
  print 'Unable to guess disc device'
  return None


def get_disc_capacity():
  """Try to guess the blank disc capacity, in bytes.

  First try dvd+rw-mediainfo, which works for anything except CDs.  Try
  wodim -atip for CDs.  The many format codes for DVDs and BDs are defined
  in:
  ftp://ftp.avc-pioneer.com/Mtfuji_7/Proposal/Oct06/Pioneer/ \
  READ_FORMAT_CAPACITIES.pdf
  """
  global DEVICE
  try:
    minfo = subprocess.check_output(['dvd+rw-mediainfo', DEVICE],
                                    stderr=subprocess.STDOUT)
    # format type 00h is "full format":
    capacity = find_field(minfo, '00h(3000)')
    if not capacity:
      # format type 26h is "DVD+RW basic format":
      capacity = find_field(minfo, '26h(0)')
    return int(capacity.split('=')[-1])
  except subprocess.CalledProcessError:
    # no disc, or CD (unreadable by dvd+rw-mediainfo)
    pass
  try:
    minfo = subprocess.check_output(['wodim', 'dev=%s' % DEVICE, '-atip'],
                                    stderr=subprocess.STDOUT)
    capacity = find_field(minfo, 'ATIP start of lead out')
    return int(capacity.split()[0]) * 2048
  except subprocess.CalledProcessError:
    return 0


def burn_disc(conn, rootid, capacity, label, fake_burn):

  fh, path_list = tempfile.mkstemp(prefix='cdarc_file_list_')
  img_size = 0
  img_file_ids = []
  cur = dcursor(conn)
  capacity = int(0.99 * capacity) # must allow a little filesystem overhead

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

  if fake_burn:
    print 'NOT BURNING, DO IT YOURSELF: %s' % img_file
  elif capacity < ONE_GB:
    print 'Burning CD image using wodim.'
    subprocess.check_call(['wodim', 'dev=%s' % DEVICE, img_file])
  else:
    print 'Burning DVD/BD image using growisofs.'
    subprocess.check_call(['growisofs', '-Z', '%s=%s' % (DEVICE, img_file)])
  print
  print 'Updating file catalog (%d files stored).' % len(img_file_ids)
  for fid in img_file_ids:
    cur.execute('UPDATE file SET disc_vol=%s, disc_date=NOW() '
                'WHERE id=%d;' % (dbquote(label), fid))
  conn.commit()

  if fake_burn:
    print 'NOT DELETING, DO IT YOURSELF: %s' % path_list
    print 'NOT DELETING, DO IT YOURSELF: %s' % img_file
  else:
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
  print 'New bytes: %ld (%s)' % (row['bytes'] or 0, 
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


def scan_tree(conn, root, verbose=False):
  """Find all files under the given root, check for them in the database table,
  update the table when necessary.

  Args:
    conn - dbi connection
    root - (id, path_root, label) tuple
    verbose - print the name of each file and its status
  Returns:
    None
  """

  cur = dcursor(conn)
  rootid, root_path = root[:2]
  files_in_db = {}
  files_on_disk = {}
  files_identical = files_changed = files_added = files_deleted = 0

  # NB that at ~100 bytes of metadata per file path, 100k files fit in 10MB.
  # So it is probably ok (and much faster) to do all the reconciliation in RAM
  # and then run the minimal set of database updates.

  ID, PATH, MTIME, SIZE, DISCVOL = range(5)

  for parent, dirs, files in os.walk(root_path):
    for f in files:
      path = os.path.join(parent, f)
      st = os.stat(path)
      # don't want to deal with float st_mtime that we sometimes get
      digest = hashlib.md5(path).digest()
      files_on_disk[digest] = (None, path, int(st.st_mtime), st.st_size, None)

  if verbose:
    print 'Scanned %d files in %s.' % (len(files_on_disk.keys()), root_path)
  
  cur.execute('SELECT id, file, st_mtime, st_size, disc_vol FROM file WHERE '
              'root=%d;' % rootid)
  row = cur.fetchone()
  while row:
    digest = hashlib.md5(row['file']).digest()
    files_in_db[digest] = (row['id'], row['file'], row['st_mtime'],
                           row['st_size'], row['disc_vol'])
    row = cur.fetchone()

  if verbose:
    print 'Loaded %d files from db.' % len(files_in_db.keys())

  # first pass: forget anything that is identical in both places, update
  # anything that exists in both but with different metadata.
  to_delete = []
  for hashval, row in files_on_disk.iteritems():
    if hashval in files_in_db:
      db_row = files_in_db[hashval]
      assert row[PATH] == db_row[PATH]
      if row[MTIME] == db_row[MTIME] and row[SIZE] == db_row[SIZE]:
        if verbose: print '  ' + row[PATH]
        files_identical += 1
      else:
        if verbose: print '! ' + row[PATH]
        cur.execute('UPDATE file SET st_mtime=%d, st_size=%d, disc_vol=NULL, '
                    'disc_date=NULL WHERE id=%d;'
                    % (row[MTIME], row[SIZE], db_row[ID]))
        conn.commit()
        files_changed += 1
      # NB: can't actually delete from files_on_disk here, or the iterator
      # will crap out.
      to_delete.append(hashval)


  for hashval in to_delete:
    del files_on_disk[hashval]
    del files_in_db[hashval]
  to_delete = None

  # second pass: anything left in files_on_disk is new
  to_insert = []
  for hashval, row in files_on_disk.iteritems():
    if verbose: print '+ ' + row[PATH]
    to_insert.append('(%s, %d, %d, %d)'
                     % (dbquote(row[PATH]), row[MTIME], row[SIZE], rootid))
    files_added += 1
  if to_insert:
    cur.execute('INSERT INTO file (file, st_mtime, st_size, root) VALUES '
                + ','.join(to_insert) + ';')
    conn.commit()
  to_insert = None # release memory
  files_on_disk = None

  # third pass: anything left in files_in_db was deleted
  to_delete = []
  for hashval, row in files_in_db.iteritems():
    if row[DISCVOL]: continue # no point deleting from catalog
    if verbose: print '- ' + row[PATH]
    to_delete.append(str(row[ID]))
    files_deleted += 1
  if to_delete:
    cur.execute('DELETE FROM file WHERE ID IN (' + ','.join(to_delete) + ');')
    conn.commit()
  to_delete = None
  files_in_db = None

  # use root entry's disc_date to record time of last scan
  cur.execute('UPDATE file SET disc_date=now() WHERE id=%d;' % rootid)
  conn.commit();

  if verbose:
    print '%8d files unchanged.' % files_identical
    print '%8d files changed on disk.' % files_changed
    print '%8d files new on disk.' % files_added
    print '%8d un-archived files deleted on disk.' % files_deleted

  return None


if __name__ == '__main__':

  global DEVICE
  DEVICE = None
  conn = connect()
  verbose = False
  fake_burn = False
  which_root = None
  disc_label = None
  command = None
  roots = []

  try:
    opts, remainder = getopt.getopt(sys.argv[1:], 'd:vr:l:N')
    opts = dict(opts)
    if '-d' in opts: DEVICE = opts['-d']
    if '-v' in opts: verbose = True
    if '-r' in opts: roots.append(get_root(conn, opts['-r']))
    if '-l' in opts: disc_label = opts['-l']
    if '-N' in opts: fake_burn = True
    command = remainder[0]
    remainder = remainder[1:]
  except (getopt.GetoptError, IndexError), e:
    sys.stderr.write('command line error: %s\n\n' % e)
    sys.stderr.write(__doc__)
    sys.exit(1)

  if command == 'scan':
    if not roots: roots = get_roots(conn)
    for root in roots:
      scan_tree(conn, root, verbose)
  elif command == 'burn':
    if len(roots) > 1:
      sys.stderr.write('must specify which root.\n')
      sys.exit(1)
    if not DEVICE: DEVICE = guess_disc_device()
    if not disc_label: disc_label = guess_label(conn, roots[0])
    capacity = get_disc_capacity()
    burn_disc(conn, roots[0][0], capacity, disc_label, fake_burn)
  elif command == 'status':
    if not roots: roots = get_roots(conn)
    for root in roots: print_status(conn, root)
  elif command == 'selftest':
    if not DEVICE: DEVICE = guess_disc_device()
    self_test()
  else:
    sys.stderr.write(__doc__)
    sys.exit(1)

  conn.close()




