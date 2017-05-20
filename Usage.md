# Command line #

```
Usage: s3dump.py (-d|-r|-l|-i|-c n) [-h hostname] [-w YYYY-MM-DD] [-a] fs level

Choose exactly one of the following:
  -d: dump (write data to s3)
  -r: restore (read data back from s3)
  -l: list dumps stored in s3
  -i: initialize dumps bucket (need to run only once)
  -c: (clean:) delete all but n latest dumps of each fs and level

Arguments and switches:
  -a: list or delete dumps for all hosts, not just me
  -h: override default hostname (redlance)
  -w: override default date stamp, use format YYYY-MM-DD
  -L: ratelimit outgoing dump to n bytes/sec.  optional suffixes k, m, g.
  fs: name of filesystem you are dumping, or an arbitrary string
  level: what level dump (0-9), or an arbitrary int
```

# Setup #

s3dump.py is a self-contained python file; put it anywhere you want.  I just run it from the googlecode svn client.

It needs to know your AWS "access ID" and "secret access key."  You can just hard code them, but then `svn up` is a pain, so you can also put them in the file `/etc/s3keys`.  Put the "access ID" on the first line by itself, and the "secret access key" on the second line.

Lastly, you have to run `s3dump.py -i` once to create the bucket named 'dumps'.

# Storing backups #

```
LEVEL=0
FS=/usr
dump -L -h0 -u -f - -$LEVEL $FS | s3dump.py -d $FS $LEVEL
```

You can put anything you want in the pipe, but you will have to remember what it is--there's no metadata to remind you later, unless you label it.  s3dump is just reading stdin, so it has no idea what your junk is.

```
tar -czv -C /srv/photo . | s3dump.py -d photo-tar 0
dd if=/dev/sda bs=8k | bzip2 | s3dump.py -d disk-image 0
```

It is possible to ratelimit outgoing dumps, which is nice when you have a lot of data to transfer and don't want to completely trash your uplink for a week:

`tar -cv -C /srv/photo . | s3dump.py -L 300k -d photo-tar 0`

## If you are afraid of Amazon stealing your sekrits ##

`dump -L -h0 -u -f - -$LEVEL $FS | gpg -e -r 9284C452 | s3dump.py -d $FS $LEVEL`

Before you do this, think about the fact that you will need to locate a copy your pgp secret key, and remember its passphrase, in the situation where you have lost your machine and are trying to get your data back.  This is a pain at best, and if your only copy of your secret key is in the dump, congratulations, you have locked the keys in the car.

# Retrieving and restoring #

Being the rather less common operation, I don't have the example in front of me.  It looks something like:

<pre>
s3dump.py -r -h redlance /home 0 | gpg | restore<br>
</pre>

But do not take my word for it.  Try it yourself with your own backup, before you need it.

# Structure in s3 #

Everything you store is organized in a tree that makes sense if you are using dump/restore and mostly leaving the default settings:

<pre>
redlance ~ $ s3dump.py -l<br>
Dumps for this host (redlance):<br>
/<br>
Level 0 2009-10-07:    21.5M<br>
Level 0 2010-06-28:    21.5M<br>
Level 0 2011-01-06:    21.5M<br>
Level 1 2006-11-20:    14.0k<br>
Level 1 2006-12-30:    14.0k<br>
/home<br>
Level 0 2009-07-08:     5.4G<br>
Level 0 2010-06-27:     5.5G<br>
Level 0 2011-01-06:     1.8G<br>
Level 1 2008-10-12:     1.9G<br>
Level 1 2009-10-07:     1.2G<br>
Level 1 2011-01-06:     1.4G<br>
Level 2 2007-02-28:     1.4G<br>
...<br>
<br>
Total data stored: 24.1G ($3.60/month)<br>
</pre>

But the reality is that hostname and filesystem name are just arbitrary strings, and "level" is an arbitrary int.  You can set them to anything you want.  The date tags are parsed (not arbitrary strings) but can also be forced to whatever valid date value you want.  The "-c" cleanup function may not make much sense if you deviate from the expected host/filesystem/level/date usage, though.

# Internal details #

When storing data, s3dump reads stdin and breaks it into 50MB chunks.  Each chunk is stored with a colon-delimited key name such as `nightfall:tar-photo:0:2012-01-21:0`.  The last field is the chunk number.  Chunks are relatively small because each one must be stored in a single HTTP POST.  The last chunk read from stdin is held in RAM until the POST is successful, then the memory is released and another 50MB is read from stdin.

If ratelimiting is used, it applies to the bytes written to the HTTP socket.  It is blind to TCP and other protocol overhead, which costs about 5%.  So for example with the 300kB/s limit that I typically use on a 6Mb cable modem, the observed usage is 312kB/s.  Note that the chunk buffering also means that your data source will see 50MB read bursts with long delays in between.

Retrieving a dump is much simpler.  The script merely finds all the keys matching the correct prefix, fetches them in order (HTTP GET) and concatenates them to stdout.  If this script is lost or python is not available, it should be possible to do the same in a few lines with e.g. curl and bash.