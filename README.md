# Command line

```
Usage: s3dump.py [opts] command

Commands and their options:

dump FS LEVEL    - write an object to S3
restore FS LEVEL - retrieve an object from S3
delete FS LEVEL  - delete an object in S3

  -k <arg>: Optional literal name of key in S3 bucket.  Otherwise,
            must provide FS and LEVEL on the command line, and a
            key will be created using hostname, fs, level, date.
  -h <arg>: Override default hostname with <arg>
  -w <arg>: Override default date, use format YYYY-MM-DD

list    - print list of dumps/objects available in S3

init    - create and test bucket

clean N - delete all but the most recent N dumps at each fs and level

  -a: clean all dumps, not just ones for this host

getacl  - print given key's ACL XML document to stdout
putacl  - read ACL XML document from stdin, apply to given key


General options that apply to any command:

-q: suppress status messages, only report errors
-L <arg>: ratelimit S3 socket to <arg>{k,m,g} bytes per second
-f <arg>: read S3 configuration from <arg> rather than /etc/s3_keys
-i: use S3 'infrequent access' storage class
```

# Setting up AWS

Create an S3 bucket in the S3 console:
https://s3.console.aws.amazon.com

Consider adding lifecycle rules to the bucket, such as transitioning
objects over a certain age to Glacier storage.  I recommend at least
enabling "Clean up incomplete multipart uploads," because s3.py uses
multipart upload chunking and a crash might leave invisible orphaned
chunks (for which you will still be charged).

Create IAM keys that you will put on the machines that are going to
run s3dump.  There are many ways you could do this.  I recommend
creating one that has full permission to read/write/delete from the
configured bucket, and a second one that is write-only.  The
write-only key can be used to run backups unattended, such as from
cron.  Then if this key is compromised, it can't be used to extract
everything in the bucket.  The read-write key can be kept somewhere
more secure, or disabled when it is not needed.

**TODO: There is still a problem:** if an intruder has the write-only
key and can guess the names of previously created S3 dumps, they can
effectively delete them by overwriting them.  This could be fixed by
randomizing key names on write.

## Create read-write IAM key

Following is an IAM policy that allows you to do the operations that
`s3dump.py` calls dump, restore, delete, clean, and list:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:Put*",
                "s3:Get*",
                "s3:DeleteObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::your-bucket-name",
                "arn:aws:s3:::your-bucket-name/*"
            ]
        }
    ]
}
```

## Create write-only IAM key

This policy allows only the "dump" operation:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:Put*",
            "Resource": "arn:aws:s3:::your-bucket-name/*"
        }
    ]
}
```

# Setting up s3dump locally

s3dump.py needs to be able to find s3.py, which it usually can if they
are in the same directory.  Otherwise they have no dependencies beyond
standard Python 2.  You can just clone the git repository and create a
symlink to `s3dump.py` in some place such as `~/bin`.

Create a file at `~/.s3keys` that contains the following:

```
service s3
region us-east-1
bucket_name your-bucket-name
access_key_id AKIAAAAAAAAYOURACCESSKEYID
secret_access_key xxxxx+your+secret+access+key+from+iam
```

# Self-test

If Python and your IAM key are correct, then you can run `s3.py`
directly and it will do a bunch of test writes and reads from S3.

# Storing a backup

The dump operation just reads stdin and streams it into an object in
S3.  The name of the object is constructed from four things:

+ hostname (defaults to the current hostname)
+ date (defaults to today)
+ filesystem (an arbitrary string you must provide)
+ level (an arbitrary int you must provide)

The arbitrary string and int label are named "filesystem" and "level"
because that is what makes sense when using with `dump`.  But
s3dump.py does not care.

Likewise, you can put anything you want into stdin, and it will just
get blindly stored.  You have to remember what you put in, because
there is no metadata except for the labels you provide.  `s3dump`
doesn't have any other metadata; it's just reading stdin.

# Usage

Some examples of putting things in and taking them out:

```
# dump/restore

dump -L -h0 -u -f - -$LEVEL $FS | s3dump.py dump $FS $LEVEL
s3dump.py restore $FS $LEVEL | restore -f -

# tar

tar -czv -C /srv/photo . | s3dump.py dump photo-tar.gz 0
s3dump.py restore photo-tar.gz 0 | tar -C /srv/photo -xvzf -

# dd

dd if=/dev/sda bs=8k | bzip2 | s3dump.py dump disk-image.bz2 0
s3dump.py restore disk-image.bz2 0 | bzip2 -d | dd if=- of=/dev/sda
```

## Ratelimiting

It is possible to ratelimit outgoing dumps, which is nice when you
have a lot of data to transfer and don't want to completely trash your
uplink for a week:

`tar -cv -C /srv/photo . | s3dump.py -L 300k dump photo-tar 0`

## Compression

`s3dump.py` supports all compression algorithms past, present, and
future, because you do it yourself:

```
tar -czv -C /srv . | bzip2 | s3dump.py dump srv.tbz 0
s3dump.py restore srv.tbz 0 | bzip2 -d | tar -C /srv -xvzf -
```

Notice how the label has been chosen to provide a clue that bzip2 was
involved.

## Encryption

Go nuts:

`dump -L -h0 -u -f - -$LEVEL $FS | gpg -e -r 9284C452 | s3dump.py dump $FS $LEVEL`

But think about the fact that you will need to find your pgp secret
key, and its passphrase, in the situation where you have lost your
machine and are trying to get your data back.

If your only copies of the key are in encrypted dumps, see
http://sadtrombone.com.

## Running from cron



# Structure in S3

Everything you store is organized in a tree that makes sense if you
are using dump/restore and mostly leaving the default settings:

<pre>
redlance ~ $ s3dump.py list<br>
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

But the reality is that hostname and filesystem name are just
arbitrary strings, and "level" is an arbitrary int.  You can set them
to anything you want.  The date tags are parsed (not arbitrary
strings) but can also be forced to whatever valid date value you want.

The "clean" function may not make much sense if you deviate from the
expected host/filesystem/level/date usage.

# Internal details

When storing data, s3dump reads stdin and breaks it into 50MB chunks.
Each chunk is stored with a colon-delimited key name such as
`nightfall:tar-photo:0:2012-01-21:0`.  The last field is the chunk
number.  Chunks are relatively small because each one must be stored
in a single HTTP POST.  The last chunk read from stdin is held in RAM
until the POST is successful, then the memory is released and another
50MB is read from stdin.

If ratelimiting is used, it applies to the bytes written to the HTTP
socket.  It is blind to TCP and other protocol overhead, which costs
about 5%.  So for example with the 300kB/s limit that I typically use
on a 6Mb cable modem, the observed usage is 312kB/s.  Note that the
chunk buffering also means that your data source will see 50MB read
bursts with long delays in between.

Retrieving a dump is much simpler.  The script merely finds all the
keys matching the correct prefix, fetches them in order (HTTP GET) and
concatenates them to stdout.  If this script is lost or python is not
available, it should be possible to do the same in a few lines with
e.g. curl and bash.
