# Fuzzing Ping

This repository demonstrates how you can fuzz network protocols, in this case the
`ping` utility, using ISLa.

The file "grammar.bnf" contains the grammar of the ICMP protocol. Messages are
represented as hex strings; an example ICMP ping message is

```
08 00 D9 B2 69 1D 64 AF 50 80
```

An ICMP Echo Request (ping) message (see
[the Wikipedia entry](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)
for an easy introduction to ICMP) starts with an "08" byte (the *message type*) followed
by a "00" byte (the *message code*). The following two bytes are the *checksum*,
followed by two *message id* and two *sequence number* bytes; the message is concluded
with the *payload*.

```
   code     id
   |        |
08 00 D9 B2 69 1D 64 AF 50 80
|     |           |     |
type  checksum    seq   payload
```

An Echo Reply contains a "00" type and the same id and sequence number. The payload
*should* be the same, though this requirement may be ignored on Windows machines.

The checksum is an "Internet checksum" according to RFC 1071.

Our script `send_icmp.py` (the test target) takes a file containing an ICMP Echo Request
as output by ISLa, sends the corresponding request to the local host, and listens for
responses. It prints some information on the sent and received messages to the command
line.

The Internet checksum is hard to specify using SMT-LIB only, and would probably result
in timeouts. Thus, we defined an application-specific predicate "internet_checksum" in
the extension file `internet_checksum.py`. When this file is passed to ISLa on the CLI,
the predicate "internet_checksum" can be used in constraints
(as `internet_checksum(<start>, <checksum>)`). The extension file is well-documented and
can serve as an introduction to defining custom semantic predicates for other situations
where this is needed.

Finally, the script `fuzz_ping.sh` calls `isla fuzz` with a number of constraints to
fuzz `send_icmp.py`. It generates 10 inputs and displays the standard output of the test
target on the console after termination. All inputs, error codes, standard output, and
standard error messages are contained in the directory `results/` afterward.

## Installation

This package requires Python 3.10. We recommend installing the requirements in a virtual
environment:

```shell
cd /path/to/ICMPFuzzer/
python3.10 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Fuzzing

To get started, you can simply run `sudo ./fuzz_ping.sh` (`sudo` is required to be able
to send messages on a socket). The script uses four constraints:

```shell
isla -O fuzz -n 10 -d results/ \
  --constraint '<type> = "08 "' \
  --constraint '<code> = "00 "' \
  --constraint 'internet_checksum(<start>, <checksum>)' \
  --constraint '
exists int cnt: (
  str.to.int(cnt) mod 2 = 0 and
  str.to.int(cnt) > 0 and
  count(<payload_data>, "<byte>", cnt))' \
  'python send_icmp.py {}' \
  grammar.bnf internet_checksum.py
```

The first two refine the message type and code to ICMP Echo Requests. The third
constraint uses the "internet_checksum" predicate to make sure the requests have a valid
checksum. Finally, the last constraint specifies that the payload must be non-empty and
consist of an even number of bytes. It seems that an even number of bytes is required
by `ping`. Instead of investigating the issue, we chose to use the chance to demonstrate
how such issues can be reflected in ISLa :smiley:

You can also use `isla solve` and pipe the result to `send_icmp.py` to obtain a more
direct feedback, and play with the constraints:

```shell
isla -O solve \
  --constraint '<type> = "08 "' \
  --constraint '<code> = "00 "' \
  --constraint 'internet_checksum(<start>, <checksum>)' \
  --constraint '
exists int cnt: (
  str.to.int(cnt) mod 2 = 0 and
  str.to.int(cnt) > 0 and
  count(<payload_data>, "<byte>", cnt))' \
  grammar.bnf internet_checksum.py | sudo python send_icmp.py /dev/stdin
```

For example, you could remove some of the constraints, or change some of the magic
values. Removing the checksum constraint demonstrates that the request's checksum is
indeed checked by `ping` (at least on macOS). You could also remove the constraint on
the number of bytes in `<payload_data>` or replace with by, e.g.,
`count(<payload_data>, "<byte>", "100")` to obtain a payload of exactly 100 bytes.

## Copyright

This project is released under the GNU General Public License v3.0 (see
[COPYING](COPYING)).
