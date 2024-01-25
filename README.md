# imap-sec

```sh
$ cargo run -- --help
Usage: imap-sec <command> [<args>]

imap-sec.

Options:
  --help            display usage information

Commands:
  max_tag           Learn max tag length (through NOOP command)
  max_literal       Learn max literal length (through user astring in LOGIN
                    command)
  allowed_tag       Learn allowed tag characters (through NOOP command)
  oom               Try to bring server OOM via SEARCH command. WARNING: Don't
                    use in production.
```
