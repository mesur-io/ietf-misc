# ietf-misc

as a rule, generate good text by the following:

```bash
$ mmark [DRAFT].md > [DRAFT-XX].xml
$ $EDITOR [DRAFT-XX].xml # ensure -XX is correct
$ xml2rfc [DRAFT-XX].xml
```

check drafts for [idnits](https://author-tools.ietf.org/idnits)
