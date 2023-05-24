# ietf-misc

as a rule, generate good text by the following:

```bash
$ mmark [DRAFT].md > [DRAFT-XX].xml
$ $EDITOR [DRAFT-XX].xml # ensure -XX is correct - or if you are brave \
# sed -i 's/-latest/-XX/g' [DRAFT-XX].xml
$ xml2rfc [DRAFT-XX].xml
```

check drafts for [idnits](https://author-tools.ietf.org/idnits)
