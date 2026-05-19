# vesl-nockup <TAG>

<one-line summary>

## Mirror source

- vesl-core: `<VESL_CORE_REV>` (released as `<VESL_CORE_TAG>`)
- nockchain (NOCK_PIN): `<NOCK_PIN>`

## Mirrored crates

(versions match vesl-core; sync.sh equivalence verified at release time)

| crate                 | version |
| --------------------- | ------- |
<MIRRORED_TABLE>

## Tooling crates

| crate                 | version |
| --------------------- | ------- |
<TOOLING_TABLE>

## Templates

<TEMPLATE_LIST>

## Highlights

- ...

## Breaking changes

- ...

## Bug fixes

- ...

## Known issues

- ...

## Verifying this release

- `cargo check` clean across all templates
- `diff -rq --exclude=target ../vesl-core/crates ./crates` empty (sync gate)
- Built against nockchain @ NOCK_PIN
